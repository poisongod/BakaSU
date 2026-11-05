// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_kallsyms.c - SuSFS HIDE_KSU_SUSFS_SYMBOLS, LKM edition.
 *
 * Upstream SuSFS is a source patch: kernel/kallsyms.c grows a
 * susfs_starts_with() check in s_show() and skips the seq_printf() when the
 * symbol name belongs to KSU/SuSFS.  We cannot patch the kernel, so the same
 * effect is produced by a kprobe that swallows the whole function.
 *
 * How the right function is found
 * -------------------------------
 * s_show() is a `static` function and this kernel builds three of them
 * (three different kCFI type hashes: s_show$80702cd9..., s_show$931aee36...,
 * s_show$b9f815d1...), so probing by name is ambiguous and the bare name does
 * not exist at all.  Instead we resolve the kernel's own
 * `static const struct seq_operations kallsyms_op` and read its `.show`
 * member.  That is by construction the s_show() that /proc/kallsyms installs,
 * and it stays correct across KASLR slides because we read the relocated
 * pointer at runtime.
 *
 * The stored pointer is the kCFI jump-table entry (a single `b` instruction
 * inside the per-type stub table), so we decode the branch and probe the real
 * function body instead: a normal prologue is a friendlier kprobe target and
 * it also catches callers that reach s_show() directly.
 *
 * How a line is suppressed
 * ------------------------
 * The probe fires at function entry, before the prologue.  When the symbol
 * must be hidden we write 0 into x0 (s_show() returns int, 0 = success) and
 * point regs->pc at the caller's LR, i.e. we return immediately: no
 * seq_printf() runs and the symbol never reaches the seq_file buffer.  The
 * debug exception restores PSTATE, so this is a plain `ret` in every respect
 * - SP/LR are still the caller's, nothing was pushed.
 *
 * When the symbol is not hidden we return 0 from the handler, kprobe
 * single-steps the first instruction and the untouched body runs, byte for
 * byte as on a stock kernel.
 *
 * Reading the symbol name
 * -----------------------
 * s_show() gets the iterator through m->private, and s_start() returns
 * m->private itself, so the second argument (x1) already *is* the
 * `struct kallsym_iter`.  We only need the offset of its `name` member.
 * `struct kallsym_iter` starts with four loff_t, one unsigned long, one
 * unsigned int and one char, so `name` always begins at byte 45 - that offset
 * does not depend on KSYM_NAME_LEN (which is 192 on this kernel, 128
 * elsewhere), because `name` is an inline array that immediately follows
 * `type`.  The read stays inside the kmalloc'd iterator (304 bytes) so a
 * wrong guess can never fault; it is additionally sanity-checked and we
 * fail open (show the line) if the bytes do not look like a symbol name.
 *
 * Deviation from the GKI patch, on purpose: upstream only guards the
 * non-module branch of s_show(), which leaves every module symbol visible -
 * and in LKM mode *all* ksu_/susfs_ symbols live in a module.  Suppressing
 * the whole call covers both branches, which is what the feature is for.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/types.h>

#include "susfs_internal.h"

#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS

/* offsetof(struct kallsym_iter, name) - see the file header. */
#define SUSFS_KSYM_NAME_OFF 45
#define SUSFS_KSYM_NAME_LEN 192
/* offsetof(struct seq_operations, show) - four pointers. */
#define SUSFS_SEQ_OPS_SHOW_OFF (3 * sizeof(unsigned long))

static const char *const susfs_hidden_prefixes[] = {
	"ksu_",
	"__ksu_",
	"susfs_",
	"ksud",
	"is_ksu_",
	"is_manager_",
	"escape_to_",
	"setup_selinux",
	"track_throne",
	"on_post_fs_data",
	"try_umount",
	"kernelsu",
	"__initcall__kmod_kernelsu",
	"apply_kernelsu",
	"handle_sepolicy",
	"getenforce",
	"setenforce",
	"is_zygote",
};

static struct kprobe susfs_kallsyms_kp;
static bool susfs_kallsyms_hook_live;

static bool susfs_kallsyms_name_sane(const char *name)
{
	int i;

	if (!name[0])
		return false;

	for (i = 0; i < SUSFS_KSYM_NAME_LEN; i++) {
		unsigned char c = name[i];

		if (!c)
			return true;
		if (c < 0x20 || c > 0x7e)
			return false;
	}

	/* No terminator inside the field: not a symbol name. */
	return false;
}

static bool susfs_kallsyms_name_hidden(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(susfs_hidden_prefixes); i++) {
		size_t len = strlen(susfs_hidden_prefixes[i]);

		if (!strncmp(name, susfs_hidden_prefixes[i], len))
			return true;
	}

	return false;
}

static int susfs_kallsyms_pre(struct kprobe *p, struct pt_regs *regs)
{
	const char *name;

	if (!regs->regs[1])
		return 0;

	name = (const char *)regs->regs[1] + SUSFS_KSYM_NAME_OFF;
	if (!susfs_kallsyms_name_sane(name))
		return 0;
	if (!susfs_kallsyms_name_hidden(name))
		return 0;

	/* Drop the line: s_show() returns 0, the caller's LR is the target. */
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * kallsyms_op.show holds a kCFI jump-table entry: one `b` instruction that
 * branches to the real body.  Follow it so the probe sits on the function
 * prologue.  Returns 0 when the value does not look usable.
 */
static unsigned long susfs_kallsyms_unwrap(unsigned long addr)
{
	return susfs_unwrap_jump_table(addr);
}

void susfs_kallsyms_init(void)
{
	unsigned long ops;
	unsigned long show;
	int ret;

	ops = susfs_lookup_symbol("kallsyms_op");
	if (!ops) {
		pr_err("susfs: kallsyms_op not found, symbol hiding off\n");
		return;
	}

	show = ((unsigned long *)ops)[SUSFS_SEQ_OPS_SHOW_OFF / sizeof(unsigned long)];
	show = susfs_kallsyms_unwrap(show);
	if (!show) {
		pr_err("susfs: kallsyms_op.show unusable, symbol hiding off\n");
		return;
	}

	memset(&susfs_kallsyms_kp, 0, sizeof(susfs_kallsyms_kp));
	susfs_kallsyms_kp.addr = (kprobe_opcode_t *)show;
	susfs_kallsyms_kp.pre_handler = susfs_kallsyms_pre;

	ret = register_kprobe(&susfs_kallsyms_kp);
	if (ret) {
		pr_err("susfs: s_show probe failed: %d\n", ret);
		return;
	}

	WRITE_ONCE(susfs_kallsyms_hook_live, true);
	pr_info("susfs: kallsyms symbol hiding armed on s_show %px (kallsyms_op %px)\n",
		(void *)show, (void *)ops);
}

bool susfs_kallsyms_available(void)
{
	return READ_ONCE(susfs_kallsyms_hook_live);
}

#endif /* CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS */
