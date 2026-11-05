// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_probe.c - kprobe registration helpers shared by every SuSFS phase.
 *
 * Upstream SuSFS is a kernel patch, so every "call site" is a plain C
 * statement inside the function it belongs to.  We are a loadable module
 * instead, so each call site becomes a kprobe on the function that
 * contains it.  Two things make that awkward and are handled here:
 *
 *  1. A good part of the functions we care about are `static` and are
 *     reached through a function pointer (seq_file ->show, fsnotify
 *     ->show, ...).  With kCFI the compiler appends a type hash to the
 *     symbol name, so kallsyms only carries `inotify_fdinfo$3b9cc5ec...`
 *     and registering the bare name fails with -ENOENT.  We therefore
 *     retry through BakaSU's existing variant resolver, which walks
 *     kallsyms_on_each_symbol() looking for `name$...` / `name.cfi_jt`.
 *
 *  2. A kprobe on a hot path must be free when the feature is idle.
 *     Every pre_handler we install starts with a cheap table check, but
 *     the probe itself still costs a breakpoint trap, so phases that are
 *     not implemented simply never register.
 */

#include <linux/kprobes.h>
#include <linux/string.h>

#include "susfs_internal.h"
#include "infra/symbol_resolver.h"

/*
 * Resolve a symbol to its address, accepting the CFI-suffixed variant.
 * Returns 0 when the symbol does not exist at all.
 */
unsigned long susfs_lookup_symbol(const char *symbol_name)
{
	return (unsigned long)ksu_resolve_symbol_for_functable_hook(symbol_name);
}

int susfs_register_kprobe(struct kprobe *kp, const char *symbol_name,
			  kprobe_pre_handler_t pre,
			  kprobe_post_handler_t post)
{
	unsigned long addr;
	int ret;

	memset(kp, 0, sizeof(*kp));
	kp->symbol_name = symbol_name;
	kp->pre_handler = pre;
	kp->post_handler = post;

	ret = register_kprobe(kp);
	if (!ret)
		return 0;

	/*
	 * The bare name is gone (CFI suffix), or the kernel refuses to
	 * probe it by name.  Retry through a resolved address.
	 */
	addr = susfs_lookup_symbol(symbol_name);
	if (!addr)
		return ret;

	memset(kp, 0, sizeof(*kp));
	kp->addr = (kprobe_opcode_t *)addr;
	kp->pre_handler = pre;
	kp->post_handler = post;

	return register_kprobe(kp);
}

/*
 * Register on the *real* function body rather than on the address the
 * resolver hands back.  Which of the two the resolver returns depends on
 * how the kernel was built (with USE_KCFI the variant resolver sorts by
 * address, so the body - which always sits below its `.cfi_jt` stub - wins;
 * without it the bare name resolves straight to the body).  Neither case is
 * allowed to reach us as a stub, so every caller unwraps: probing a stub
 * only sees indirect callers, while the body is reached by both (the stub
 * tail-branches into it).  susfs_unwrap_jump_table() returns the address
 * unchanged when it is not a stub, so this is safe for plain functions too.
 * `kp` is cleared when the registration fails, so callers can test it with
 * `kp->addr`.
 */
int susfs_register_kprobe_at(struct kprobe *kp, const char *symbol_name,
			     kprobe_pre_handler_t pre)
{
	unsigned long addr = susfs_lookup_symbol(symbol_name);
	int ret;

	if (!addr)
		return -ENOENT;
	addr = susfs_unwrap_jump_table(addr);
	if (!addr)
		return -ENOENT;

	memset(kp, 0, sizeof(*kp));
	kp->addr = (kprobe_opcode_t *)addr;
	kp->pre_handler = pre;

	ret = register_kprobe(kp);
	if (ret)
		memset(kp, 0, sizeof(*kp));
	return ret;
}

int susfs_register_kretprobe(struct kretprobe *krp, const char *symbol_name,
			     kretprobe_handler_t entry,
			     kretprobe_handler_t ret_handler, int data_size)
{
	unsigned long addr;
	int maxactive = krp->maxactive;
	int ret;

	memset(krp, 0, sizeof(*krp));
	krp->maxactive = maxactive;
	krp->kp.symbol_name = symbol_name;
	krp->entry_handler = entry;
	krp->handler = ret_handler;
	krp->data_size = data_size;

	ret = register_kretprobe(krp);
	if (!ret)
		return 0;

	addr = susfs_lookup_symbol(symbol_name);
	if (!addr)
		return ret;

	memset(krp, 0, sizeof(*krp));
	krp->maxactive = maxactive;
	krp->kp.addr = (kprobe_opcode_t *)addr;
	krp->entry_handler = entry;
	krp->handler = ret_handler;
	krp->data_size = data_size;

	return register_kretprobe(krp);
}

/*
 * kCFI jump-table entry -> real function body.
 *
 * With CONFIG_CFI_CLANG and !CONFIG_CFI_CLANG_INDIRECT (that is: plain
 * "kcfi" on 5.x, which is what this kernel uses), every function that is
 * ever called through a pointer also gets an entry in the `.cfi_jt` jump
 * table, and kallsyms reports it as `name.cfi_jt`.  That entry is a single
 * `b <real function>` instruction, so a probe placed on it only sees
 * indirect callers.  Direct callers branch to the body instead.
 *
 * BakaSU's resolver deliberately prefers the `.cfi_jt` variant (it is the
 * address the kernel's indirect-call sites use), so anything that wants
 * *all* callers has to follow the branch.  Returns `addr` unchanged when
 * it is not a stub, 0 when the address is not inside the text segment.
 */
unsigned long susfs_unwrap_jump_table(unsigned long addr)
{
	unsigned long stext, etext;
	u32 insn;
	s32 off;

	if (!addr)
		return 0;

	stext = susfs_lookup_symbol("_stext");
	etext = susfs_lookup_symbol("_etext");
	if (!stext || !etext || etext <= stext)
		return 0;
	if (addr < stext || addr >= etext || (addr & 3))
		return 0;

	insn = READ_ONCE(*(u32 *)addr);
	if ((insn & 0xfc000000u) != 0x14000000u)
		return addr;

	/* imm26 is signed, counted in instructions, relative to the stub. */
	off = (s32)(insn << 6) >> 4;
	if (!off)	/* `b .` - a stub pointing at itself is not usable */
		return 0;

	addr += (unsigned long)(long)off;
	if (addr < stext || addr >= etext || (addr & 3))
		return 0;

	return addr;
}

/*
 * Find the first `bl <target>` inside [start, start + size).
 *
 * Returns the address *after* the branch, which is what the callee sees in
 * x30 and therefore what an LR-pinned probe has to compare against.  Used
 * for call sites we can only reach from the caller side (a kprobe cannot
 * know that it was entered from one specific caller, but the callee can
 * compare its link register).
 */
unsigned long susfs_find_bl_to(unsigned long start, unsigned long size,
			       unsigned long target)
{
	const u32 *p = (const u32 *)start;
	unsigned long i;

	if (!start || !target || !size)
		return 0;

	for (i = 0; i + 4 <= size; i += 4) {
		u32 insn = READ_ONCE(p[i / 4]);
		unsigned long pc, dst;

		if ((insn & 0xfc000000u) != 0x94000000u)
			continue;

		pc = start + i;
		dst = pc + (unsigned long)(long)((s32)(insn << 6) >> 4);
		if (dst == target)
			return pc + 4;
	}
	return 0;
}
