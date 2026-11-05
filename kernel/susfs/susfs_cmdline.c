// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_cmdline.c - SuSFS SPOOF_CMDLINE_OR_BOOTCONFIG, LKM edition.
 *
 * Upstream SuSFS is a kernel patch: fs/proc/cmdline.c and fs/proc/bootconfig.c
 * call susfs_spoof_cmdline_or_bootconfig() instead of seq_puts()ing the real
 * buffer.  We load a stock, locked boot image and cannot patch fs/proc, so the
 * same effect is produced with a kprobe.
 *
 * This kernel is built with CONFIG_BOOT_CONFIG=n - there is no
 * /proc/bootconfig and no boot_config_proc_show() symbol - so /proc/cmdline is
 * the only surface the feature can and must cover here.  Both surfaces read
 * from the same userspace-provided string upstream, so the behaviour the
 * manager sees is identical.
 *
 * Why a PC-rewriting kprobe and not a kretprobe on cmdline_proc_show()?
 *   cmdline_proc_show() is two statements: seq_puts(m, saved_command_line)
 *   followed by seq_putc(m, '\n').  A kretprobe would run after the real
 *   cmdline had already been copied into the seq_file buffer, so the only way
 *   to hide it there would be to truncate/rewrite the buffer afterwards - and
 *   the real string would still have been read.  Instead the probe fires at
 *   function entry and, when a fake string has been installed, points
 *   regs->pc at our own replacement and returns 1.
 *
 *   kprobe_handler() reacts to a non-zero pre_handler return by calling
 *   reset_current_kprobe() and returning without setting up single-stepping
 *   (arch/arm64/kernel/probes/kprobes.c).  The debug exception then returns
 *   through kernel_exit(), which restores PSTATE from the interrupted context,
 *   i.e. IRQs and preemption are back on, and execution continues at
 *   regs->pc.  The original prologue never ran, so SP and LR still belong to
 *   the caller: our function is entered as an ordinary tail call, in ordinary
 *   process context, and may sleep / kmalloc / take locks.
 *
 *   When no fake string is installed the handler returns 0, the probe
 *   single-steps and the untouched body runs - the real cmdline is shown,
 *   exactly like an unpatched kernel.
 *
 * The saved_command_line pointer itself is deliberately NOT swapped: OPPO
 * drivers (qti_gadget, oplus_secure_common) and dynamic_debug parse that
 * global at probe time, so rewriting it would change driver behaviour far
 * beyond what upstream's read-path patch does.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "susfs_internal.h"

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG

#define SUSFS_CMDLINE_BUF_SIZE SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE

/*
 * Lazily allocated on the first SET command: the buffer is 8 KiB and most
 * boots never use the feature, so there is no reason to carry it around.
 */
static char *susfs_fake_cmdline;
static DEFINE_SPINLOCK(susfs_cmdline_lock);
static bool susfs_cmdline_is_set;

static struct kprobe susfs_cmdline_kp;
static bool susfs_cmdline_hook_live;

/*
 * Replacement body for cmdline_proc_show().  Entered with x0 = seq_file *,
 * x1 = v, and the caller's LR - see the file header for why that is legal.
 */
static int susfs_cmdline_show(struct seq_file *m, void *v)
{
	char *buf;
	unsigned long flags;

	buf = kmalloc(SUSFS_CMDLINE_BUF_SIZE, GFP_KERNEL);
	if (!buf) {
		/* Never fall back to the real cmdline on allocation failure:
		 * that is the one thing this feature exists to hide.  An empty
		 * line is what a failed allocation looks like upstream too. */
		seq_putc(m, '\n');
		return 0;
	}

	/* The spinlock only guards the copy; seq_puts() may grow the seq
	 * buffer and sleep, so it must run outside. */
	spin_lock_irqsave(&susfs_cmdline_lock, flags);
	strscpy(buf, susfs_fake_cmdline, SUSFS_CMDLINE_BUF_SIZE);
	spin_unlock_irqrestore(&susfs_cmdline_lock, flags);

	seq_puts(m, buf);
	seq_putc(m, '\n');
	kfree(buf);
	return 0;
}

static int susfs_cmdline_pre(struct kprobe *p, struct pt_regs *regs)
{
	if (!READ_ONCE(susfs_cmdline_is_set))
		return 0;

	regs->pc = (unsigned long)susfs_cmdline_show;
	return 1;
}

void susfs_set_cmdline_or_bootconfig(void __user **user_info)
{
	struct st_susfs_spoof_cmdline_or_bootconfig *info;
	unsigned long flags;
	int err = 0;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		if (copy_to_user(
			    &((struct st_susfs_spoof_cmdline_or_bootconfig __user *)
				       *user_info)
				     ->err,
			    &err, sizeof(err)))
			err = -EFAULT;
		SUSFS_LOGI("CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n",
			   err);
		return;
	}

	if (copy_from_user(
		    info,
		    (struct st_susfs_spoof_cmdline_or_bootconfig __user *)*user_info,
		    sizeof(*info))) {
		info->err = -EFAULT;
		goto out;
	}

	if (!info->fake_cmdline_or_bootconfig[0]) {
		info->err = -EINVAL;
		goto out;
	}

	/* copy_from_user() gave us exactly the struct; make sure the string
	 * terminates inside the array before strscpy() sees it. */
	info->fake_cmdline_or_bootconfig[sizeof(info->fake_cmdline_or_bootconfig) -
					 1] = '\0';

	if (!READ_ONCE(susfs_cmdline_hook_live)) {
		info->err = ERR_CMD_NOT_SUPPORTED;
		goto out;
	}

	if (!susfs_fake_cmdline) {
		char *buf = kzalloc(SUSFS_CMDLINE_BUF_SIZE, GFP_KERNEL);

		if (!buf) {
			info->err = -ENOMEM;
			goto out;
		}
		/* No locking needed: nothing reads it before the flag below. */
		WRITE_ONCE(susfs_fake_cmdline, buf);
	}

	spin_lock_irqsave(&susfs_cmdline_lock, flags);
	strscpy(susfs_fake_cmdline, info->fake_cmdline_or_bootconfig,
		SUSFS_CMDLINE_BUF_SIZE);
	spin_unlock_irqrestore(&susfs_cmdline_lock, flags);

	WRITE_ONCE(susfs_cmdline_is_set, true);
	info->err = 0;
out:
	if (copy_to_user(
		    (struct st_susfs_spoof_cmdline_or_bootconfig __user *)*user_info,
		    info, sizeof(*info)))
		info->err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n",
		   info->err);
	kfree(info);
}

void susfs_cmdline_init(void)
{
	int ret;

	/* cmdline_proc_show is `static` but kallsyms carries the plain name:
	 * fs/proc/cmdline.c is not a kCFI indirect-call target.  The helper
	 * still falls back to the CFI-suffixed variant if that ever changes. */
	ret = susfs_register_kprobe(&susfs_cmdline_kp, "cmdline_proc_show",
				    susfs_cmdline_pre, NULL);
	if (ret) {
		pr_err("susfs: cmdline_proc_show probe failed: %d\n", ret);
		return;
	}

	WRITE_ONCE(susfs_cmdline_hook_live, true);
	pr_info("susfs: cmdline spoof armed on cmdline_proc_show\n");
}

bool susfs_cmdline_available(void)
{
	return READ_ONCE(susfs_cmdline_hook_live);
}

#endif /* CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG */
