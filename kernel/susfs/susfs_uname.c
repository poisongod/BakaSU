// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_uname.c - SuSFS SPOOF_UNAME for the LKM edition.
 *
 * Upstream SuSFS is a kernel patch: it edits SYSCALL_DEFINE1(newuname) so the
 * kernel-side copy of `struct new_utsname` gets the fake release/version
 * before the single copy_to_user().  We load a stock, locked boot image and
 * cannot patch fs/utsname.c, so we replace the syscall table entry instead.
 *
 * Why the syscall table and not a kprobe?
 *   A kprobe on __arm64_sys_newuname() runs *before* the syscall body, so the
 *   fake strings would have to be installed somewhere the body reads (i.e. we
 *   would have to rewrite the real utsname namespace), and a kretprobe runs
 *   after the body, where only the user buffer is left to rewrite - and
 *   copy_to_user() from a probe context is exactly the kind of thing that
 *   bites later.  Replacing the table entry gives us an ordinary syscall
 *   function: full process context, no probe trampoline, and we can simply
 *   call the original and then patch the result.  BakaSU already patches the
 *   table for __NR_init_module/__NR_finit_module/__NR_execve, so the
 *   mechanism is proven on this kernel (fixmap + stop_machine, once, at
 *   module load - never from a probe).
 *
 * Why the original is called first
 *   The real syscall also applies override_release() for PER_LINUX32
 *   processes and returns -EFAULT when the user buffer is not writable.  By
 *   running it first we inherit all of that, then overwrite only the two
 *   fields SuSFS owns.  Nothing else in the structure is touched, so
 *   sysname/nodename/machine/domainname stay truthful.
 *
 * Fast path
 *   Until userspace sends CMD_SUSFS_SET_UNAME the hook is a single
 *   READ_ONCE() on a bool plus the original call, which is the same shape
 *   upstream gets from static_branch_enable() - just cheaper to reason
 *   about in a module.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/ptrace.h>
#include <linux/atomic.h>
#include <asm/unistd.h>

#include "susfs_internal.h"
#include "hook/syscall_hook.h"

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME

/* arm64 asm-generic: __NR_uname is the entry that points at sys_newuname. */
#ifndef __NR_uname
#define __NR_uname 160
#endif

static struct st_susfs_uname susfs_uname_spoof;
static DEFINE_SPINLOCK(susfs_uname_lock);
static bool susfs_uname_spoof_set;

/* Non-NULL once the table entry was successfully replaced. */
static syscall_fn_t susfs_orig_newuname;
static bool susfs_uname_hook_live;

/* ------------------------------------------------------------------ */
/* userspace command: CMD_SUSFS_SET_UNAME                              */
/* ------------------------------------------------------------------ */
void susfs_set_uname(void __user **user_info)
{
	struct st_susfs_uname info = { 0 };
	unsigned long flags;

	if (copy_from_user(&info, (struct st_susfs_uname __user *)*user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	/*
	 * Upstream refuses empty strings rather than treating them as "keep
	 * the current value": an empty release/version would make
	 * `uname -r` print nothing, which is a far louder tell than the
	 * stock string.
	 */
	if (info.release[0] == '\0' || info.version[0] == '\0') {
		info.err = -EFAULT;
		goto out;
	}

	spin_lock_irqsave(&susfs_uname_lock, flags);
	if (!strcmp(info.release, "default"))
		strscpy(susfs_uname_spoof.release, utsname()->release,
			__NEW_UTS_LEN);
	else
		strscpy(susfs_uname_spoof.release, info.release, __NEW_UTS_LEN);
	if (!strcmp(info.version, "default"))
		strscpy(susfs_uname_spoof.version, utsname()->version,
			__NEW_UTS_LEN);
	else
		strscpy(susfs_uname_spoof.version, info.version, __NEW_UTS_LEN);
	spin_unlock_irqrestore(&susfs_uname_lock, flags);

	WRITE_ONCE(susfs_uname_spoof_set, true);

	SUSFS_LOGI("set spoofed release: '%s', version: '%s'\n",
		   susfs_uname_spoof.release, susfs_uname_spoof.version);

	info.err = 0;
out:
	if (copy_to_user(&((struct st_susfs_uname __user *)*user_info)->err,
			 &info.err, sizeof(info.err)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_SET_UNAME -> ret: %d\n", info.err);
}

/* ------------------------------------------------------------------ */
/* spoof helper (kept for ABI parity with upstream)                    */
/* ------------------------------------------------------------------ */
void susfs_spoof_uname(struct new_utsname *tmp)
{
	unsigned long flags;

	if (!READ_ONCE(susfs_uname_spoof_set))
		return;

	spin_lock_irqsave(&susfs_uname_lock, flags);
	strscpy(tmp->release, susfs_uname_spoof.release, __NEW_UTS_LEN);
	strscpy(tmp->version, susfs_uname_spoof.version, __NEW_UTS_LEN);
	spin_unlock_irqrestore(&susfs_uname_lock, flags);
}

/* ------------------------------------------------------------------ */
/* syscall hook                                                        */
/* ------------------------------------------------------------------ */
static long susfs_newuname_hook(const struct pt_regs *regs)
{
	struct new_utsname __user *name;
	struct new_utsname tmp;
	long ret;

	/* regs->regs[0] is the only argument; the body never clobbers it. */
	name = (struct new_utsname __user *)(unsigned long)regs->regs[0];

	if (!READ_ONCE(susfs_uname_spoof_set) ||
	    !READ_ONCE(susfs_orig_newuname))
		return susfs_orig_newuname ? susfs_orig_newuname(regs) :
					     -ENOSYS;

	ret = susfs_orig_newuname(regs);
	if (ret)
		return ret;

	/*
	 * The original just copied the whole structure out, so the page is
	 * present and writable; a failure here can only mean the caller
	 * raced with munmap, in which case the syscall is already lost.
	 */
	if (copy_from_user(&tmp, name, sizeof(tmp)))
		return ret;

	susfs_spoof_uname(&tmp);

	if (copy_to_user(name, &tmp, sizeof(tmp)))
		return -EFAULT;

	return ret;
}

void susfs_uname_init(void)
{
	if (!ksu_syscall_table) {
		SUSFS_LOGE("syscall table unavailable, spoof_uname stays off\n");
		return;
	}

	ksu_syscall_table_hook(__NR_uname, susfs_newuname_hook,
			       &susfs_orig_newuname);
	if (!susfs_orig_newuname) {
		/*
		 * ksu_syscall_table_hook() has already patched the entry by the
		 * time it reports a missing original, so the table currently
		 * points at our hook while `susfs_orig_newuname` is NULL - every
		 * uname() would branch to address zero.  Undo it.
		 */
		ksu_syscall_table_unhook(__NR_uname);
		SUSFS_LOGE("failed to hook __NR_uname, spoof_uname stays off\n");
		return;
	}

	/*
	 * ksu_syscall_table_hook() ignores the fixmap write result, so confirm
	 * the entry really points at us before claiming the feature.
	 */
	if (READ_ONCE(ksu_syscall_table[__NR_uname]) != susfs_newuname_hook) {
		ksu_syscall_table_unhook(__NR_uname);
		susfs_orig_newuname = NULL;
		SUSFS_LOGE("__NR_uname patch did not stick, spoof_uname stays off\n");
		return;
	}

	WRITE_ONCE(susfs_uname_hook_live, true);
	SUSFS_LOGI("spoof_uname hook installed on __NR_uname (%d)\n",
		   __NR_uname);
}

bool susfs_uname_available(void)
{
	return READ_ONCE(susfs_uname_hook_live);
}

#else /* !CONFIG_KSU_SUSFS_SPOOF_UNAME */

void susfs_uname_init(void)
{
}

#endif /* CONFIG_KSU_SUSFS_SPOOF_UNAME */
