// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_mount.c - SuSFS SUS_MOUNT (mount hiding), LKM edition.
 *
 * Upstream is a kernel patch and touches two layers:
 *
 *   1. fs/namespace.c:mnt_alloc_id() hands out a *fake* id
 *      (ida_alloc_min(&mnt_id_ida, DEFAULT_KSU_MNT_ID, GFP_KERNEL)) whenever
 *      the mount is being created by a ksu process, and copy_mnt_ns() gives
 *      the clones of such a mount one as well.  From that moment the mount
 *      carries `mnt_id >= DEFAULT_KSU_MNT_ID`, which is the flag the rest of
 *      the feature keys off.  mnt_free_id() frees whatever id the mount
 *      currently has, so fake ids go back to the same ida and nothing leaks
 *      and nothing collides with a real id.
 *
 *   2. the three show_* callbacks in fs/proc_namespace.c print nothing for
 *      such a mount unless the reader is a ksu process, and __lookup_mnt()
 *      refuses to resolve a path onto one while the caller carries
 *      TIF_PROC_UMOUNTED (i.e. after KernelSU umounted that package).
 *
 * We are a module, so both layers become probes:
 *
 *   - Marking happens right after the fact.  alloc_vfsmnt() is the single
 *     place a `struct mount` is allocated (it calls mnt_alloc_id() itself),
 *     so a kretprobe there covers every creation path: mount(2), fsopen
 *     based mounts and clone_mnt() cloning.  The handler swaps the real id
 *     for a fake one and returns the real id to the ida.  clone_mnt() gets
 *     its own kretprobe that remembers the *source* mount's id, because a
 *     non-ksu process can clone a hidden mount (unshare(CLONE_NEWNS) in an
 *     app) and the clone has to stay hidden.
 *
 *   - Hiding is one kprobe per show_* callback that returns straight away
 *     (the whole line is skipped, exactly like upstream's `return 0`), plus
 *     a kretprobe on __lookup_mnt() that answers "nothing is mounted here"
 *     for umounted tasks.  These four only exist while userspace has the
 *     feature switched on: __lookup_mnt() is on every path walk that
 *     crosses a mount point, and a trap there has no business being there
 *     when the feature is off.
 *
 * Both handler kinds run with interrupts disabled - kprobe pre_handlers in
 * the breakpoint exception handler, kretprobe handlers inside
 * kretprobe_hash_lock() (a raw spinlock taken with IRQs off) - so every
 * allocation here is GFP_ATOMIC and nothing sleeps.  For the same reason
 * the "am I a ksu process" test reads the task SID through
 * security_task_getsecid() (pure field reads) instead of going through any
 * of the cached-SID string helpers.
 *
 * Deliberate deviations from upstream, all documented in
 * docs/susfs-lkm-feasibility.md (§11.5):
 *   - mnt_group_id is not virtualised, so peer groups stay visible,
 *   - __lookup_mnt() says "nothing here" instead of "the first legal mount
 *     below this one",
 *   - mounts created by kernel:s0 are not marked: our restore script builds
 *     the /product/bin overlay from that domain and hiding it would make
 *     `su` resolve to the stock read-only directory,
 *   - the copy_mnt_ns() case reuses no id, every clone gets a fresh fake one,
 *   - marking never stops; upstream stops once /sdcard/Android/data is
 *     decrypted, which is strictly less hiding, never more,
 *   - fake ids are allocated by range from the bottom of the ksu range,
 *     upstream allocates them min-first from the same ida,
 *   - the __lookup_mnt() probe is optional (module parameter `lookup_hook`,
 *     on by default): it is the only piece of this feature that sits on a
 *     path every process walks through, so it can be switched off on a
 *     device where the breakpoint shows up in the profile.
 */

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/idr.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/*
 * The real layout of `struct mount` (and real_mount()).  This is the
 * kernel's own private header, pulled in here on purpose: the whole feature
 * depends on mnt_id sitting where the compiler that built the kernel put
 * it, so we compile against the very same declaration instead of
 * hard-coding an offset, and validate the result once at init time (see
 * susfs_mount_validate_layout()).
 */
#include <fs/mount.h>

#include "susfs_internal.h"
#include "../selinux/selinux.h"

/* Highest id the kernel's mnt_id_ida can hand out as a *real* id. */
#define SUSFS_MOUNT_FAKE_ID_MAX 0x7fffffff
#define SUSFS_MOUNT_FAKE_ID_MIN DEFAULT_KSU_MNT_ID

/*
 * kretprobe instance pools.  alloc_vfsmnt()/clone_mnt() never nest, but the
 * pool is shared by every task on the box, so keep some headroom;  running
 * dry only means the return handler is skipped for that call.
 * __lookup_mnt() is on the path-walk fast path and is the busiest of the
 * three, hence the larger pool.
 */
#define SUSFS_MOUNT_MAXACTIVE_ALLOC 64
#define SUSFS_MOUNT_MAXACTIVE_CLONE 64
#define SUSFS_MOUNT_MAXACTIVE_LOOKUP 128

/*
 * The kernel's own mount-id allocator, i.e. `static struct ida mnt_id_ida`
 * in fs/namespace.c.  It is not exported, so it is resolved through
 * kallsyms at init.
 */
static struct ida *susfs_mount_ida;

/* SID of u:r:ksu:s0, resolved once at init (0 = not resolved). */
static u32 susfs_mount_ksu_sid;

/* Everything the marking side needs is in place. */
static bool susfs_mount_mark_ok;

/* The hiding hooks (three show_*, plus __lookup_mnt when enabled) can be
 * installed on this kernel - trial-registered once at init. */
static bool susfs_mount_hide_ok;

/* The three show_* hiding probes are installed right now. */
static bool susfs_mount_hide_armed;

/*
 * Whether the __lookup_mnt() half of the hiding is installed.  Kept apart
 * from susfs_mount_hide_armed so that the parameter below can keep it out
 * while the three show_* probes are on.
 */
static bool susfs_mount_lookup_armed;

/*
 * Install the __lookup_mnt() probe (default: yes).
 *
 * Upstream pays a compare here because it is a kernel patch; we pay a
 * breakpoint trap.  That is the one hot spot of this feature - the function
 * runs for every path resolution that steps through a mount point - so the
 * escape hatch is a parameter rather than a rebuild.  Turning it off keeps
 * the /proc mounts, mountinfo and mountstats hiding and only loses the
 * "an umounted app cannot walk into a sus mount" half.
 */
static bool susfs_mount_lookup_hook = true;
module_param_named(lookup_hook, susfs_mount_lookup_hook, bool, 0644);
MODULE_PARM_DESC(lookup_hook,
		 "install the __lookup_mnt kretprobe (default 1); 0 keeps only the /proc hiding");

/* Userspace switch, read by the show_ and __lookup_mnt handlers. */
static bool susfs_mount_hide_enabled;

/* One-shot complaint when the fake id range is exhausted. */
static bool susfs_mount_ida_warned;

static DEFINE_MUTEX(susfs_mount_mutex);

static struct kretprobe susfs_mount_krp_alloc;
static struct kretprobe susfs_mount_krp_clone;
static struct kprobe susfs_mount_kp_vfsmnt;
static struct kprobe susfs_mount_kp_mountinfo;
static struct kprobe susfs_mount_kp_vfsstat;
static struct kretprobe susfs_mount_krp_lookup;

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * Is the current task running in the ksu domain?
 *
 * Called from probe context, so it must not sleep: security_task_getsecid()
 * is one indirect call into selinux_task_getsecid(), which reads the SID
 * out of the cred's security blob.  (BakaSU's own is_ksu_domain() would do
 * as well, but its fallback path - when the cached SID has not been set up
 * - builds a secctx string, and that is not a thing to do with IRQs off.)
 */
static bool susfs_mount_is_ksu_proc(void)
{
	u32 sid = 0;
	u32 want = READ_ONCE(susfs_mount_ksu_sid);

	if (!want)
		return false;

	security_task_getsecid(current, &sid);
	return sid == want;
}

/*
 * Is this id one of ours?  Everything at or above DEFAULT_KSU_MNT_ID is:
 * the kernel's ida never reaches that value (it counts up from 0), so the
 * range doubles as the "this mount is hidden" flag.
 */
static inline bool susfs_mount_id_is_fake(int id)
{
	return id >= SUSFS_MOUNT_FAKE_ID_MIN;
}

/*
 * Give a freshly allocated mount a fake id, returning the real one to the
 * ida.  Idempotent: a mount that already carries a fake id is left alone,
 * which is what makes the alloc_vfsmnt() and clone_mnt() probes compose.
 */
static void susfs_mount_mark(struct mount *mnt)
{
	struct ida *ida;
	int real_id, fake_id;

	if (!mnt)
		return;

	ida = READ_ONCE(susfs_mount_ida);
	if (!ida)
		return;

	real_id = READ_ONCE(mnt->mnt_id);
	if (susfs_mount_id_is_fake(real_id))
		return;

	/*
	 * GFP_ATOMIC: this runs either in the kretprobe trampoline (IRQs
	 * off, kretprobe_hash_lock() held) or, for the clone case, from
	 * clone_mnt() while it holds namespace_sem plus whatever per-fs
	 * locks the caller took.
	 */
	fake_id = ida_alloc_range(ida, SUSFS_MOUNT_FAKE_ID_MIN,
				  SUSFS_MOUNT_FAKE_ID_MAX, GFP_ATOMIC);
	if (fake_id < 0) {
		/*
		 * Out of fake ids (absurd at ~2e9 ids, but the caller may
		 * run with a tiny memcg).  Leaving the real id in place is
		 * the only safe option: the mount simply stays visible.
		 */
		if (!READ_ONCE(susfs_mount_ida_warned)) {
			WRITE_ONCE(susfs_mount_ida_warned, true);
			SUSFS_LOGE("no fake mnt_id available (%d), mount %d stays visible\n",
				   fake_id, real_id);
		}
		return;
	}

	WRITE_ONCE(mnt->mnt_id, fake_id);
	/*
	 * The real id is now unused.  Freeing it here (instead of hooking
	 * mnt_free_id()) keeps the ida balanced: the kernel frees whatever id
	 * the mount carries at unmount time, which is the fake one.
	 */
	ida_free(ida, real_id);
}

/* ------------------------------------------------------------------ */
/* marking probes                                                     */
/* ------------------------------------------------------------------ */

/*
 * alloc_vfsmnt() is where every `struct mount` is born, and it is static,
 * so it can only be reached by name - which is fine, a kretprobe on a
 * static function works the same as on any other.
 */
static int susfs_mount_ret_alloc(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct mount *mnt = (struct mount *)regs->regs[0];

	/* alloc_vfsmnt() returns NULL on failure */
	if (!mnt)
		return 0;

	if (!susfs_mount_is_ksu_proc())
		return 0;

	susfs_mount_mark(mnt);
	return 0;
}

/*
 * Remember the id of the mount being cloned.  A clone of a hidden mount has
 * to stay hidden even when a non-ksu process does the cloning (an app
 * calling unshare(CLONE_NEWNS) gets a private copy of every mount).
 */
static int susfs_mount_entry_clone(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct mount *old = (struct mount *)regs->regs[0];
	int *slot = (int *)ri->data;

	if (!old || IS_ERR(old))
		*slot = -1;
	else
		*slot = READ_ONCE(old->mnt_id);
	return 0;
}

static int susfs_mount_ret_clone(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct mount *new = (struct mount *)regs->regs[0];
	int old_id = *(int *)ri->data;

	/* clone_mnt() returns an ERR_PTR on failure */
	if (!new || IS_ERR(new))
		return 0;

	/*
	 * The ksu case was already handled by the alloc_vfsmnt() probe (it
	 * runs inside clone_mnt()); marking again is a no-op because the
	 * fake id is already there.  All that is left is propagation.
	 */
	if (!susfs_mount_id_is_fake(old_id) && !susfs_mount_is_ksu_proc())
		return 0;

	susfs_mount_mark(new);
	return 0;
}

/* ------------------------------------------------------------------ */
/* hiding probes                                                      */
/* ------------------------------------------------------------------ */

/*
 * show_vfsmnt()/show_mountinfo()/show_vfsstat() all have the signature
 *
 *	int show_x(struct seq_file *m, struct vfsmount *mnt)
 *
 * and are called from m_show() with `&r->mnt` for a `struct mount *r`, so
 * the mount pointer is in x1 and returning with x0 = 0, pc = lr skips the
 * line exactly like upstream's `return 0` inside the callback does.
 */
static int susfs_mount_pre_show(struct kprobe *kp, struct pt_regs *regs)
{
	struct vfsmount *vfs = (struct vfsmount *)regs->regs[1];
	struct mount *mnt;

	if (!READ_ONCE(susfs_mount_hide_enabled))
		return 0;
	if (!vfs)
		return 0;

	mnt = real_mount(vfs);
	if (!susfs_mount_id_is_fake(READ_ONCE(mnt->mnt_id)))
		return 0;
	if (susfs_mount_is_ksu_proc())
		return 0;

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * __lookup_mnt(mnt, dentry) answers "is something mounted here?".  For a
 * task that KernelSU has just umounted a package for, the answer must be no
 * for hidden mounts, so the path resolves to the underlying directory.
 *
 * Upstream returns the first *legal* mount below instead; we return NULL.
 */
static int susfs_mount_ret_lookup(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct mount *mnt = (struct mount *)regs->regs[0];

	if (!mnt)
		return 0;
	if (!susfs_is_current_proc_umounted())
		return 0;
	if (!susfs_mount_id_is_fake(READ_ONCE(mnt->mnt_id)))
		return 0;
	/* never hide anything from ourselves */
	if (susfs_mount_is_ksu_proc())
		return 0;

	regs->regs[0] = 0;
	return 1;
}

/* ------------------------------------------------------------------ */
/* (dis)arming the hiding hooks                                       */
/* ------------------------------------------------------------------ */

static int susfs_mount_arm_hide(void)
{
	int ret;

	ret = susfs_register_kprobe_at(&susfs_mount_kp_vfsmnt, "show_vfsmnt",
				       susfs_mount_pre_show);
	if (ret)
		return ret;

	ret = susfs_register_kprobe_at(&susfs_mount_kp_mountinfo,
				       "show_mountinfo", susfs_mount_pre_show);
	if (ret) {
		unregister_kprobe(&susfs_mount_kp_vfsmnt);
		memset(&susfs_mount_kp_vfsmnt, 0, sizeof(susfs_mount_kp_vfsmnt));
		return ret;
	}

	ret = susfs_register_kprobe_at(&susfs_mount_kp_vfsstat, "show_vfsstat",
				       susfs_mount_pre_show);
	if (ret) {
		unregister_kprobe(&susfs_mount_kp_mountinfo);
		memset(&susfs_mount_kp_mountinfo, 0,
		       sizeof(susfs_mount_kp_mountinfo));
		unregister_kprobe(&susfs_mount_kp_vfsmnt);
		memset(&susfs_mount_kp_vfsmnt, 0, sizeof(susfs_mount_kp_vfsmnt));
		return ret;
	}

	if (READ_ONCE(susfs_mount_lookup_hook)) {
		susfs_mount_krp_lookup.maxactive = SUSFS_MOUNT_MAXACTIVE_LOOKUP;
		ret = susfs_register_kretprobe(&susfs_mount_krp_lookup,
					       "__lookup_mnt", NULL,
					       susfs_mount_ret_lookup, 0);
		if (ret) {
			unregister_kprobe(&susfs_mount_kp_vfsstat);
			memset(&susfs_mount_kp_vfsstat, 0,
			       sizeof(susfs_mount_kp_vfsstat));
			unregister_kprobe(&susfs_mount_kp_mountinfo);
			memset(&susfs_mount_kp_mountinfo, 0,
			       sizeof(susfs_mount_kp_mountinfo));
			unregister_kprobe(&susfs_mount_kp_vfsmnt);
			memset(&susfs_mount_kp_vfsmnt, 0,
			       sizeof(susfs_mount_kp_vfsmnt));
			return ret;
		}
		WRITE_ONCE(susfs_mount_lookup_armed, true);
	}

	return 0;
}

static void susfs_mount_disarm_hide(void)
{
	if (READ_ONCE(susfs_mount_lookup_armed)) {
		unregister_kretprobe(&susfs_mount_krp_lookup);
		memset(&susfs_mount_krp_lookup, 0, sizeof(susfs_mount_krp_lookup));
		WRITE_ONCE(susfs_mount_lookup_armed, false);
	}
	unregister_kprobe(&susfs_mount_kp_vfsstat);
	memset(&susfs_mount_kp_vfsstat, 0, sizeof(susfs_mount_kp_vfsstat));
	unregister_kprobe(&susfs_mount_kp_mountinfo);
	memset(&susfs_mount_kp_mountinfo, 0, sizeof(susfs_mount_kp_mountinfo));
	unregister_kprobe(&susfs_mount_kp_vfsmnt);
	memset(&susfs_mount_kp_vfsmnt, 0, sizeof(susfs_mount_kp_vfsmnt));
}

/* ------------------------------------------------------------------ */
/* userspace command                                                  */
/* ------------------------------------------------------------------ */

void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info)
{
	struct st_susfs_hide_sus_mnts_for_non_su_procs info = { 0 };
	int err = 0;

	if (copy_from_user(&info,
			   (struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)
				   *user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy;
	}

	if (!READ_ONCE(susfs_mount_hide_ok)) {
		/*
		 * The show_* or __lookup_mnt probes are not installable on
		 * this kernel; refuse instead of reporting success for a
		 * switch that would do nothing.
		 */
		info.err = -EOPNOTSUPP;
		goto out_copy;
	}

	if (mutex_lock_interruptible(&susfs_mount_mutex)) {
		info.err = -ERESTARTSYS;
		goto out_copy;
	}

	if (info.enabled) {
		if (!READ_ONCE(susfs_mount_hide_armed)) {
			err = susfs_mount_arm_hide();
			if (err) {
				SUSFS_LOGE("failed to install mount hiding hooks, err: %d\n",
					   err);
				info.err = err;
				goto out_unlock;
			}
			WRITE_ONCE(susfs_mount_hide_armed, true);
		}
		WRITE_ONCE(susfs_mount_hide_enabled, true);
	} else {
		/*
		 * Switch the handlers off before dropping the probes: an
		 * instance that is already unwinding must not use a probe
		 * that is being removed.
		 */
		WRITE_ONCE(susfs_mount_hide_enabled, false);
		if (READ_ONCE(susfs_mount_hide_armed)) {
			susfs_mount_disarm_hide();
			WRITE_ONCE(susfs_mount_hide_armed, false);
		}
	}

	info.err = 0;
	SUSFS_LOGI("hide sus mounts for non-su procs: %d\n", !!info.enabled);

out_unlock:
	mutex_unlock(&susfs_mount_mutex);
out_copy:
	if (copy_to_user((struct st_susfs_hide_sus_mnts_for_non_su_procs __user *)
				 *user_info,
			 &info, sizeof(info)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS -> ret: %d\n",
		   info.err);
}

/* ------------------------------------------------------------------ */
/* availability / init                                                */
/* ------------------------------------------------------------------ */

bool susfs_mount_available(void)
{
	return READ_ONCE(susfs_mount_mark_ok) && READ_ONCE(susfs_mount_hide_ok);
}

/*
 * Compare the compiled-in `struct mount` layout against the running
 * kernel's: real_mount() is a container_of(), so mnt_ns and mnt_id are only
 * read correctly if the struct we compiled against matches the one the
 * kernel built.  current->fs->root/pwd are mounts of the caller, whose
 * namespace we know, which makes this a two-field check (id in the real
 * range *and* the namespace pointer agreeing) rather than a guess.
 */
static bool susfs_mount_layout_ok(struct vfsmount *vfs,
				  struct mnt_namespace *ns)
{
	struct mount *mnt;
	int id;

	if (!vfs || !ns)
		return false;

	mnt = real_mount(vfs);
	if (READ_ONCE(mnt->mnt_ns) != ns)
		return false;

	id = READ_ONCE(mnt->mnt_id);
	if (id < 0 || susfs_mount_id_is_fake(id))
		return false;

	return true;
}

static int susfs_mount_validate_layout(void)
{
	struct fs_struct *fs;
	struct mnt_namespace *ns;

	if (!current->nsproxy)
		return -EAGAIN;
	ns = current->nsproxy->mnt_ns;
	if (!ns)
		return -EAGAIN;

	fs = current->fs;
	if (!fs)
		return -EAGAIN;

	if (susfs_mount_layout_ok(fs->root.mnt, ns))
		return 0;
	if (susfs_mount_layout_ok(fs->pwd.mnt, ns))
		return 0;

	return -EINVAL;
}

void susfs_mount_init(void)
{
	struct kprobe kp;
	int ret;

	/* mnt_id_ida: not exported, resolved through kallsyms. */
	susfs_mount_ida = (struct ida *)susfs_lookup_symbol("mnt_id_ida");
	if (!susfs_mount_ida) {
		SUSFS_LOGE("mnt_id_ida not found, sus_mount stays off\n");
		return;
	}

	ret = security_secctx_to_secid(KERNEL_SU_CONTEXT,
				       strlen(KERNEL_SU_CONTEXT),
				       &susfs_mount_ksu_sid);
	if (ret || !susfs_mount_ksu_sid) {
		SUSFS_LOGE("cannot resolve %s to a SID (%d), sus_mount stays off\n",
			   KERNEL_SU_CONTEXT, ret);
		susfs_mount_ksu_sid = 0;
		return;
	}

	ret = susfs_mount_validate_layout();
	if (ret) {
		SUSFS_LOGE("struct mount layout check failed (%d), sus_mount stays off\n",
			   ret);
		return;
	}

	/*
	 * The hiding hooks are only installed when userspace switches the
	 * feature on, but they have to be installable then, so try them now
	 * and throw them away again.  If that fails the whole feature stays
	 * off: a switch that reports success while doing nothing would be a
	 * lie to the manager.
	 */
	ret = susfs_register_kprobe_at(&kp, "show_vfsmnt",
				       susfs_mount_pre_show);
	if (ret) {
		SUSFS_LOGE("show_vfsmnt probe unavailable (%d), sus_mount stays off\n",
			   ret);
		return;
	}
	unregister_kprobe(&kp);

	ret = susfs_register_kprobe_at(&kp, "show_mountinfo",
				       susfs_mount_pre_show);
	if (ret) {
		SUSFS_LOGE("show_mountinfo probe unavailable (%d), sus_mount stays off\n",
			   ret);
		return;
	}
	unregister_kprobe(&kp);

	ret = susfs_register_kprobe_at(&kp, "show_vfsstat",
				       susfs_mount_pre_show);
	if (ret) {
		SUSFS_LOGE("show_vfsstat probe unavailable (%d), sus_mount stays off\n",
			   ret);
		return;
	}
	unregister_kprobe(&kp);

	if (READ_ONCE(susfs_mount_lookup_hook)) {
		struct kretprobe krp;

		memset(&krp, 0, sizeof(krp));
		krp.maxactive = SUSFS_MOUNT_MAXACTIVE_LOOKUP;
		ret = susfs_register_kretprobe(&krp, "__lookup_mnt", NULL,
					       susfs_mount_ret_lookup, 0);
		if (ret) {
			SUSFS_LOGE("__lookup_mnt probe unavailable (%d), sus_mount stays off\n",
				   ret);
			return;
		}
		unregister_kretprobe(&krp);
	} else {
		SUSFS_LOGI("lookup_hook=0: __lookup_mnt is left alone (only /proc hiding)\n");
	}

	/*
	 * Marking, on the other hand, has to be live from now on: a mount
	 * created by us before the switch is flipped is still hidden
	 * afterwards, and there is no way to mark a mount retroactively
	 * without walking every namespace.
	 */
	susfs_mount_krp_alloc.maxactive = SUSFS_MOUNT_MAXACTIVE_ALLOC;
	ret = susfs_register_kretprobe(&susfs_mount_krp_alloc, "alloc_vfsmnt",
				       NULL, susfs_mount_ret_alloc, 0);
	if (ret) {
		SUSFS_LOGE("alloc_vfsmnt probe unavailable (%d), sus_mount stays off\n",
			   ret);
		return;
	}

	susfs_mount_krp_clone.maxactive = SUSFS_MOUNT_MAXACTIVE_CLONE;
	ret = susfs_register_kretprobe(&susfs_mount_krp_clone, "clone_mnt",
				       susfs_mount_entry_clone,
				       susfs_mount_ret_clone, sizeof(int));
	if (ret) {
		SUSFS_LOGE("clone_mnt probe unavailable (%d), sus_mount stays off\n",
			   ret);
		unregister_kretprobe(&susfs_mount_krp_alloc);
		memset(&susfs_mount_krp_alloc, 0, sizeof(susfs_mount_krp_alloc));
		return;
	}

	/*
	 * Both switch groups are live now, so the feature can finally report
	 * itself as available: available() must never be true while either
	 * half is still missing.
	 */
	WRITE_ONCE(susfs_mount_hide_ok, true);
	WRITE_ONCE(susfs_mount_mark_ok, true);
	SUSFS_LOGI("sus_mount ready (ksu sid %u), marking live, hiding arms on request\n",
		   susfs_mount_ksu_sid);
}
