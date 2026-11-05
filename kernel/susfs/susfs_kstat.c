// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_kstat.c - SuSFS SUS_KSTAT (metadata spoofing) for the LKM edition.
 *
 * Upstream SuSFS is a kernel patch, so every spoof point is a plain call
 * inserted into the function that owns it:
 *
 *   generic_fillattr()      -> susfs_sus_kstat_spoof_generic_fillattr()
 *   show_map_vma()          -> susfs_sus_kstat_spoof_show_map_vma()
 *   vfs_statfs()            -> susfs_sus_kstat_spoof_vfs_statfs()
 *   inotify_fdinfo()        -> susfs_sus_kstat_spoof_inotify_fdinfo()
 *
 * We load a stock, locked boot image, so we cannot patch those files.  Each
 * call site therefore becomes a kprobe and we re-derive the arguments the
 * call site would have handed over.  The four hooks, and why each one sits
 * where it does (offsets verified against the stock 5.4.254-qgki image with
 * capstone; base 0xffffffc010080000):
 *
 *  1. stat/lstat/fstat/statx -> kretprobe on vfs_getattr_nosec()
 *
 *     generic_fillattr() is inlined into vfs_getattr_nosec() in this kernel
 *     (there is no call instruction and no separate symbol), so it cannot be
 *     hooked.  One level up is equivalent: the kretprobe rewrites the
 *     already filled struct kstat, which is exactly the state the patched
 *     generic_fillattr() would have produced before returning.
 *     vfs_statx() (used by statx) and vfs_getattr()/vfs_statx_fd() all funnel
 *     through it, so a single probe covers every stat family syscall.
 *
 *  2. /proc/self/maps -> kprobe on show_vma_header_prefix()
 *
 *     show_map_vma() calls it with x0=m, x1=start, x2=end, x3=flags,
 *     x4=pgoff, x5=dev, x6=ino, and it prints "dev" and "ino" straight from
 *     those two registers.  Rewriting x5/x6 is enough; no per-cpu inode
 *     hand-off is needed.  (show_numa_map()'s rollup line also calls it, but
 *     with dev=0/ino=0, which can never match a table entry.)
 *
 *  3. statfs/fstatfs -> kretprobe on vfs_statfs()
 *
 *     Both user_statfs() and fd_statfs() go through vfs_statfs().  Upstream
 *     calls statfs_by_dentry() + calculate_f_flags(); vfs_statfs() is exactly
 *     that pair (see fs/statfs.c), so we simply overwrite the filled
 *     struct kstatfs on the way out.
 *
 *  4. /proc/<pid>/fdinfo/<inotify fd> -> kprobe on seq_printf()
 *
 *     inotify_fdinfo() is static and reached through a function pointer, and
 *     its first seq_printf() prints "ino:%lx sdev:%x" from x3/x4.  We hook
 *     the shared seq_printf() and only act when the return address is the
 *     call site we located inside inotify_fdinfo() at registration time
 *     (scan the function body for the first `bl seq_printf`).  Using the
 *     exact return address instead of an address window means a spoof can
 *     never leak into an unrelated seq_printf().
 *
 * Upstream also spoofs `ino:` in fs/proc/fd.c's seq_show().  That line does
 * not exist in this kernel: its seq_show() prints "pos/flags/mnt_id" only,
 * and the mnt_id it prints comes straight from real_mount()->mnt_id, i.e.
 * the fake id SUS_MOUNT already installed.  There is therefore nothing left
 * for SUS_KSTAT to rewrite on this surface, and no hook is registered for it
 * (an `ino:` line that only appeared for spoofed files would itself be the
 * anomaly).
 *
 * Synchronisation
 * ---------------
 * Upstream keeps the table under a mutex and publishes entries with
 * hash_add_rcu(); deletions (only ever from update) wait for a grace period
 * before re-adding.  We instead keep a spinlock for the table and never free
 * an entry:
 *
 *   - lookups run inside kprobe handlers, i.e. from arbitrary process
 *     context.  A short spinlock is cheaper and far easier to reason about
 *     than RCU here.
 *   - update rewrites the existing entry in place.  Because every reader
 *     copies what it needs while holding the lock, there is no torn read,
 *     and because the entry is never freed there is no grace period to wait
 *     for (synchronize_rcu() from a kprobe handler would be unpleasant).
 *   - the price is that a re-marked path leaks the old entry's bytes.  The
 *     table is bounded by the number of files userspace asks to hide, and
 *     update reuses the entry, so this does not grow over time.
 *
 * Everything that can sleep (kern_path(), vfs_statfs(), kzalloc(),
 * copy_from_user(), register_kprobe()) is called with the spinlock dropped.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <linux/kprobes.h>

#include "susfs_internal.h"

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT

#define SUS_KSTAT_HASH_BITS 14

/*
 * inotify_fdinfo() is ~0x1d0 bytes on this kernel and its first
 * seq_printf() call is at +0x84.  We only ever need the first match, so a
 * generous scan window keeps us safe across small rebuilds without having to
 * know the exact function size.
 */
#define SUSFS_INOTIFY_SCAN_SIZE 0x200

static DEFINE_HASHTABLE(SUS_KSTAT_HLIST, SUS_KSTAT_HASH_BITS);
static DEFINE_SPINLOCK(susfs_kstat_lock);
static DEFINE_MUTEX(susfs_kstat_reg_lock);
static atomic_t susfs_kstat_entries = ATOMIC_INIT(0);

/* Populated once, on first successful add. */
static bool susfs_kstat_hooks_on;
/*
 * True when the one core probe (vfs_getattr_nosec kretprobe) is known to be
 * installable.  Answered from an init-time trial registration so that
 * susfs_get_enabled_features() tells the truth before the first rule, and
 * cleared again if the real install attempt later fails.
 */
static bool susfs_kstat_core_ok;
static unsigned long susfs_inotify_seq_lr;

/* ------------------------------------------------------------------ */
/* table                                                               */
/* ------------------------------------------------------------------ */

/*
 * Look up an entry by (ino, dev) and let @fn rewrite whatever it wants while
 * the table lock is held.  Entries are never freed, so the pointer stays
 * valid after the lock is dropped as well, but readers copy what they need
 * inside the lock so that a concurrent update cannot tear the values.
 */
static void susfs_kstat_walk(unsigned long ino, unsigned long dev,
			     void (*fn)(struct st_susfs_sus_kstat_hlist *, void *),
			     void *arg)
{
	struct st_susfs_sus_kstat_hlist *entry;

	if (!atomic_read(&susfs_kstat_entries))
		return;

	spin_lock(&susfs_kstat_lock);
	hash_for_each_possible(SUS_KSTAT_HLIST, entry, node, ino) {
		if (entry->target_ino == ino && entry->target_dev == dev) {
			fn(entry, arg);
			break;
		}
	}
	spin_unlock(&susfs_kstat_lock);
}

static bool susfs_kstat_inode_marked(const struct inode *inode)
{
	return inode && inode->i_mapping &&
	       test_bit(AS_FLAGS_SUS_KSTAT, &inode->i_mapping->flags);
}

/* ------------------------------------------------------------------ */
/* marking + add / update                                              */
/* ------------------------------------------------------------------ */

/*
 * Resolve @pathname and (re)fill the runtime half of @entry: the real
 * (ino, dev) the entry is keyed on, the mount's statfs snapshot and the
 * AS_FLAGS_SUS_KSTAT bit on the backing inode.
 *
 * Upstream takes target_ino from userspace.  We take it from the inode that
 * kern_path() actually resolved instead: both are the same value when
 * userspace is correct (ksud stats the very same path), and the authoritative
 * one cannot be stale if the file was replaced between the stat and the
 * command.
 */
static int susfs_mark_inode_sus_kstat(const char *target_pathname,
				      struct st_susfs_sus_kstat_hlist *entry,
				      bool is_update)
{
	struct path path;
	struct inode *inode;
	int err;

	err = kern_path(target_pathname, 0, &path);
	if (err) {
		SUSFS_LOGE("failed opening file '%s'\n", target_pathname);
		return err;
	}

	inode = d_backing_inode(path.dentry);
	if (!inode || !inode->i_mapping) {
		SUSFS_LOGE("inode || inode->i_mapping is NULL\n");
		err = -ENOENT;
		goto out;
	}

	entry->is_fuse = false;
	entry->target_ino = inode->i_ino;
	entry->target_dev = inode->i_sb->s_dev;
	/*
	 * Upstream stores susfs_get_non_sus_mnt_id_from_mnt() here for two
	 * consumers: kstat.mnt_id (5.10+) and the /proc/<pid>/fdinfo ino line.
	 * Neither exists on this kernel (5.4 has no mnt_id in struct kstat, and
	 * fs/proc/fd.c::seq_show() prints only pos/flags/mnt_id with the mount's
	 * own id, which SUS_MOUNT already rewrites), so the field stays 0 and is
	 * never read.  Keeping the field populated with a fabricated value
	 * would only invite a future reader to trust it.
	 */
	entry->spoofed_mnt_id = 0;

	/*
	 * Upstream: statfs_by_dentry(no_sus_vfsmnt->mnt_root) followed by
	 * f_flags = calculate_f_flags(no_sus_vfsmnt).  vfs_statfs() is
	 * literally that pair (fs/statfs.c), and statfs_by_dentry() only ever
	 * looks at dentry->d_sb, so handing it the resolved path instead of
	 * the mount root yields the same super_block and the same f_flags.
	 */
	err = vfs_statfs(&path, &entry->spoofed_kstatfs);
	if (err) {
		SUSFS_LOGE("vfs_statfs failed on '%s': %d\n", target_pathname, err);
		goto out;
	}

	/*
	 * Upstream refreshes spoofed_size on update (the file behind the
	 * mount point was just replaced).  Only meaningful when userspace set
	 * KSTAT_SPOOF_SIZE, i.e. for the "full clone" variant.
	 */
	if (is_update)
		entry->info.spoofed_size = inode->i_size;

	set_bit(AS_FLAGS_SUS_KSTAT, &inode->i_mapping->flags);

	SUSFS_LOGI("marked AS_FLAGS_SUS_KSTAT on pathname: '%s', inode->i_sb->s_dev: %u, inode->i_ino: %lu, inode->i_mapping->flags: 0x%lx\n",
		   target_pathname, inode->i_sb->s_dev, inode->i_ino,
		   inode->i_mapping->flags);
out:
	path_put(&path);
	return err;
}

/*
 * Register the four probes.  Called once, from the first successful add, so
 * a kernel that never uses SUS_KSTAT carries no breakpoint at all.
 */
static void susfs_kstat_register_hooks(void);

void susfs_add_sus_kstat(void __user **user_info)
{
	struct st_susfs_sus_kstat info = {0};
	struct st_susfs_sus_kstat_hlist *new_entry, *tmp;
	bool dup = false;
	int bkt;

	if (copy_from_user(&info, (void __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (!info.target_pathname[0]) {
		info.err = -EINVAL;
		goto out;
	}
	info.target_pathname[SUSFS_MAX_LEN_PATHNAME - 1] = '\0';

	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry) {
		info.err = -ENOMEM;
		goto out;
	}

	memcpy(&new_entry->info, &info, sizeof(info));
	/*
	 * ksud sends st_dev as libc sees it, i.e. new_encode_dev().  Turn it
	 * back into the kernel's own dev_t once, here, so every spoof point
	 * (kstat.dev, maps dev column, fdinfo sdev) can use it verbatim.
	 */
	new_entry->info.spoofed_dev = new_decode_dev((u32)info.spoofed_dev);

	info.err = susfs_mark_inode_sus_kstat(new_entry->info.target_pathname,
					      new_entry, false);
	if (info.err) {
		kfree(new_entry);
		goto out;
	}

	/*
	 * Upstream replaces a pre-existing entry for the same pathname.  We
	 * overwrite it in place: same visible result, no free, no grace
	 * period.
	 *
	 * The bucket is keyed on target_ino, but the file behind a given
	 * pathname can be replaced between two adds (rewrite-then-rename
	 * changes the inode), so the duplicate has to be looked up across the
	 * whole table.  Searching only the new entry's bucket would leave the
	 * old node in its stale bucket, where it can never be found again and
	 * is simply dead weight.
	 */
	spin_lock(&susfs_kstat_lock);
	hash_for_each(SUS_KSTAT_HLIST, bkt, tmp, node) {
		if (!strcmp(tmp->info.target_pathname,
			    new_entry->info.target_pathname)) {
			dup = true;
			break;
		}
	}

	if (dup) {
		bool rekey = tmp->target_ino != new_entry->target_ino;

		if (rekey)
			hash_del(&tmp->node);

		tmp->target_ino = new_entry->target_ino;
		tmp->target_dev = new_entry->target_dev;
		memcpy(&tmp->spoofed_kstatfs, &new_entry->spoofed_kstatfs,
		       sizeof(tmp->spoofed_kstatfs));
		tmp->spoofed_mnt_id = new_entry->spoofed_mnt_id;
		tmp->is_fuse = new_entry->is_fuse;
		memcpy(&tmp->info, &new_entry->info, sizeof(tmp->info));

		if (rekey)
			hash_add(SUS_KSTAT_HLIST, &tmp->node, tmp->target_ino);
	} else {
		hash_add(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);
		atomic_inc(&susfs_kstat_entries);
	}
	spin_unlock(&susfs_kstat_lock);

	if (dup) {
		SUSFS_LOGI("pathname: '%s' already exists, entry updated\n",
			   new_entry->info.target_pathname);
		kfree(new_entry);
	} else {
		SUSFS_LOGI("added '%s'\n", new_entry->info.target_pathname);
	}

	if (!READ_ONCE(susfs_kstat_hooks_on))
		susfs_kstat_register_hooks();

out:
	if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*user_info)->err,
			 &info.err, sizeof(info.err)))
		info.err = -EFAULT;
	/*
	 * Upstream labels the result with the command the caller actually
	 * issued; CMD_SUSFS_ADD_SUS_KSTAT and CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY
	 * share this function and are told apart only by info.is_statically
	 * (ksud sets it for the *_STATICALLY form and nowhere else).  The label
	 * is the only observable proof of which path ran, so keep it honest.
	 */
	SUSFS_LOGI("%s -> ret: %d\n",
		   info.is_statically ? "CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY"
				      : "CMD_SUSFS_ADD_SUS_KSTAT",
		   info.err);
}

void susfs_update_sus_kstat(void __user **user_info)
{
	struct st_susfs_sus_kstat info = {0};
	struct st_susfs_sus_kstat_hlist tmp = {0}, *entry = NULL;
	struct st_susfs_sus_kstat saved;
	bool rekey;
	int bkt;

	if (copy_from_user(&info, (void __user *)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (!info.target_pathname[0]) {
		info.err = -EINVAL;
		goto out;
	}
	info.target_pathname[SUSFS_MAX_LEN_PATHNAME - 1] = '\0';

	/*
	 * Upstream keys the update on the pathname and keeps every spoofed
	 * value recorded by the matching add; only the real (ino, dev) is
	 * refreshed, because the file behind the path was just replaced.
	 */
	spin_lock(&susfs_kstat_lock);
	hash_for_each(SUS_KSTAT_HLIST, bkt, entry, node) {
		if (!strcmp(entry->info.target_pathname, info.target_pathname))
			break;
	}
	if (!entry) {
		spin_unlock(&susfs_kstat_lock);
		info.err = -ENOENT;
		SUSFS_LOGE("pathname: '%s' not found\n", info.target_pathname);
		goto out;
	}
	memcpy(&saved, &entry->info, sizeof(saved));
	tmp.is_fuse = entry->is_fuse;
	spin_unlock(&susfs_kstat_lock);

	memcpy(&tmp.info, &saved, sizeof(tmp.info));
	tmp.info.target_ino = info.target_ino;
	tmp.info.spoofed_dev = saved.spoofed_dev; /* already decoded */

	info.err = susfs_mark_inode_sus_kstat(tmp.info.target_pathname, &tmp, true);
	if (info.err)
		goto out;

	spin_lock(&susfs_kstat_lock);
	hash_for_each(SUS_KSTAT_HLIST, bkt, entry, node) {
		if (!strcmp(entry->info.target_pathname, info.target_pathname))
			break;
	}
	if (!entry) {
		/* Raced with a concurrent update that dropped nothing. */
		spin_unlock(&susfs_kstat_lock);
		info.err = -ENOENT;
		goto out;
	}

	/*
	 * The file behind the path was replaced, so the entry has to move to
	 * the new inode's bucket.  Decide that *before* overwriting the key.
	 */
	rekey = entry->target_ino != tmp.target_ino;
	if (rekey)
		hash_del(&entry->node);

	entry->target_ino = tmp.target_ino;
	entry->target_dev = tmp.target_dev;
	memcpy(&entry->spoofed_kstatfs, &tmp.spoofed_kstatfs,
	       sizeof(entry->spoofed_kstatfs));
	entry->spoofed_mnt_id = tmp.spoofed_mnt_id;
	entry->is_fuse = tmp.is_fuse;
	memcpy(&entry->info, &tmp.info, sizeof(entry->info));

	if (rekey)
		hash_add(SUS_KSTAT_HLIST, &entry->node, entry->target_ino);
	spin_unlock(&susfs_kstat_lock);

	SUSFS_LOGI("updated '%s', target_ino: %lu\n", info.target_pathname,
		   tmp.target_ino);

out:
	if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*user_info)->err,
			 &info.err, sizeof(info.err)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", info.err);
}

/* ------------------------------------------------------------------ */
/* 1. stat / lstat / fstat / statx                                     */
/* ------------------------------------------------------------------ */

struct susfs_getattr_data {
	struct kstat *stat;
	unsigned long ino;
	unsigned long dev;
};

static void susfs_kstat_apply_stat(struct st_susfs_sus_kstat_hlist *entry,
				   void *arg)
{
	struct kstat *stat = arg;
	int flags = entry->info.flags;

	if (flags & KSTAT_SPOOF_INO)
		stat->ino = entry->info.spoofed_ino;
	if (flags & KSTAT_SPOOF_DEV)
		stat->dev = (dev_t)entry->info.spoofed_dev;
	if (flags & KSTAT_SPOOF_NLINK)
		stat->nlink = entry->info.spoofed_nlink;
	if (flags & KSTAT_SPOOF_SIZE)
		stat->size = entry->info.spoofed_size;
	if (flags & KSTAT_SPOOF_ATIME_TV_SEC)
		stat->atime.tv_sec = entry->info.spoofed_atime_tv_sec;
	if (flags & KSTAT_SPOOF_ATIME_TV_NSEC)
		stat->atime.tv_nsec = entry->info.spoofed_atime_tv_nsec;
	if (flags & KSTAT_SPOOF_MTIME_TV_SEC)
		stat->mtime.tv_sec = entry->info.spoofed_mtime_tv_sec;
	if (flags & KSTAT_SPOOF_MTIME_TV_NSEC)
		stat->mtime.tv_nsec = entry->info.spoofed_mtime_tv_nsec;
	if (flags & KSTAT_SPOOF_CTIME_TV_SEC)
		stat->ctime.tv_sec = entry->info.spoofed_ctime_tv_sec;
	if (flags & KSTAT_SPOOF_CTIME_TV_NSEC)
		stat->ctime.tv_nsec = entry->info.spoofed_ctime_tv_nsec;
	if (flags & KSTAT_SPOOF_BLKSIZE)
		stat->blksize = entry->info.spoofed_blksize;
	if (flags & KSTAT_SPOOF_BLOCKS)
		stat->blocks = entry->info.spoofed_blocks;
}

static int susfs_vfs_getattr_entry(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct susfs_getattr_data *data = (void *)ri->data;
	const struct path *path;
	struct inode *inode;

	if (!atomic_read(&susfs_kstat_entries))
		return 1;

	path = (const struct path *)regs->regs[0];
	if (!path || !path->dentry)
		return 1;

	inode = d_backing_inode(path->dentry);
	if (!susfs_kstat_inode_marked(inode))
		return 1;

	data->stat = (struct kstat *)regs->regs[1];
	if (!data->stat)
		return 1;

	data->ino = inode->i_ino;
	data->dev = (unsigned long)inode->i_sb->s_dev;
	return 0;
}

static int susfs_vfs_getattr_ret(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct susfs_getattr_data *data = (void *)ri->data;

	if ((long)regs->regs[0])
		return 0;

	susfs_kstat_walk(data->ino, data->dev, susfs_kstat_apply_stat,
			 data->stat);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 2. /proc/<pid>/maps                                                 */
/* ------------------------------------------------------------------ */

/*
 * out[0]/out[1] = the two arguments to rewrite, out[2] = hit flag.  The
 * flag matters: regs->regs[5]/[6] may carry garbage in their upper 32 bits
 * (the callee only ever looks at the low half), so we must not write them
 * back unless we actually have something to say.
 */
static void susfs_kstat_apply_maps(struct st_susfs_sus_kstat_hlist *entry,
				   void *arg)
{
	unsigned long *out = arg;

	out[0] = entry->info.spoofed_dev; /* dev column */
	out[1] = entry->info.spoofed_ino; /* ino column */
	out[2] = 1;
}

static int susfs_show_vma_header_prefix_pre(struct kprobe *p,
					    struct pt_regs *regs)
{
	unsigned long out[3];

	if (!atomic_read(&susfs_kstat_entries))
		return 0;

	/*
	 * show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino)
	 * -> x5 = dev, x6 = ino.
	 */
	out[2] = 0;
	susfs_kstat_walk(regs->regs[6], (u32)regs->regs[5],
			 susfs_kstat_apply_maps, out);
	if (!out[2])
		return 0;

	regs->regs[5] = out[0];
	regs->regs[6] = out[1];
	return 0;
}

/* ------------------------------------------------------------------ */
/* 3. statfs / fstatfs                                                 */
/* ------------------------------------------------------------------ */

struct susfs_statfs_data {
	struct kstatfs *buf;
	unsigned long ino;
	unsigned long dev;
};

static void susfs_kstat_apply_statfs(struct st_susfs_sus_kstat_hlist *entry,
				     void *arg)
{
	memcpy(arg, &entry->spoofed_kstatfs, sizeof(struct kstatfs));
}

static int susfs_vfs_statfs_entry(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct susfs_statfs_data *data = (void *)ri->data;
	const struct path *path;
	struct inode *inode;

	if (!atomic_read(&susfs_kstat_entries))
		return 1;

	path = (const struct path *)regs->regs[0];
	if (!path || !path->dentry)
		return 1;

	inode = d_backing_inode(path->dentry);
	if (!susfs_kstat_inode_marked(inode))
		return 1;

	data->buf = (struct kstatfs *)regs->regs[1];
	if (!data->buf)
		return 1;

	data->ino = inode->i_ino;
	data->dev = (unsigned long)inode->i_sb->s_dev;
	return 0;
}

static int susfs_vfs_statfs_ret(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct susfs_statfs_data *data = (void *)ri->data;

	if ((long)regs->regs[0])
		return 0;

	susfs_kstat_walk(data->ino, data->dev, susfs_kstat_apply_statfs,
			 data->buf);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 4. inotify fdinfo                                                   */
/* ------------------------------------------------------------------ */

static void susfs_kstat_apply_inotify(struct st_susfs_sus_kstat_hlist *entry,
				      void *arg)
{
	unsigned long *out = arg;

	out[0] = entry->info.spoofed_ino;
	out[1] = entry->info.spoofed_dev;
	out[2] = 1;
}

static int susfs_seq_printf_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long out[3];

	if (!atomic_read(&susfs_kstat_entries))
		return 0;

	/* Only the call site inside inotify_fdinfo(). */
	if (regs->regs[30] != susfs_inotify_seq_lr)
		return 0;

	/*
	 * seq_printf(m, "ino:%lx sdev:%x", ino, sdev)
	 * -> x3 = ino, x4 = sdev.
	 */
	out[2] = 0;
	susfs_kstat_walk(regs->regs[3], (u32)regs->regs[4],
			 susfs_kstat_apply_inotify, out);
	if (!out[2])
		return 0;

	regs->regs[3] = out[0];
	regs->regs[4] = out[1];
	return 0;
}

/*
 * Find the return address of the first `bl <target>` inside
 * [@start, @start + @size).  This is how we pin the seq_printf() call inside
 * inotify_fdinfo() to one exact instruction instead of an address window.
 */
static unsigned long susfs_find_first_bl(unsigned long start, unsigned long size,
					 unsigned long target)
{
	const u32 *p = (const u32 *)start;
	unsigned long best = 0;
	unsigned long i;

	for (i = 0; i + 4 <= size; i += 4) {
		u32 insn = READ_ONCE(p[i / 4]);
		s32 imm;
		unsigned long pc, dst;

		if ((insn & 0xFC000000u) != 0x94000000u)
			continue;

		imm = (s32)(insn << 6) >> 4; /* sign-extend imm26, then << 2 */
		pc = start + i;
		dst = pc + (unsigned long)(long)imm;
		if (dst != target)
			continue;

		/* Keep the lowest hit: inotify_fdinfo's ino/sdev print is the
		 * first seq_printf() in the function. */
		if (!best || pc + 4 < best)
			best = pc + 4;
	}
	return best;
}

/* ------------------------------------------------------------------ */
/* registration                                                        */
/* ------------------------------------------------------------------ */

static struct kretprobe susfs_getattr_krp;
static struct kretprobe susfs_statfs_krp;
static struct kprobe susfs_vma_kp;
static struct kprobe susfs_seq_printf_kp;

static void susfs_kstat_register_hooks(void)
{
	unsigned long inotify_addr, seq_printf_addr;
	int err;

	mutex_lock(&susfs_kstat_reg_lock);
	if (READ_ONCE(susfs_kstat_hooks_on)) {
		mutex_unlock(&susfs_kstat_reg_lock);
		return;
	}
	/*
	 * Mark as attempted up front: a failed registration will not start
	 * working later, and re-registering an already armed probe fails with
	 * -EINVAL, which would spam the log on every add.  Each probe below is
	 * independent, so one failure only costs that one spoof point.
	 */
	WRITE_ONCE(susfs_kstat_hooks_on, true);

	/*
	 * maxactive: vfs_getattr_nosec()/vfs_statfs() are hot and can nest
	 * (a filesystem's ->getattr may stat something else).  The default of
	 * 10 instances would silently drop spoofs; 128 costs a few KB.
	 * The helpers memset() the struct, so maxactive must be set before the
	 * call -- they preserve it.
	 */
	susfs_getattr_krp.maxactive = 128;
	err = susfs_register_kretprobe(&susfs_getattr_krp, "vfs_getattr_nosec",
				       susfs_vfs_getattr_entry,
				       susfs_vfs_getattr_ret,
				       sizeof(struct susfs_getattr_data));
	if (err) {
		SUSFS_LOGE("failed to hook vfs_getattr_nosec: %d\n", err);
		/*
		 * The core spoof point is gone: everything else in this file is
		 * an extra (mtime/ino in listings, statfs).  Stop advertising
		 * SUS_KSTAT instead of pretending the feature works.
		 */
		WRITE_ONCE(susfs_kstat_core_ok, false);
	}

	susfs_statfs_krp.maxactive = 64;
	err = susfs_register_kretprobe(&susfs_statfs_krp, "vfs_statfs",
				       susfs_vfs_statfs_entry,
				       susfs_vfs_statfs_ret,
				       sizeof(struct susfs_statfs_data));
	if (err)
		SUSFS_LOGE("failed to hook vfs_statfs: %d\n", err);

	err = susfs_register_kprobe(&susfs_vma_kp, "show_vma_header_prefix",
				    susfs_show_vma_header_prefix_pre, NULL);
	if (err)
		SUSFS_LOGE("failed to hook show_vma_header_prefix: %d\n", err);

	seq_printf_addr = susfs_lookup_symbol("seq_printf");
	inotify_addr = susfs_lookup_symbol("inotify_fdinfo");
	if (!seq_printf_addr || !inotify_addr) {
		/* Not fatal: the other three spoof points still work. */
		SUSFS_LOGE("seq_printf/inotify_fdinfo not resolved (%lx/%lx), inotify spoof disabled\n",
			   seq_printf_addr, inotify_addr);
	} else {
		susfs_inotify_seq_lr = susfs_find_first_bl(inotify_addr,
							  SUSFS_INOTIFY_SCAN_SIZE,
							  seq_printf_addr);
		if (!susfs_inotify_seq_lr) {
			SUSFS_LOGE("no bl seq_printf inside inotify_fdinfo, inotify spoof disabled\n");
		} else {
			err = susfs_register_kprobe(&susfs_seq_printf_kp,
						    "seq_printf",
						    susfs_seq_printf_pre, NULL);
			if (err)
				SUSFS_LOGE("failed to hook seq_printf: %d\n", err);
			else
				SUSFS_LOGI("inotify spoof armed at lr=0x%lx\n",
					   susfs_inotify_seq_lr);
		}
	}

	SUSFS_LOGI("SUS_KSTAT hooks registered\n");
	mutex_unlock(&susfs_kstat_reg_lock);
}

bool susfs_kstat_available(void)
{
	return READ_ONCE(susfs_kstat_core_ok);
}

/*
 * Trial-register the core probe and remove it again.  SUS_KSTAT installs its
 * hooks lazily on the first add (vfs_getattr_nosec() runs on every stat()
 * call, so an idle module must not leave a trap there), but the manager asks
 * for enabled_features at startup - before any rule exists.  A NULL-handler
 * trial proves the symbol resolves and is probeable right now without
 * leaving anything armed; registration does not depend on the handlers.
 */
static int susfs_kstat_trial(void)
{
	struct kretprobe trial;
	int ret;

	memset(&trial, 0, sizeof(trial));
	trial.maxactive = 8;
	ret = susfs_register_kretprobe(&trial, "vfs_getattr_nosec", NULL, NULL,
				       0);
	if (ret) {
		SUSFS_LOGE("vfs_getattr_nosec probe unavailable (%d), sus_kstat stays off\n",
			   ret);
		return ret;
	}
	unregister_kretprobe(&trial);
	return 0;
}

void susfs_kstat_init(void)
{
	if (susfs_kstat_trial())
		return;

	WRITE_ONCE(susfs_kstat_core_ok, true);
	SUSFS_LOGI("SUS_KSTAT ready (hooks registered on first add_sus_kstat)\n");
}

#endif /* CONFIG_KSU_SUSFS_SUS_KSTAT */
