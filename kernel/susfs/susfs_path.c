// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_path.c - SuSFS SUS_PATH (path hiding), LKM edition.
 *
 * Upstream SuSFS is a source patch.  Hiding a path there is a two part
 * mechanism:
 *
 *   1. `susfs_add_sus_path()` resolves the path once and marks the inode
 *      with AS_FLAGS_SUS_PATH in address_space.flags (no inode hash table,
 *      no per-lookup string compare).
 *   2. A handful of call sites inside fs/namei.c, fs/stat.c, fs/open.c and
 *      fs/readdir.c call `susfs_is_inode_sus_path()` and turn the answer
 *      into "-ENOENT" (or, for readdir, into "skip this entry").
 *
 * We load a stock, locked boot image, so part 1 is unchanged but part 2 has
 * to become a kprobe per call site.  The interesting consequence is that
 * the *decision* is a single bit test on the inode: it is cheap, it is
 * correct for every path that resolves to that inode (hard links, renamed
 * parents, /proc/self/fd/N, bind mounts of the same file, ...), and it does
 * not care about path spelling.
 *
 * Which call sites are covered, and why
 * -------------------------------------
 *   may_open()                 open()/openat()/openat2()/creat()/O_TRUNC
 *   vfs_getattr_nosec()        stat()/lstat()/fstat()/statx()   (kretprobe)
 *   do_faccessat()+0x108       access()/faccessat()
 *   may_delete()               unlink()/rmdir()/rename()  (both victims)
 *   vfs_mkdir/mknod/symlink()  mkdir()/mknod()/symlink()
 *   vfs_link()                 link()
 *   notify_change()            chmod()/chown()/truncate()/ftruncate()/utimes()
 *   filldir64/filldir/         readdir()/getdents()   (entry removal)
 *     compat_filldir()
 *
 * Notes on the individual choices:
 *
 *  - `may_open` is the single gate every "open an existing inode" path
 *    funnels through (do_last() -> may_open()), and it is an ordinary
 *    function here (not inlined), so one probe covers open/openat/openat2/
 *    creat and the O_TRUNC re-open done by open(..., O_TRUNC).
 *
 *  - stat is *not* done by patching generic_fillattr(): that function is
 *    inlined into vfs_getattr_nosec() in this kernel and has no symbol of
 *    its own.  A kretprobe on vfs_getattr_nosec() is equivalent (and is the
 *    same trick susfs_kstat.c uses for its own reasons).
 *
 *  - access() cannot be done at a function entry: do_faccessat() first
 *    builds the path (which we must not skip) and only then asks
 *    inode_permission().  The probe therefore sits *on the `bl
 *    inode_permission` instruction* and skips just that call, leaving the
 *    already-built `struct path` to be released by the normal exit path.
 *    The offset is not hardcoded: it is found by scanning do_faccessat()
 *    for the `bl` whose target is inode_permission(), so a rebuild of the
 *    kernel with a different layout keeps working (see
 *    susfs_path_arm_faccessat()).
 *
 *  - Deletion and creation are covered by may_delete() (called by
 *    vfs_unlink(), vfs_rmdir() and twice by vfs_rename()) plus the
 *    vfs_* creation helpers.  do_truncate() is deliberately *not* hooked:
 *    it always calls notify_change(), so the truncate family is already
 *    covered there and a second probe would only duplicate work.
 *
 *  - readdir is covered by the three dir_context actors.  They are reached
 *    through a function pointer, so with kCFI kallsyms only carries
 *    `filldir64$<hash>` and the address BakaSU's resolver hands back is the
 *    `.cfi_jt` stub; both are handled (variant lookup + stub unwrap).
 *    Returning 0 with pc = x30 makes dir_emit() see "entry consumed" and
 *    keep enumerating, which is exactly "the entry does not exist".
 *
 * Documented behavioural differences from upstream (deliberate, see
 * docs/susfs-lkm-feasibility.md)
 * -------------------------------------------------------------------
 *  a) open(O_CREAT) on a hidden path fails with -ENOENT, but upstream
 *     additionally installs a decoy dentry so that the caller cannot tell
 *     the path was hidden.  Reproducing that needs `nd->flags` handling,
 *     RCU-walk retry semantics and d_invalidate() ordering inside
 *     link_path_walk()/lookup_open(), none of which can be reproduced from
 *     a kprobe safely.  We return -ENOENT, which is what a missing path
 *     looks like anyway.
 *  b) Creating a *new* name inside a hidden directory: the filesystem's
 *     ->create() callback runs (lookup_open() calls it directly, not
 *     through vfs_create()) and may_open() then returns -ENOENT, so an
 *     empty file can be left behind.  Upstream's decoy dentry prevents
 *     this.  Only reachable by a process that already knows the hidden
 *     directory name.
 *  c) readlink() is not covered (upstream hides it through the same inode
 *     check, but there is no single non-inlined function to hook that does
 *     not also affect unrelated callers).
 *  d) readdir matching compares (ino, basename, d_type) but not st_dev,
 *     because filldir64() has no directory context (dir_context carries no
 *     file/dentry).  The residual risk is hiding an identically named,
 *     identically numbered, same-type entry on another filesystem, which is
 *     vanishingly unlikely; a false negative is not possible.
 *  e) statfs is not handled here at all: it belongs to SUS_MOUNT.
 *
 * Locking
 * -------
 * Readers (kprobes) take susfs_path_lock and walk the list; writers take
 * susfs_path_mutex (which may sleep, because resolving a path calls
 * kern_path()) and take susfs_path_lock only around the list link
 * manipulation.  Entries are never freed: a kprobe may be walking the list
 * while the writer would otherwise kfree() a node, and an RCU grace period
 * is not available to a kprobe that runs with interrupts masked.
 *
 * The hot path (may_open / stat / access) never touches the list at all -
 * it only does test_bit() on the inode - so the list lock is not on the
 * critical path of any syscall.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_types.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>

#include "susfs_internal.h"
#include "ksu.h"

/*
 * How far into do_faccessat() we are willing to look for the
 * `bl inode_permission`.  The function is a bit over 0x180 bytes in this
 * kernel and the call sits at +0x108; 0x400 leaves room for a rebuild
 * without turning the scan into a search of the whole text segment.
 */
#define SUSFS_PATH_FACCESSAT_SCAN 0x400

struct susfs_path_node {
	struct list_head list;
	char pathname[SUSFS_MAX_LEN_PATHNAME];
	char name[SUSFS_MAX_LEN_PATHNAME];
	u16 name_len;
	bool is_loop;
	unsigned long ino;
	unsigned int d_type;
	/*
	 * Owner of the marked inode, captured at resolve time.  Upstream
	 * feeds the inode to susfs_is_inode_sus_path() from both sides
	 * (open/stat directly, readdir after an ilookup), so both sides see
	 * the same "current uid == inode owner" escape hatch.  We cannot
	 * ilookup() from a kprobe, so readdir matches by (ino, name, type)
	 * and needs the uid cached here to stay equivalent.
	 */
	uid_t target_uid;
};

/* kretprobe payload: did the inode we are about to stat turn out hidden? */
struct susfs_path_retdata {
	bool hidden;
};

struct susfs_path_hook {
	const char *name;
	kprobe_pre_handler_t pre;
	bool core;
	struct kprobe kp;
	bool armed;
};

static LIST_HEAD(susfs_path_list);
static DEFINE_MUTEX(susfs_path_mutex);
static DEFINE_SPINLOCK(susfs_path_lock);
static atomic_t susfs_path_entries = ATOMIC_INIT(0);

static bool susfs_path_core_ok;
static bool susfs_path_armed;
static int susfs_path_arm_err;
static DEFINE_MUTEX(susfs_path_arm_mutex);

static struct kprobe susfs_path_kp_faccessat;
static struct kretprobe susfs_path_krp_getattr;

static int susfs_path_pre_may_open(struct kprobe *kp, struct pt_regs *regs);
static int susfs_path_pre_may_delete(struct kprobe *kp, struct pt_regs *regs);
static int susfs_path_pre_dir_inode(struct kprobe *kp, struct pt_regs *regs);
static int susfs_path_pre_vfs_link(struct kprobe *kp, struct pt_regs *regs);
static int susfs_path_pre_notify_change(struct kprobe *kp,
					struct pt_regs *regs);
static int susfs_path_pre_filldir(struct kprobe *kp, struct pt_regs *regs);
static int susfs_path_pre_faccessat(struct kprobe *kp, struct pt_regs *regs);

/*
 * Ordered by importance.  `may_open` plus the vfs_getattr_nosec kretprobe
 * registered further down are the core pair: they are what userspace
 * actually observes (open and stat), and they decide whether the feature is
 * advertised at all.  Everything in this table after `may_open`, and the
 * do_faccessat probe, is hardening - if one of those cannot be installed the
 * feature still works for open/stat, so the failure is logged but does not
 * disable SUS_PATH.
 *
 * Every entry is registered on the *real* function body, never on a kCFI
 * jump-table stub: a stub is a single `b body` reached only by indirect
 * callers, so a probe there would miss the direct calls inside the kernel.
 * Probing the body entry instead catches both (the stub tail-branches into
 * it).  susfs_unwrap_jump_table() returns the address unchanged when it is
 * not a stub, so this is safe for plain functions too.
 */
static struct susfs_path_hook susfs_path_hooks[] = {
	{ .name = "may_open", .pre = susfs_path_pre_may_open, .core = true },
	{ .name = "may_delete", .pre = susfs_path_pre_may_delete },
	{ .name = "vfs_mkdir", .pre = susfs_path_pre_dir_inode },
	{ .name = "vfs_mknod", .pre = susfs_path_pre_dir_inode },
	{ .name = "vfs_symlink", .pre = susfs_path_pre_dir_inode },
	{ .name = "vfs_link", .pre = susfs_path_pre_vfs_link },
	{ .name = "notify_change", .pre = susfs_path_pre_notify_change },
	{ .name = "filldir64", .pre = susfs_path_pre_filldir },
	{ .name = "filldir", .pre = susfs_path_pre_filldir },
	{ .name = "compat_filldir", .pre = susfs_path_pre_filldir },
};

/* ------------------------------------------------------------------ */
/* registry                                                            */
/* ------------------------------------------------------------------ */

static void susfs_path_set_basename(struct susfs_path_node *node)
{
	char *p, *base;
	size_t len;

	len = strnlen(node->pathname, SUSFS_MAX_LEN_PATHNAME);
	/* "/a/b/" and "/a/b" are the same path; keep the root's slash. */
	while (len > 1 && node->pathname[len - 1] == '/')
		len--;
	node->pathname[len] = '\0';

	base = node->pathname;
	for (p = node->pathname; *p; p++) {
		if (*p == '/')
			base = p + 1;
	}

	len = strlen(base);
	if (len >= SUSFS_MAX_LEN_PATHNAME)
		len = SUSFS_MAX_LEN_PATHNAME - 1;
	memcpy(node->name, base, len);
	node->name[len] = '\0';
	node->name_len = (u16)len;
}

/*
 * Resolve the path and mark the inode.  Called from process context only
 * (the add syscall and the extra-works worker), never from a kprobe.
 *
 * Returns 0 on success.  A failure here is not fatal for a loop entry: the
 * path may simply not exist yet, and the periodic re-resolution picks it up
 * once it appears.
 */
static int susfs_path_resolve(struct susfs_path_node *node)
{
	struct path path;
	struct inode *inode;
	int err;

	err = kern_path(node->pathname, LOOKUP_FOLLOW, &path);
	if (err)
		return err;

	inode = d_backing_inode(path.dentry);
	if (!inode || !inode->i_mapping) {
		path_put(&path);
		return -EINVAL;
	}

	set_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags);
	WRITE_ONCE(node->ino, inode->i_ino);
	WRITE_ONCE(node->d_type, (inode->i_mode & S_IFMT) >> 12);
	WRITE_ONCE(node->target_uid, inode->i_uid.val);

	path_put(&path);
	return 0;
}

/*
 * The single decision the hot path makes.  Order matters: the
 * "unmounted app" test is a thread flag plus a uid compare and rejects
 * essentially every caller, so the (still cheap) bit test runs only for
 * processes that SuSFS already considers hidden from.
 *
 * shell (2000) and root (0) never pass susfs_is_current_proc_umounted_app(),
 * so they always see the real filesystem - that is upstream behaviour and
 * it is also what makes the manager usable.
 *
 * `current_uid() != inode->i_uid` is upstream's is_i_uid_not_allowed()
 * verbatim: a process never hides a file from itself.  That matters for the
 * common case of an app hiding its own files under
 * /sdcard/Android/data/<pkg>, and for /sdcard as a whole, where the path is
 * owned by the MediaProvider uid and stays visible to that provider.
 * susfs_path_match_dirent() applies the same test from the cached
 * target_uid, so `ls` and `cat` never disagree.
 */
static bool susfs_path_inode_hidden(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	if (!test_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags))
		return false;
	if (likely(current_uid().val == inode->i_uid.val))
		return false;

	SUSFS_LOGI("hiding ino '%lu'\n", inode->i_ino);
	return true;
}

static inline bool susfs_path_active(void)
{
	return READ_ONCE(susfs_path_core_ok) &&
	       atomic_read(&susfs_path_entries) > 0;
}

static inline bool susfs_path_should_hide(struct inode *inode)
{
	if (!susfs_path_active())
		return false;
	if (!susfs_is_current_proc_umounted_app())
		return false;
	return susfs_path_inode_hidden(inode);
}

/*
 * readdir side: filldir64() only carries the dirent, so the match is
 * (ino, basename, d_type).  DT_UNKNOWN means "the filesystem did not tell
 * us", in which case the type is not part of the comparison.
 */
static bool susfs_path_match_dirent(const char *name, int namlen, u64 ino,
				    u32 d_type)
{
	struct susfs_path_node *node;
	bool hit = false;

	if (!susfs_path_active())
		return false;
	if (!susfs_is_current_proc_umounted_app())
		return false;
	if (!name || namlen <= 0 || !ino)
		return false;

	spin_lock(&susfs_path_lock);
	list_for_each_entry (node, &susfs_path_list, list) {
		if (!node->ino || node->ino != ino)
			continue;
		if (node->name_len != (u16)namlen)
			continue;
		if (memcmp(node->name, name, namlen))
			continue;
		if (d_type != DT_UNKNOWN && node->d_type != d_type)
			continue;
		/* Upstream's is_i_uid_not_allowed(): never hide from the owner. */
		if (likely(current_uid().val == node->target_uid))
			continue;
		hit = true;
		break;
	}
	spin_unlock(&susfs_path_lock);

	if (hit) {
		SUSFS_LOGI("hiding dirent '%.*s' ino '%llu'\n", namlen, name,
			   (unsigned long long)ino);
	}
	return hit;
}

/* ------------------------------------------------------------------ */
/* deny helpers                                                        */
/* ------------------------------------------------------------------ */

/*
 * Function-entry probe: x30 still holds the caller's return address (the
 * callee prologue has not run yet), so jumping there returns -ENOENT from
 * the hooked function without executing any of it.  Callee-saved registers
 * are untouched, which is what the caller expects from a function that
 * returns early.
 */
static int susfs_path_deny(struct pt_regs *regs)
{
	regs->regs[0] = (unsigned long)(long)-ENOENT;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * Instruction-level probe: the probe sits *on* a `bl`, so x30 is still the
 * return address of the function's own caller and must not be used.
 * Resuming at addr + 4 skips exactly that one call.
 */
static int susfs_path_deny_insn(struct kprobe *kp, struct pt_regs *regs)
{
	regs->regs[0] = (unsigned long)(long)-ENOENT;
	regs->pc = (unsigned long)kp->addr + 4;
	return 1;
}

/* ------------------------------------------------------------------ */
/* kprobe handlers                                                     */
/* ------------------------------------------------------------------ */

static int susfs_path_pre_may_open(struct kprobe *kp, struct pt_regs *regs)
{
	struct path *path = (struct path *)regs->regs[0];

	if (!path || !path->dentry)
		return 0;
	if (!susfs_path_should_hide(d_backing_inode(path->dentry)))
		return 0;
	return susfs_path_deny(regs);
}

static int susfs_path_pre_may_delete(struct kprobe *kp, struct pt_regs *regs)
{
	struct inode *dir = (struct inode *)regs->regs[0];
	struct dentry *victim = (struct dentry *)regs->regs[1];

	/* may_delete() is called with a possibly-erroneous dentry first. */
	if (susfs_path_should_hide(dir))
		return susfs_path_deny(regs);
	if (victim && !IS_ERR(victim) &&
	    susfs_path_should_hide(d_backing_inode(victim)))
		return susfs_path_deny(regs);
	return 0;
}

/* vfs_mkdir()/vfs_mknod()/vfs_symlink(): x0 is the parent inode. */
static int susfs_path_pre_dir_inode(struct kprobe *kp, struct pt_regs *regs)
{
	if (!susfs_path_should_hide((struct inode *)regs->regs[0]))
		return 0;
	return susfs_path_deny(regs);
}

/* vfs_link(old_dentry, dir, new_dentry, delegated_inode) */
static int susfs_path_pre_vfs_link(struct kprobe *kp, struct pt_regs *regs)
{
	struct dentry *old = (struct dentry *)regs->regs[0];
	struct inode *dir = (struct inode *)regs->regs[1];

	if (old && !IS_ERR(old) &&
	    susfs_path_should_hide(d_backing_inode(old)))
		return susfs_path_deny(regs);
	if (susfs_path_should_hide(dir))
		return susfs_path_deny(regs);
	return 0;
}

/* notify_change(dentry, iattr, delegated_inode) - also covers truncate. */
static int susfs_path_pre_notify_change(struct kprobe *kp,
					struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];

	if (!dentry || IS_ERR(dentry))
		return 0;
	if (!susfs_path_should_hide(d_backing_inode(dentry)))
		return 0;
	return susfs_path_deny(regs);
}

/*
 * filldir64(ctx, name, namlen, offset, ino, d_type) and its 32-bit
 * counterparts share the same argument layout.
 *
 * Returning 0 to the caller is what dir_emit() treats as "entry consumed,
 * keep going".  Returning -EINVAL instead would make the filesystem abort
 * the whole enumeration, which is not what we want.
 */
static int susfs_path_pre_filldir(struct kprobe *kp, struct pt_regs *regs)
{
	if (!susfs_path_match_dirent((const char *)regs->regs[1],
				     (int)regs->regs[2], regs->regs[4],
				     (u32)regs->regs[5]))
		return 0;

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/* Probe sits on the `bl inode_permission` inside do_faccessat(). */
static int susfs_path_pre_faccessat(struct kprobe *kp, struct pt_regs *regs)
{
	if (!susfs_path_should_hide((struct inode *)regs->regs[0]))
		return 0;
	return susfs_path_deny_insn(kp, regs);
}

/*
 * vfs_getattr_nosec() returns int, so the decision has to be made on entry
 * (where the path is still available) and applied on return.
 */
static int susfs_path_getattr_entry(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct susfs_path_retdata *data = (struct susfs_path_retdata *)ri->data;
	struct path *path = (struct path *)regs->regs[0];

	data->hidden = false;
	if (!path || !path->dentry)
		return 1;
	if (!susfs_path_should_hide(d_backing_inode(path->dentry)))
		return 1;

	data->hidden = true;
	return 0;
}

static int susfs_path_getattr_ret(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct susfs_path_retdata *data = (struct susfs_path_retdata *)ri->data;

	if (data->hidden)
		regs->regs[0] = (unsigned long)(long)-ENOENT;
	return 0;
}

/* ------------------------------------------------------------------ */
/* arming                                                             */
/* ------------------------------------------------------------------ */

/*
 * Register a probe at an address we computed ourselves (after unwrapping a
 * kCFI jump-table stub).  susfs_register_kprobe() cannot be used for those:
 * it registers on the address the resolver returns, which for an indirect
 * call target is the stub, and a probe on the stub only sees indirect
 * callers.  susfs_register_kprobe_at() in susfs_probe.c does that part.
 */

/*
 * Same idea for kretprobes.  susfs_register_kretprobe() resolves by name
 * only, which lands on the kCFI stub; the return trampoline still fires
 * (the stub tail-branches and keeps our replaced LR), but probing the body
 * is both cheaper and independent of that detail.
 */
static int susfs_path_register_kretprobe_at(struct kretprobe *krp,
					    const char *name,
					    kretprobe_handler_t entry,
					    kretprobe_handler_t ret_handler,
					    int data_size, int maxactive)
{
	unsigned long addr = susfs_lookup_symbol(name);
	int ret;

	if (!addr)
		return -ENOENT;
	addr = susfs_unwrap_jump_table(addr);
	if (!addr)
		return -ENOENT;

	memset(krp, 0, sizeof(*krp));
	krp->kp.addr = (kprobe_opcode_t *)addr;
	krp->entry_handler = entry;
	krp->handler = ret_handler;
	krp->data_size = data_size;
	krp->maxactive = maxactive;

	ret = register_kretprobe(krp);
	if (ret)
		memset(krp, 0, sizeof(*krp));
	return ret;
}

static int susfs_path_arm_faccessat(void)
{
	unsigned long func = susfs_lookup_symbol("do_faccessat");
	unsigned long perm = susfs_lookup_symbol("inode_permission");
	unsigned long after_bl;
	int ret;

	if (!func || !perm)
		return -ENOENT;

	/* Both sides must be the bodies, not the .cfi_jt stubs. */
	func = susfs_unwrap_jump_table(func);
	perm = susfs_unwrap_jump_table(perm);
	if (!func || !perm)
		return -ENOENT;

	after_bl = susfs_find_bl_to(func, SUSFS_PATH_FACCESSAT_SCAN, perm);
	if (!after_bl)
		return -ENOENT;

	memset(&susfs_path_kp_faccessat, 0, sizeof(susfs_path_kp_faccessat));
	susfs_path_kp_faccessat.addr = (kprobe_opcode_t *)(after_bl - 4);
	susfs_path_kp_faccessat.pre_handler = susfs_path_pre_faccessat;

	ret = register_kprobe(&susfs_path_kp_faccessat);
	if (ret)
		memset(&susfs_path_kp_faccessat, 0,
		       sizeof(susfs_path_kp_faccessat));
	return ret;
}

static void susfs_path_disarm_all(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(susfs_path_hooks); i++) {
		struct susfs_path_hook *hook = &susfs_path_hooks[i];

		if (!hook->armed)
			continue;
		unregister_kprobe(&hook->kp);
		hook->armed = false;
	}

	if (susfs_path_krp_getattr.kp.addr) {
		unregister_kretprobe(&susfs_path_krp_getattr);
		memset(&susfs_path_krp_getattr, 0,
		       sizeof(susfs_path_krp_getattr));
	}

	if (susfs_path_kp_faccessat.addr) {
		unregister_kprobe(&susfs_path_kp_faccessat);
		memset(&susfs_path_kp_faccessat, 0,
		       sizeof(susfs_path_kp_faccessat));
	}
}

/*
 * Installing the probes is deferred until the first path is added: an
 * armed-but-unused probe still costs a breakpoint trap on every open(),
 * stat(), readdir() entry and chmod() in the system, and most devices never
 * add a single sus path.
 */
static int susfs_path_arm(void)
{
	struct susfs_path_hook *hook;
	int i, ret = 0;

	if (READ_ONCE(susfs_path_armed))
		return READ_ONCE(susfs_path_arm_err);
	if (!READ_ONCE(susfs_path_core_ok))
		return -ENODEV;

	mutex_lock(&susfs_path_arm_mutex);
	if (susfs_path_armed)
		goto out;

	for (i = 0; i < ARRAY_SIZE(susfs_path_hooks); i++) {
		hook = &susfs_path_hooks[i];

		ret = susfs_register_kprobe_at(&hook->kp, hook->name, hook->pre);
		if (ret) {
			SUSFS_LOGE("failed to install '%s' probe, err: %d\n",
				   hook->name, ret);
			if (hook->core) {
				susfs_path_core_ok = false;
				goto fail;
			}
			ret = 0;
			continue;
		}
		hook->armed = true;
	}

	/* stat(): the return value has to be rewritten after the fact. */
	ret = susfs_path_register_kretprobe_at(
		&susfs_path_krp_getattr, "vfs_getattr_nosec",
		susfs_path_getattr_entry, susfs_path_getattr_ret,
		sizeof(struct susfs_path_retdata), 128);
	if (ret) {
		SUSFS_LOGE("failed to install 'vfs_getattr_nosec' probe, "
			   "err: %d\n",
			   ret);
		memset(&susfs_path_krp_getattr, 0,
		       sizeof(susfs_path_krp_getattr));
		susfs_path_core_ok = false;
		goto fail;
	}

	/* access(): optional hardening, same as the other non-core hooks. */
	ret = susfs_path_arm_faccessat();
	if (ret) {
		SUSFS_LOGE("failed to install 'do_faccessat' probe, err: %d\n",
			   ret);
		ret = 0;
	}

	susfs_path_arm_err = 0;
	WRITE_ONCE(susfs_path_armed, true);
	SUSFS_LOGI("sus_path hooks armed\n");
	goto out;

fail:
	susfs_path_disarm_all();
	susfs_path_arm_err = ret;
out:
	mutex_unlock(&susfs_path_arm_mutex);
	return ret;
}

/* ------------------------------------------------------------------ */
/* userspace commands                                                  */
/* ------------------------------------------------------------------ */

/*
 * `is_loop` entries name a path that may not exist yet (the classic use is
 * a directory the app creates later), so a failed resolution is not an
 * error there - the extra-works worker retries it whenever SuSFS umounts a
 * package.
 */
static void susfs_path_add(void __user **user_info, bool is_loop)
{
	struct st_susfs_sus_path info;
	struct susfs_path_node *node, *existing;
	int err = 0;

	if (copy_from_user(&info,
			   (struct st_susfs_sus_path __user *)*user_info,
			   sizeof(info))) {
		err = -EFAULT;
		goto out;
	}
	if (!info.target_pathname[0] ||
	    info.target_pathname[SUSFS_MAX_LEN_PATHNAME - 1]) {
		err = -EINVAL;
		goto out;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		err = -ENOMEM;
		goto out;
	}
	strscpy(node->pathname, info.target_pathname, sizeof(node->pathname));
	node->is_loop = is_loop;
	susfs_path_set_basename(node);

	err = susfs_path_arm();
	if (err)
		goto out_free;

	/* Mark the inode before the entry becomes visible to the hot path. */
	if (susfs_path_resolve(node) && !is_loop) {
		err = -ENOENT;
		goto out_free;
	}

	mutex_lock(&susfs_path_mutex);
	list_for_each_entry (existing, &susfs_path_list, list) {
		if (strcmp(existing->pathname, node->pathname))
			continue;

		/*
		 * Same path added twice.  Refresh in place instead of
		 * replacing the node: readers walk this list without taking
		 * the mutex and entries are never freed.
		 */
		if (node->ino) {
			WRITE_ONCE(existing->ino, node->ino);
			WRITE_ONCE(existing->d_type, node->d_type);
			WRITE_ONCE(existing->target_uid, node->target_uid);
		}
		if (!is_loop)
			existing->is_loop = false;
		mutex_unlock(&susfs_path_mutex);
		kfree(node);
		SUSFS_LOGI("sus_path '%s' refreshed, ino: %lu\n",
			   existing->pathname, existing->ino);
		goto out;
	}

	spin_lock(&susfs_path_lock);
	list_add_tail(&node->list, &susfs_path_list);
	spin_unlock(&susfs_path_lock);
	atomic_inc(&susfs_path_entries);
	mutex_unlock(&susfs_path_mutex);

	SUSFS_LOGI("sus_path '%s' added, ino: %lu, loop: %d\n", node->pathname,
		   node->ino, is_loop);
	goto out;

out_free:
	kfree(node);
out:
	if (copy_to_user(
		    &((struct st_susfs_sus_path __user *)*user_info)->err, &err,
		    sizeof(err)))
		err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_PATH%s -> ret: %d\n",
		   is_loop ? "_LOOP" : "", err);
}

void susfs_add_sus_path(void __user **user_info)
{
	susfs_path_add(user_info, false);
}

void susfs_add_sus_path_loop(void __user **user_info)
{
	susfs_path_add(user_info, true);
}

/*
 * Periodic re-resolution of the loop entries, run from susfs_extra_works
 * (scheduled by the kernel_umount feature handler).  Paths that appeared
 * since the last run get their inode marked here, which is what makes
 * "hide the directory the app is about to create" work.
 *
 * ksu_cred is the init credentials captured at module load; resolving with
 * them means the paths are marked regardless of which process happened to
 * trigger the umount.
 */
void susfs_path_loop_run(void)
{
	struct susfs_path_node *node;
	const struct cred *saved;
	int refreshed = 0, failed = 0;

	if (!susfs_path_active())
		return;
	if (!ksu_cred)
		return;

	mutex_lock(&susfs_path_mutex);
	saved = override_creds(ksu_cred);
	list_for_each_entry (node, &susfs_path_list, list) {
		if (!node->is_loop)
			continue;
		if (susfs_path_resolve(node))
			failed++;
		else
			refreshed++;
	}
	revert_creds(saved);
	mutex_unlock(&susfs_path_mutex);

	if (refreshed || failed)
		SUSFS_LOGI("sus_path loop: refreshed %d, failed %d\n",
			   refreshed, failed);
}

bool susfs_path_available(void)
{
	return READ_ONCE(susfs_path_core_ok);
}

/* ------------------------------------------------------------------ */
/* init                                                               */
/* ------------------------------------------------------------------ */

/*
 * Honest availability check.  A feature whose core hooks cannot be
 * installed must not be advertised to the manager, so the two probes that
 * the open/stat paths depend on are installed and immediately removed
 * here.  The real arming still happens lazily on the first add, and if that
 * fails the same flag is cleared.
 */
void susfs_path_init(void)
{
	struct kprobe kp;
	unsigned long addr;
	int ret;

	WRITE_ONCE(susfs_path_core_ok, false);

	addr = susfs_lookup_symbol("may_open");
	if (!addr)
		goto out;
	addr = susfs_unwrap_jump_table(addr);
	if (!addr)
		goto out;

	memset(&kp, 0, sizeof(kp));
	kp.addr = (kprobe_opcode_t *)addr;
	ret = register_kprobe(&kp);
	if (ret)
		goto out;
	unregister_kprobe(&kp);

	addr = susfs_lookup_symbol("vfs_getattr_nosec");
	if (!addr)
		goto out;
	addr = susfs_unwrap_jump_table(addr);
	if (!addr)
		goto out;

	memset(&kp, 0, sizeof(kp));
	kp.addr = (kprobe_opcode_t *)addr;
	ret = register_kprobe(&kp);
	if (ret)
		goto out;
	unregister_kprobe(&kp);

	WRITE_ONCE(susfs_path_core_ok, true);
out:
	SUSFS_LOGI("sus_path hooks %s\n",
		   susfs_path_core_ok ? "available" : "UNAVAILABLE");
}
