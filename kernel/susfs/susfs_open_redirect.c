// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_open_redirect.c - SuSFS OPEN_REDIRECT, LKM edition.
 *
 * What the feature is
 * -------------------
 * A rule pairs two existing files:
 *
 *   target_pathname      the path the (selected) process believes it opens
 *   redirected_pathname  the path that is really opened
 *
 * When a process covered by `uid_scheme` opens the target path it gets the
 * contents of the redirected file, while every path report (/proc/self/maps,
 * /proc/self/fd/N, readlink, d_path, getcwd) keeps naming the target.  The
 * canonical use is showing a *different* copy of a file to a package than
 * the one it would otherwise read, without the package being able to tell.
 *
 * How upstream does it
 * --------------------
 * Upstream SuSFS is a source patch, so it has two cheap insertion points:
 *
 *   1. `susfs_add_open_redirect()` resolves both paths once and records the
 *      two (dev, ino) pairs plus both pathnames, and sets
 *      AS_FLAGS_OPEN_REDIRECT in `inode->i_mapping->flags` of *both* inodes.
 *   2. fs/namei.c `path_openat()` is patched: after the walk succeeds it
 *      tests the resolved inode for the flag, looks the rule up by ino, and
 *      - if `uid_scheme` matches the caller - throws away the nameidata and
 *      re-walks with a fabricated `struct filename` holding the redirected
 *      path.  So the substituted path goes through the *normal* open path:
 *      same do_open(), same fsnotify, same error handling.
 *   3. Display is spoofed separately: `show_map_vma()` prints the target
 *      pathname itself for flagged inodes (skipping seq_file_path) and
 *      rewrites the dev/ino columns.
 *
 * How we do it
 * ------------
 * We cannot patch fs/namei.c, and the resolution point inside path_openat()
 * is a straight-line block in a 4 KiB function - there is no function to
 * probe there, and rewriting `nd` from a probe is exactly the kind of thing
 * that breaks silently.  So:
 *
 *   1. Table: same fields, one entry per rule (upstream needs two hlist
 *      nodes, one per direction; a single node holding both sides is
 *      equivalent and one less allocation).
 *   2. Forward (the actual redirect): a syscall-table hook on __NR_openat.
 *      Because openat is one of the hottest syscalls in the system, the hook
 *      stays out of the way as much as it can:
 *        a. no rule at all                  -> straight to the original
 *        b. no uid_scheme applies to me      -> straight to the original
 *        c. copy the name (bounded, <=256 B) and string-compare it against
 *           the registered target pathnames
 *        d. only when it matches do we resolve it with kern_path(), look the
 *           rule up by (dev, ino) and open the redirected path with
 *           filp_open() + fd_install().
 *      Steps (c)/(d) are what keeps this affordable: (c) is a list walk of
 *      at most a handful of strcmp()s (usually zero: the list is empty for
 *      every device that never used the feature), and (d) only happens for
 *      the paths that are actually redirected.
 *   3. Display: a kretprobe on `prepend_path()`, the single choke point
 *      behind __d_path() / path_with_deleted() / d_absolute_path() /
 *      getcwd().  seq_file_path() -> seq_path() -> d_path() ->
 *      path_with_deleted() -> prepend_path(), so /proc/<pid>/maps, fdinfo,
 *      /proc/<pid>/fd/N, /proc/<pid>/cwd, /proc/<pid>/root and plain
 *      d_path() users all get the target name from one hook.  The dev/ino
 *      columns of /proc/<pid>/maps are a separate kprobe on
 *      show_vma_header_prefix(), which is how the two values reach the
 *      seq_file without going through d_path() at all.
 *
 * Honest caveats (deliberate deviations from the upstream patch)
 * --------------------------------------------------------------
 *  a. The caller must spell the target path exactly as it was registered
 *     (either the registered spelling or the kernel's canonical name of the
 *     same file: `susfs_add_open_redirect()` stores both, see
 *     susfs_or_canonical_name()).  Upstream tests only the resolved inode's
 *     flag bit, so it also catches any other spelling (/proc/self/fd/N,
 *     hardlinks reached under a third name).  We cannot: resolving every
 *     openat() name to find out would roughly double the cost of the
 *     hottest syscall on the device, so the string compare is the gate and
 *     a differently-spelled path is a *safe miss* (it opens the target
 *     file, i.e. behaves as if the rule did not exist).  Absolute paths are
 *     the normal case and are fully covered, including the symlink-vs-target
 *     pair (e.g. /system/etc/x -> /my_engineering/etc/x).
 *  b. 32-bit processes use the compat syscall table and are not redirected
 *     (the native table entry we patch is not the one they call).  All
 *     Android app processes on this device are 64-bit.
 *  c. `fsnotify_open()` is not exported on this kernel, so an inotify
 *     watcher on the target inode does not receive IN_OPEN/IN_ACCESS for a
 *     redirected open.  The file itself, its dentry and its contents are
 *     the redirected file's, so the only observable difference is the
 *     missing notification.
 *  d. Instances of the same file reached through a bind mount or a second
 *     hardlink share the inode, hence the flag bit and the table lookup -
 *     but see (a): the string gate still has to match.
 *  e. Entries and the AS_FLAGS_OPEN_REDIRECT bits are never freed and never
 *     cleared: the table state is immutable for readers, which is what lets
 *     the hot paths hold a spinlock instead of an SRCU read lock (and lets
 *     the kretprobe payload keep a pointer to the pathname string).  A
 *     replaced rule just gets `dead = true`, and the marked inodes keep a
 *     single unused bit set.  Re-adding a rule is idempotent from the
 *     caller's point of view.
 *  f. Replacing a rule matches on either spelling of the target (registered
 *     name or canonical alias).  Upstream rejects an add whose redirected
 *     side duplicates an existing rule; we simply supersede the old rule, so
 *     "point this path somewhere else" is one command instead of two.
 *  g. `SHRINK`/umount: if the redirected file disappears, filp_open() fails
 *     and the error is returned as-is (upstream behaves the same way: the
 *     substituted walk fails).
 *  h. `openat2()` does not exist on this kernel (5.4, no backport) so there
 *     is nothing else to hook.
 *  i. A name relative to a real dirfd is not redirected (see the comment in
 *     susfs_or_sys_openat()); absolute names and AT_FDCWD-relative names are.
 *  j. `O_NOFOLLOW` is honoured when resolving the target for comparison, so
 *     a caller that refuses to follow a symlink is never replied with the
 *     redirected file's contents.
 *
 * Locking
 * -------
 * Readers (the openat hook, the two display probes) take
 * `susfs_or_lock` (spinlock, irqsave because the maps hook can run with
 * interrupts disabled) and walk the list.  The only writer is the add
 * command, which appends a node and flips `dead` on superseded nodes under
 * the same lock; allocation and path resolution happen outside it.  Because
 * nodes are never freed, a reader that grabbed `entry->target_pathname`
 * under the lock can keep using the string after dropping it.
 *
 * Arming is lazy, exactly like SUS_PATH: `susfs_open_redirect_init()`
 * trial-registers every hook and immediately removes it, so the manager is
 * only told the feature exists when it can really be installed.  The real
 * registration happens on the first rule, and a failure there rolls
 * everything back and clears the same flag.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/seq_file.h>
#include <asm/unistd.h>

#include "susfs_internal.h"
#include "ksu.h"
#include "hook/syscall_hook.h"
#include "selinux/selinux.h"

/*
 * prepend_path() is called once per path report, and /proc/<pid>/maps calls
 * it once per VMA.  The default maxactive would be max(10, 2*nr_cpu); a
 * thread cannot nest d_path() deeply, but maps has one call in flight per
 * task and the probe is registered for the whole system, so leave headroom.
 */
#define SUSFS_OR_PREPEND_MAXACTIVE 64

#ifndef __NR_openat
#define __NR_openat 56
#endif

/* ------------------------------------------------------------------ */
/* table                                                              */
/* ------------------------------------------------------------------ */

struct susfs_or_entry {
	struct list_head list;
	/* "fake" side: what the selected process sees and asks to open */
	u32 target_dev;
	unsigned long target_ino;
	char target_pathname[SUSFS_MAX_LEN_PATHNAME];
	/*
	 * Second accepted spelling of the same file (kernel's canonical name,
	 * see susfs_or_canonical_name()).  Empty when it would be identical.
	 */
	char target_alias[SUSFS_MAX_LEN_PATHNAME];
	/* "real" side: what is actually opened */
	u32 redirected_dev;
	unsigned long redirected_ino;
	char redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int uid_scheme;
	bool dead;
	/* only used to log a redirection once per rule instead of per open */
	bool logged;
};

static LIST_HEAD(susfs_or_list);
static DEFINE_SPINLOCK(susfs_or_lock);
static DEFINE_MUTEX(susfs_or_arm_mutex);
static atomic_t susfs_or_entries = ATOMIC_INIT(0);

static bool susfs_or_core_ok;
static bool susfs_or_armed;
static int susfs_or_arm_err;

static syscall_fn_t susfs_or_orig_openat;
static syscall_fn_t susfs_or_probe_orig;
static struct kretprobe susfs_or_krp_prepend;
static struct kprobe susfs_or_kp_vma;

/* kretprobe payload for prepend_path(): where to write and what to write. */
struct susfs_or_prepend_data {
	char **bufp;
	int *buflenp;
	const char *fake;
};

/*
 * (dev, ino) plus the exact pathname the caller used.  The pathname is part
 * of the key on purpose: two hardlinks (or a bind mount and its source)
 * share one inode, and without it a rule registered for /a would also fire
 * for /b - redirecting a path nobody asked to redirect.  A string that
 * resolved to the right inode but is not the registered one is a miss, which
 * is exactly the documented deviation (a).
 */
static bool susfs_or_name_matches(const struct susfs_or_entry *entry,
				  const char *name)
{
	if (!strcmp(entry->target_pathname, name))
		return true;
	return entry->target_alias[0] != '\0' &&
	       !strcmp(entry->target_alias, name);
}

/*
 * Do these two rules describe the same file?  Any spelling of one side
 * against any spelling of the other counts, so adding the rule a second time
 * through the other spelling replaces the old node instead of stacking a
 * duplicate (both would otherwise match the same opens).
 */
static bool susfs_or_same_target(const struct susfs_or_entry *a,
				 const struct susfs_or_entry *b)
{
	if (susfs_or_name_matches(a, b->target_pathname))
		return true;
	return b->target_alias[0] != '\0' &&
	       susfs_or_name_matches(a, b->target_alias);
}

static struct susfs_or_entry *
susfs_or_find_target_locked(u32 dev, unsigned long ino, unsigned long ok_mask,
			    const char *name)
{
	struct susfs_or_entry *entry;

	list_for_each_entry (entry, &susfs_or_list, list) {
		if (entry->dead)
			continue;
		if (entry->target_dev != dev || entry->target_ino != ino)
			continue;
		if (!(ok_mask & BIT(entry->uid_scheme)))
			continue;
		if (!susfs_or_name_matches(entry, name))
			continue;
		return entry;
	}
	return NULL;
}

static struct susfs_or_entry *
susfs_or_find_redirected_locked(u32 dev, unsigned long ino)
{
	struct susfs_or_entry *entry;

	list_for_each_entry (entry, &susfs_or_list, list) {
		if (entry->dead)
			continue;
		if (entry->redirected_dev != dev ||
		    entry->redirected_ino != ino)
			continue;
		return entry;
	}
	return NULL;
}

static bool susfs_or_name_registered(const char *name)
{
	struct susfs_or_entry *entry;
	bool found = false;

	spin_lock(&susfs_or_lock);
	list_for_each_entry (entry, &susfs_or_list, list) {
		if (entry->dead)
			continue;
		if (susfs_or_name_matches(entry, name)) {
			found = true;
			break;
		}
	}
	spin_unlock(&susfs_or_lock);
	return found;
}

/* ------------------------------------------------------------------ */
/* uid_scheme                                                         */
/* ------------------------------------------------------------------ */

/*
 * Which of the five schemes cover the current process.  Computed once per
 * openat (never inside the table lock): `is_ksu_domain()` is only expensive
 * on the slow path where `cached_su_sid` has not been primed, and even then
 * it is a comparison against a constant context string.
 *
 * Semantics copied verbatim from upstream
 * `susfs_open_redirect_spoof_do_sys_openat()`; note that a scheme is the
 * *set of processes the rule applies to*, so all matching bits are set and
 * the per-entry test is a single bit test.
 */
static unsigned long susfs_or_uid_mask(void)
{
	uid_t uid = current_uid().val;
	bool ksu;
	unsigned long mask = 0;

	if (uid % 100000 < 10000)
		mask |= BIT(UID_NON_APP_PROC);

	ksu = is_ksu_domain();
	if (uid == 0 && !ksu)
		mask |= BIT(UID_ROOT_PROC_EXCEPT_SU_PROC);
	if (!ksu)
		mask |= BIT(UID_NON_SU_PROC);

	if (susfs_is_current_proc_umounted_app())
		mask |= BIT(UID_UMOUNTED_APP_PROC);
	if (susfs_is_current_proc_umounted())
		mask |= BIT(UID_UMOUNTED_PROC);

	return mask;
}

/* ------------------------------------------------------------------ */
/* forward: openat()                                                  */
/* ------------------------------------------------------------------ */

static long susfs_or_sys_openat(const struct pt_regs *regs)
{
	const char __user *filename;
	struct susfs_or_entry *entry;
	struct path path;
	struct file *f;
	struct inode *inode;
	char name[SUSFS_MAX_LEN_PATHNAME];
	unsigned long ok_mask;
	unsigned int flags;
	umode_t mode;
	bool log_it = false;
	int fd, n;

	/*
	 * Never call through a NULL original.  ksu_syscall_table_hook()
	 * patches the table even when it failed to capture the old entry, so
	 * an empty `orig` does not imply the entry was left alone; this check
	 * turns that leftover state into a clean -ENOSYS instead of an
	 * indirect branch to address zero.
	 */
	if (!READ_ONCE(susfs_or_orig_openat))
		return -ENOSYS;
	if (!atomic_read(&susfs_or_entries))
		return susfs_or_orig_openat(regs);

	ok_mask = susfs_or_uid_mask();
	if (!ok_mask)
		return susfs_or_orig_openat(regs);

	/* __arm64_sys_openat(dfd, filename, flags, mode) */
	filename = (const char __user *)(unsigned long)regs->regs[1];
	if (!filename)
		return susfs_or_orig_openat(regs);

	n = strncpy_from_user(name, filename, sizeof(name));
	if (n <= 0 || n >= (int)sizeof(name))
		return susfs_or_orig_openat(regs);

	if (!susfs_or_name_registered(name))
		return susfs_or_orig_openat(regs);

	flags = (unsigned int)regs->regs[2];
	mode = (umode_t)regs->regs[3];

	/*
	 * Resolve the name the caller actually handed us (relative names are
	 * resolved against the caller's cwd, exactly like the original call
	 * would) and compare inodes.  If the resolved inode is not a
	 * registered target - it was replaced, or the string only matched by
	 * accident - we fall through to the original.
	 *
	 * A name relative to a real dirfd cannot be resolved here:
	 * filename_lookup()/user_path_at()/getname() are not exported and
	 * kern_path() always uses AT_FDCWD, so resolving it would test a
	 * different file that merely shares the name.  Fall through instead -
	 * no redirect is better than redirecting the wrong file.
	 *
	 * O_NOFOLLOW is honoured so that a symlink target is not followed
	 * when the caller explicitly asked not to.
	 */
	if (name[0] != '/' && (int)regs->regs[0] != AT_FDCWD)
		return susfs_or_orig_openat(regs);

	if (kern_path(name, (flags & O_NOFOLLOW) ? 0 : LOOKUP_FOLLOW, &path))
		return susfs_or_orig_openat(regs);

	inode = d_backing_inode(path.dentry);
	if (!inode) {
		path_put(&path);
		return susfs_or_orig_openat(regs);
	}

	spin_lock(&susfs_or_lock);
	entry = susfs_or_find_target_locked((u32)inode->i_sb->s_dev,
					    inode->i_ino, ok_mask, name);
	if (entry && !entry->logged) {
		entry->logged = true;
		log_it = true;
	}
	spin_unlock(&susfs_or_lock);

	path_put(&path);

	if (!entry)
		return susfs_or_orig_openat(regs);

	if (log_it)
		SUSFS_LOGI("open_redirect: '%s' -> '%s' scheme=%d uid=%u\n",
			   entry->target_pathname, entry->redirected_pathname,
			   entry->uid_scheme, current_uid().val);

	/*
	 * Same order as do_sys_open(): reserve the descriptor first so the
	 * fd-limit error is reported before any work is done, then open, then
	 * publish.  `uid_scheme == UID_UMOUNTED_*` was already checked above.
	 */
	fd = get_unused_fd_flags(flags);
	if (fd < 0)
		return fd;

	f = filp_open(entry->redirected_pathname, flags, mode);
	if (IS_ERR(f)) {
		put_unused_fd(fd);
		return PTR_ERR(f);
	}

	fd_install(fd, f);
	return fd;
}

/* ------------------------------------------------------------------ */
/* reverse: path display                                              */
/* ------------------------------------------------------------------ */

/*
 * prepend_path(path, root, buffer, buflen) has already stored the finished
 * string in `*buffer` (and the remaining space in `*buflen`) by the time the
 * return handler runs, so the rewrite is a pure buffer operation:
 *
 *     old string   [start .......... start+old_len]  (NUL at old_len)
 *     free space   [start-avail .... start)
 *     new string   [start+old_len-fl .... start+old_len]  (fl = strlen(fake))
 *
 * i.e. the fake path is written right-aligned to where the old NUL was, so
 * the buffer keeps pointing at a NUL-terminated string and every caller that
 * only looks at the returned pointer (`__d_path` -> `res`, `d_path` ->
 * `path_with_deleted`, seq_path -> mangle_path) keeps working.
 *
 * Only `error == 0` is rewritten: 1 (already at the root), 2 (detached),
 * 3 (escaped the root) and negative errors all leave an unusable string
 * behind, and the "(deleted)" suffix that path_with_deleted() prepended is
 * part of the old string, so a successful substitution drops it - correct,
 * because the name we print is the target path, which does exist.
 */
static int susfs_or_prepend_entry(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct susfs_or_prepend_data *data = (void *)ri->data;
	const struct path *path;
	struct susfs_or_entry *entry;
	struct inode *inode;

	if (!atomic_read(&susfs_or_entries))
		return 1;
	if (!susfs_is_current_proc_umounted_app())
		return 1;

	path = (const struct path *)regs->regs[0];
	if (!path || !path->dentry)
		return 1;

	inode = d_backing_inode(path->dentry);
	if (!inode || !inode->i_mapping)
		return 1;
	if (!test_bit(AS_FLAGS_OPEN_REDIRECT, &inode->i_mapping->flags))
		return 1;

	spin_lock(&susfs_or_lock);
	entry = susfs_or_find_redirected_locked((u32)inode->i_sb->s_dev,
						inode->i_ino);
	if (entry)
		data->fake = entry->target_pathname;
	spin_unlock(&susfs_or_lock);

	if (!entry)
		return 1;

	data->bufp = (char **)regs->regs[2];
	data->buflenp = (int *)regs->regs[3];
	return 0;
}

static int susfs_or_prepend_ret(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct susfs_or_prepend_data *data = (void *)ri->data;
	char *start, *dst;
	size_t old_len, fl;
	int avail;

	if ((int)regs->regs[0] != 0)
		return 0;
	if (!data->fake || !data->bufp || !data->buflenp)
		return 0;

	start = *data->bufp;
	if (!start)
		return 0;

	avail = *data->buflenp;
	if (avail < 0)
		return 0;

	fl = strlen(data->fake);
	if (!fl)
		return 0;

	old_len = strlen(start);
	/* the fake path plus its NUL has to fit in front of the old NUL */
	if (old_len + (size_t)avail < fl)
		return 0;

	dst = start + old_len - fl;
	memmove(dst, data->fake, fl);
	dst[fl] = '\0'; /* == start[old_len], the old terminator slot */

	*data->bufp = dst;
	*data->buflenp = avail + (int)old_len - (int)fl;
	return 0;
}

/*
 * show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino)
 *   -> x5 = dev (32-bit), x6 = ino.
 *
 * show_map_vma() prints the header with the file's dev/ino before it prints
 * the name, so the columns have to be fixed here; the name itself comes from
 * seq_file_path() -> prepend_path().  The upper halves of x5/x6 may hold
 * garbage (the callee only reads w5), so they are only written back when a
 * rule actually matched.
 */
static int susfs_or_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct susfs_or_entry *entry;

	if (!atomic_read(&susfs_or_entries))
		return 0;
	if (!susfs_is_current_proc_umounted_app())
		return 0;

	spin_lock(&susfs_or_lock);
	entry = susfs_or_find_redirected_locked((u32)regs->regs[5],
						regs->regs[6]);
	if (entry) {
		regs->regs[5] = entry->target_dev;
		regs->regs[6] = entry->target_ino;
	}
	spin_unlock(&susfs_or_lock);

	return 0;
}

/* ------------------------------------------------------------------ */
/* arming                                                             */
/* ------------------------------------------------------------------ */

/*
 * The forward hook is the one that has to exist: without it nothing is
 * redirected.  Both display hooks are treated as core too, because a
 * half-installed feature (file redirected but /proc/self/fd and maps still
 * naming the real path) is worse than no feature at all - it advertises a
 * redirect the process can trivially detect.
 */
static int susfs_or_arm_openat(void)
{
	if (!ksu_syscall_table)
		return -ENODEV;

	/* a previous arm may have left the entry pointing at us */
	if (READ_ONCE(ksu_syscall_table[__NR_openat]) == susfs_or_sys_openat) {
		if (susfs_or_orig_openat)
			return 0;
		/*
		 * Stale state: the entry points at our forwarder but the
		 * original was never captured.  Drop the tracking record first,
		 * otherwise ksu_syscall_table_hook() would store our own
		 * forwarder as "the original" and recurse forever.
		 */
		ksu_syscall_table_unhook(__NR_openat);
		if (READ_ONCE(ksu_syscall_table[__NR_openat]) ==
		    susfs_or_sys_openat)
			return -EIO;
	}

	ksu_syscall_table_hook(__NR_openat, susfs_or_sys_openat,
			       &susfs_or_orig_openat);
	if (!susfs_or_orig_openat)
		return -ENOENT;

	/*
	 * ksu_syscall_table_hook() ignores the fixmap write result, so confirm
	 * the entry really points at us before claiming the feature.  The
	 * unhook is left to susfs_or_disarm_all(), which is gated on the entry
	 * itself and therefore restores it exactly once.
	 */
	if (READ_ONCE(ksu_syscall_table[__NR_openat]) != susfs_or_sys_openat)
		return -EIO;
	return 0;
}

static int susfs_or_register_prepend(void)
{
	unsigned long addr = susfs_lookup_symbol("prepend_path");
	int ret;

	if (!addr)
		return -ENOENT;
	addr = susfs_unwrap_jump_table(addr);
	if (!addr)
		return -ENOENT;

	memset(&susfs_or_krp_prepend, 0, sizeof(susfs_or_krp_prepend));
	susfs_or_krp_prepend.kp.addr = (kprobe_opcode_t *)addr;
	susfs_or_krp_prepend.entry_handler = susfs_or_prepend_entry;
	susfs_or_krp_prepend.handler = susfs_or_prepend_ret;
	susfs_or_krp_prepend.data_size = sizeof(struct susfs_or_prepend_data);
	susfs_or_krp_prepend.maxactive = SUSFS_OR_PREPEND_MAXACTIVE;

	ret = register_kretprobe(&susfs_or_krp_prepend);
	if (ret)
		memset(&susfs_or_krp_prepend, 0, sizeof(susfs_or_krp_prepend));
	return ret;
}

static int susfs_or_register_vma(void)
{
	unsigned long addr = susfs_lookup_symbol("show_vma_header_prefix");
	int ret;

	if (!addr)
		return -ENOENT;
	addr = susfs_unwrap_jump_table(addr);
	if (!addr)
		return -ENOENT;

	memset(&susfs_or_kp_vma, 0, sizeof(susfs_or_kp_vma));
	susfs_or_kp_vma.addr = (kprobe_opcode_t *)addr;
	susfs_or_kp_vma.pre_handler = susfs_or_vma_pre;

	ret = register_kprobe(&susfs_or_kp_vma);
	if (ret)
		memset(&susfs_or_kp_vma, 0, sizeof(susfs_or_kp_vma));
	return ret;
}

static void susfs_or_disarm_all(void)
{
	/*
	 * Gate on the table entry rather than on `susfs_or_orig_openat`:
	 * ksu_syscall_table_hook() patches the entry even when it failed to
	 * capture the original, so an empty `orig` does not mean the entry was
	 * left alone.  Checking the entry also makes this idempotent - after a
	 * successful unhook the entry is the real syscall again, so a second
	 * call does not emit a spurious "not found in hooked entries" warning.
	 *
	 * `susfs_or_orig_openat` is deliberately kept: if the restore did not
	 * take, the entry still points at susfs_or_sys_openat(), which must
	 * keep forwarding to the real syscall instead of calling NULL.
	 */
	if (ksu_syscall_table &&
	    READ_ONCE(ksu_syscall_table[__NR_openat]) == susfs_or_sys_openat)
		ksu_syscall_table_unhook(__NR_openat);

	if (susfs_or_krp_prepend.kp.addr) {
		unregister_kretprobe(&susfs_or_krp_prepend);
		memset(&susfs_or_krp_prepend, 0,
		       sizeof(susfs_or_krp_prepend));
	}

	if (susfs_or_kp_vma.addr) {
		unregister_kprobe(&susfs_or_kp_vma);
		memset(&susfs_or_kp_vma, 0, sizeof(susfs_or_kp_vma));
	}
}

/*
 * Deferred until the first rule for the same reason as SUS_PATH: an armed
 * probe on __NR_openat costs every open() in the system a breakpoint trap,
 * and most devices never add an open redirect.
 */
static int susfs_or_arm(void)
{
	int ret = 0;

	if (READ_ONCE(susfs_or_armed))
		return READ_ONCE(susfs_or_arm_err);
	if (!READ_ONCE(susfs_or_core_ok))
		return -ENODEV;

	mutex_lock(&susfs_or_arm_mutex);
	if (susfs_or_armed) {
		/* lost the race against another add; report its verdict */
		ret = susfs_or_arm_err;
		goto out;
	}

	ret = susfs_or_arm_openat();
	if (ret) {
		SUSFS_LOGE("failed to hook __NR_openat, err: %d\n", ret);
		goto fail;
	}

	ret = susfs_or_register_prepend();
	if (ret) {
		SUSFS_LOGE("failed to install 'prepend_path' probe, err: %d\n",
			   ret);
		goto fail;
	}

	ret = susfs_or_register_vma();
	if (ret) {
		SUSFS_LOGE("failed to install 'show_vma_header_prefix' probe, "
			   "err: %d\n",
			   ret);
		goto fail;
	}

	WRITE_ONCE(susfs_or_arm_err, 0);
	WRITE_ONCE(susfs_or_armed, true);
	SUSFS_LOGI("open_redirect hooks armed\n");
	goto out;

fail:
	susfs_or_disarm_all();
	WRITE_ONCE(susfs_or_arm_err, ret);
out:
	mutex_unlock(&susfs_or_arm_mutex);
	return ret;
}

/* ------------------------------------------------------------------ */
/* userspace command                                                  */
/* ------------------------------------------------------------------ */

/*
 * The kernel's canonical name of an already-resolved path (symlinks
 * followed, ".." collapsed).  A rule is keyed on the spelling the caller
 * used, and userspace used to hand us a pre-canonicalised string, so a
 * process that opened the *other* spelling (the symlink itself, e.g.
 * /system/etc/security/otacerts.zip -> /my_engineering/etc/...) never
 * matched.  Storing both spellings closes that gap: the (dev, ino) pair
 * guarantees they denote the same file.
 *
 * d_path() writes into the tail of `buf` and returns a pointer inside it, so
 * the string is moved to the front before copying out.  Any failure yields
 * an empty alias, which simply means "only the registered spelling matches".
 */
static void susfs_or_canonical_name(const struct path *path, char *out,
				    size_t len)
{
	char buf[SUSFS_MAX_LEN_PATHNAME];
	char *p;

	out[0] = '\0';
	p = d_path(path, buf, sizeof(buf));
	if (IS_ERR(p) || !p)
		return;
	if (p != buf)
		memmove(buf, p, strlen(p) + 1);
	strscpy(out, buf, len);
}

/*
 * Resolve both sides, refuse the pseudo filesystems where an inode-based
 * rule cannot mean anything, then append the node.
 *
 * Ordering matters: the node is linked and the flag bits are set only after
 * arming succeeded, so a failed add leaves no trace on the inode and no
 * reachable entry.  A process that opens the target between those two steps
 * (arming and linking) simply is not redirected yet - arming only installs
 * hooks, it cannot redirect by itself.
 */
void susfs_add_open_redirect(void __user **user_info)
{
	struct st_susfs_open_redirect info;
	struct susfs_or_entry *entry, *old;
	struct path target_path, redirected_path;
	struct inode *target_inode, *redirected_inode;
	char canon[SUSFS_MAX_LEN_PATHNAME];
	int err = 0;

	if (copy_from_user(&info,
			   (struct st_susfs_open_redirect __user *)*user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy;
	}

	if (info.target_pathname[0] == '\0') {
		info.err = -EINVAL;
		SUSFS_LOGE("empty target_pathname\n");
		goto out_copy;
	}
	if (!memchr(info.target_pathname, '\0', SUSFS_MAX_LEN_PATHNAME) ||
	    !memchr(info.redirected_pathname, '\0', SUSFS_MAX_LEN_PATHNAME)) {
		info.err = -EINVAL;
		SUSFS_LOGE("pathname not NUL-terminated\n");
		goto out_copy;
	}
	if (info.redirected_pathname[0] == '\0') {
		info.err = -EINVAL;
		SUSFS_LOGE("empty redirected_pathname\n");
		goto out_copy;
	}
	if (info.uid_scheme < UID_NON_APP_PROC ||
	    info.uid_scheme > UID_UMOUNTED_PROC) {
		info.err = -EINVAL;
		SUSFS_LOGE("invalid uid scheme: %d\n", info.uid_scheme);
		goto out_copy;
	}

	err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &target_path);
	if (err) {
		SUSFS_LOGE("failed opening target '%s', err: %d\n",
			   info.target_pathname, err);
		info.err = err;
		goto out_copy;
	}

	err = kern_path(info.redirected_pathname, LOOKUP_FOLLOW,
			&redirected_path);
	if (err) {
		SUSFS_LOGE("failed opening redirected '%s', err: %d\n",
			   info.redirected_pathname, err);
		info.err = err;
		goto out_path_put_target;
	}

	target_inode = d_backing_inode(target_path.dentry);
	redirected_inode = d_backing_inode(redirected_path.dentry);
	/*
	 * Upstream reports -ENOENT here: the path resolved, but there is no
	 * inode to key the rule on.  `i_mapping` is checked too so the later
	 * set_bit() cannot dereference NULL.
	 */
	if (!target_inode || !target_inode->i_mapping ||
	    !redirected_inode || !redirected_inode->i_mapping) {
		info.err = -ENOENT;
		goto out_path_put_both;
	}

	/*
	 * pseudo filesystems: their inodes are not cached the way a normal
	 * filesystem's are (each lookup can hand out a different inode), so a
	 * rule keyed on (dev, ino) plus a flag bit would be unreliable.  Refuse
	 * instead of pretending.
	 */
	if (target_inode->i_sb->s_magic == FUSE_SUPER_MAGIC ||
	    redirected_inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {
		info.err = -EINVAL;
		SUSFS_LOGE("fuse inode unsupported\n");
		goto out_path_put_both;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		info.err = -ENOMEM;
		goto out_path_put_both;
	}

	susfs_or_canonical_name(&target_path, canon, sizeof(canon));

	entry->target_dev = (u32)target_inode->i_sb->s_dev;
	entry->target_ino = target_inode->i_ino;
	memcpy(entry->target_pathname, info.target_pathname,
	       SUSFS_MAX_LEN_PATHNAME);
	if (canon[0] && strcmp(canon, info.target_pathname))
		strscpy(entry->target_alias, canon,
			sizeof(entry->target_alias));
	entry->redirected_dev = (u32)redirected_inode->i_sb->s_dev;
	entry->redirected_ino = redirected_inode->i_ino;
	memcpy(entry->redirected_pathname, info.redirected_pathname,
	       SUSFS_MAX_LEN_PATHNAME);
	entry->uid_scheme = info.uid_scheme;
	INIT_LIST_HEAD(&entry->list);

	err = susfs_or_arm();
	if (err) {
		/* report the real reason (e.g. -EIO) instead of a generic one */
		info.err = err;
		SUSFS_LOGE("failed to arm open_redirect, err: %d\n", err);
		kfree(entry);
		goto out_path_put_both;
	}

	/*
	 * Mark both inodes.  The target side is what a future "is this path
	 * redirected" test would look at; the redirected side is the one the
	 * display hooks test (SUSFS_IS_INODE_OPEN_REDIRECT is exactly the flag
	 * plus the umounted-app gate).
	 */
	set_bit(AS_FLAGS_OPEN_REDIRECT, &target_inode->i_mapping->flags);
	set_bit(AS_FLAGS_OPEN_REDIRECT, &redirected_inode->i_mapping->flags);

	spin_lock(&susfs_or_lock);
	list_for_each_entry (old, &susfs_or_list, list) {
		if (!old->dead && susfs_or_same_target(old, entry)) {
			WRITE_ONCE(old->dead, true);
			break;
		}
	}
	list_add_tail(&entry->list, &susfs_or_list);
	spin_unlock(&susfs_or_lock);
	atomic_inc(&susfs_or_entries);

	info.err = 0;
	SUSFS_LOGI("open_redirect added: '%s' -> '%s' scheme=%d alias='%s'\n",
		   entry->target_pathname, entry->redirected_pathname,
		   entry->uid_scheme, entry->target_alias);

out_path_put_both:
	path_put(&redirected_path);
out_path_put_target:
	path_put(&target_path);
out_copy:
	if (copy_to_user(
		    &((struct st_susfs_open_redirect __user *)*user_info)->err,
		    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", info.err);
}

/* ------------------------------------------------------------------ */
/* availability / init                                                */
/* ------------------------------------------------------------------ */

/*
 * The feature list asks this; it must be false whenever a redirect could
 * silently go un-redirected or un-spoofed.  `susfs_or_arm_err` covers the
 * case where arming failed after init had said yes; a later successful arm
 * clears it again, so the answer always tracks what is actually installed.
 */
bool susfs_open_redirect_available(void)
{
	return READ_ONCE(susfs_or_core_ok) && !READ_ONCE(susfs_or_arm_err);
}

/*
 * The forward hook is a pass-through that only calls the saved original, so
 * a probe registration that cannot be undone is harmless: the entry stays
 * "hooked" but every openat() reaches the real syscall unchanged.
 */
static long susfs_or_probe_syscall(const struct pt_regs *regs)
{
	if (!susfs_or_probe_orig)
		return -ENOSYS;
	return susfs_or_probe_orig(regs);
}

void susfs_open_redirect_init(void)
{
	struct kprobe kp;
	unsigned long addr;
	int ret;

	WRITE_ONCE(susfs_or_core_ok, false);

	if (!ksu_syscall_table) {
		SUSFS_LOGE("syscall table unavailable, open_redirect stays off\n");
		goto out;
	}

	ksu_syscall_table_hook(__NR_openat, susfs_or_probe_syscall,
			       &susfs_or_probe_orig);
	if (!susfs_or_probe_orig) {
		SUSFS_LOGE("__NR_openat unresolvable, open_redirect stays off\n");
		goto out;
	}
	if (READ_ONCE(ksu_syscall_table[__NR_openat]) != susfs_or_probe_syscall) {
		ksu_syscall_table_unhook(__NR_openat);
		SUSFS_LOGE("__NR_openat not patchable, open_redirect stays off\n");
		goto out;
	}
	ksu_syscall_table_unhook(__NR_openat);
	if (READ_ONCE(ksu_syscall_table[__NR_openat]) != susfs_or_probe_orig) {
		/*
		 * Our pass-through probe could not be removed.  It is harmless
		 * (it only forwards), but arming on top of it would chain two
		 * hooks and leave a bogus "original" behind, so refuse.
		 */
		SUSFS_LOGE("__NR_openat not restorable, open_redirect stays "
			   "off\n");
		goto out;
	}

	addr = susfs_lookup_symbol("prepend_path");
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

	addr = susfs_lookup_symbol("show_vma_header_prefix");
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

	WRITE_ONCE(susfs_or_core_ok, true);
out:
	SUSFS_LOGI("open_redirect hooks %s\n",
		   susfs_or_core_ok ? "available" : "UNAVAILABLE");
}
