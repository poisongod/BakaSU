// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_map.c - SuSFS SUS_MAP (mapping hiding), LKM edition.
 *
 * Upstream SuSFS hides a mapping by
 *
 *   1. `susfs_add_sus_map()` resolving the path once and marking the inode
 *      with AS_FLAGS_SUS_MAP in address_space.flags, and
 *   2. consulting that bit at every place where a VMA (or an address range
 *      belonging to one) can turn into user visible output.
 *
 * Part 1 is unchanged.  Part 2 becomes one kprobe per call site, each of
 * which makes the hooked function return the "nothing here" answer when the
 * VMA it was handed belongs to a flagged inode:
 *
 *   show_map_vma(m, vma)                void -> skip the whole line
 *   show_smap(m, vma)                   int  -> return 0, print nothing
 *   walk_page_vma(vma, ops, priv)       int  -> return 0, gather no stats
 *   walk_page_range(mm, s, e, ops, p)   int  -> return 0, walk nothing
 *   __access_remote_vm(tsk, mm, ...)    int  -> return 0, copy nothing
 *
 * The first two cover /proc/<pid>/maps, /proc/<pid>/smaps and the header
 * line inside smaps.  The last three close the remaining leaks:
 *
 *   - /proc/<pid>/smaps_rollup has no per-VMA line, it prints a single total
 *     summed up by smap_gather_stats().  That helper is inlined in this
 *     kernel, but it hands each VMA to walk_page_vma() with either
 *     smaps_walk_ops or smaps_shmem_walk_ops, so returning early from that
 *     walk is exactly what upstream's `if (!SUSFS_IS_INODE_SUS_MAP(...))
 *     smap_gather_stats(...)` does.  shmem_swap_usage() is called by the
 *     same helper *before* the walk, hence the kretprobe that zeroes its
 *     result for a hidden VMA - without it the aggregated Swap figure would
 *     still include a hidden tmpfs mapping.
 *   - /proc/<pid>/pagemap walks page ranges instead of VMAs; upstream skips
 *     the whole 128 KiB chunk whose first VMA is hidden, which here is the
 *     same as returning 0 from walk_page_range() when the caller passes
 *     pagemap_ops.
 *   - /proc/<pid>/mem (and anything else reaching access_remote_vm()) would
 *     otherwise let a reader copy a hidden mapping's contents out.  Upstream
 *     breaks out of the copy loop; returning 0 bytes transferred from
 *     __access_remote_vm() is the same observable result.
 *
 * All of them are decided with the same `susfs_is_current_proc_umounted_app()`
 * gate upstream uses, so shell (2000) and root (0) always keep seeing the
 * real maps - that is what makes the feature testable from a normal app
 * and what keeps the manager/debug tools honest.
 *
 * Why the hooks are lazily armed
 * ------------------------------
 * /proc/<pid>/maps is read by a lot of unrelated processes (every `ps`,
 * every bug report, every monitoring service).  A kprobe costs a
 * breakpoint trap for each caller even when no rule exists, so the probes
 * are installed on the first ADD_SUS_MAP and not before.  `available()` is
 * answered from the init-time trial registration, so the feature list is
 * correct *before* the first rule too - it says "supported", which is the
 * truth: the hooks are known to be installable and are installed the
 * moment they are needed.
 *
 * Remaining, unavoidable differences
 * ----------------------------------
 *  a. proc_map_files_readdir() (/proc/<pid>/map_files) collects the VMAs
 *     into a genradix before emitting any of them, so there is no per-entry
 *     hook that could drop one VMA without either truncating the whole
 *     listing (dir_emit() returning false stops the readdir, and the caller
 *     has no idea an entry was dropped) or failing it (-ENOMEM from
 *     genradix_ptr_alloc).  What those entries would reveal is a bare
 *     "start-end" address range with no file name, and upstream only hides
 *     the readdir entry as well - looking the very same name up directly
 *     still works there.  Deliberate, documented gap.
 *  b. /proc/<pid>/numa_maps has its own walker and no upstream handling
 *     either.
 *  c. The rule lives in `inode->i_mapping->flags`, exactly like upstream:
 *     it survives rename/hardlink/bind-mount (they share the inode) but it
 *     only applies to the inode instance that `kern_path()` resolved.  On
 *     a filesystem that hands out a fresh inode per lookup (FUSE in
 *     pathological cases) the bit can be lost - and then the mapping is
 *     simply not hidden, it is never *mis*hidden.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "susfs_internal.h"

static bool susfs_map_core_ok;		/* every hook is known to work */
static bool susfs_map_armed;		/* probes are installed (or tried) */
static int susfs_map_arm_err;		/* <0 when the install failed */
static DEFINE_MUTEX(susfs_map_arm_mutex);

/*
 * Cheap "has any rule ever been added" gate.  Rules are one-way (the inode
 * bit is never cleared, upstream does not clear it either), so a monotonic
 * counter is enough and no per-rule bookkeeping has to be kept.
 */
static atomic_t susfs_map_flagged = ATOMIC_INIT(0);

static struct kprobe susfs_map_kp_vma;
static struct kprobe susfs_map_kp_smap;
static struct kprobe susfs_map_kp_walk_vma;
static struct kprobe susfs_map_kp_walk_range;
static struct kprobe susfs_map_kp_remote_vm;
static struct kretprobe susfs_map_krp_shmem_swap;

/*
 * Walk tables the range hooks have to recognise, resolved once in init().
 * They are plain data symbols in .data (no kCFI hash, not exported), so the
 * ordinary kallsyms resolver finds them by their bare name.
 */
static unsigned long susfs_map_smaps_walk_ops;
static unsigned long susfs_map_smaps_shmem_walk_ops;
static unsigned long susfs_map_pagemap_ops;

/* ------------------------------------------------------------------ */
/* match                                                              */
/* ------------------------------------------------------------------ */

static bool susfs_map_vma_hidden(struct vm_area_struct *vma)
{
	struct file *file;
	struct inode *inode;

	if (!vma)
		return false;

	/* anonymous mappings have no inode and nothing to hide */
	file = vma->vm_file;
	if (!file)
		return false;

	inode = file_inode(file);
	if (!inode || !inode->i_mapping)
		return false;

	return test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags);
}

static inline bool susfs_map_rules_active(void)
{
	return READ_ONCE(susfs_map_core_ok) &&
	       atomic_read(&susfs_map_flagged) > 0;
}

static inline bool susfs_map_should_hide(struct vm_area_struct *vma)
{
	if (!susfs_map_rules_active())
		return false;
	if (!susfs_is_current_proc_umounted_app())
		return false;
	return susfs_map_vma_hidden(vma);
}

/*
 * Lockless find_vma(): the first VMA whose range ends above @addr, holes
 * included - that is what find_vma() answers and what upstream's pagemap and
 * /proc/<pid>/mem sites use.  Every caller of the range hooks below holds
 * mmap_sem for reading, so nothing is locked here; a kprobe must not sleep.
 *
 * Every caller of this helper except the __access_remote_vm() probe is
 * already inside mmap_sem (see the per-hook comments below).  That one
 * probe sits on the function entry, before the lock is taken, and takes
 * read_trylock() around the walk instead.
 */
static struct vm_area_struct *susfs_map_vma_at(struct mm_struct *mm,
					       unsigned long addr)
{
	struct vm_area_struct *vma;

	if (!mm)
		return NULL;

	for (vma = READ_ONCE(mm->mmap); vma; vma = READ_ONCE(vma->vm_next)) {
		if (addr < vma->vm_end)
			return vma;
	}

	return NULL;
}

/* ------------------------------------------------------------------ */
/* hooks                                                              */
/* ------------------------------------------------------------------ */

/*
 * show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
 *
 * Printing happens entirely inside this function (the header comes from
 * show_vma_header_prefix(), which is called from here), so pretending it
 * returned early removes the whole line from both `maps` and the header
 * line of `smaps`.
 */
static int susfs_map_pre_map_vma(struct kprobe *kp, struct pt_regs *regs)
{
	if (!susfs_map_should_hide((struct vm_area_struct *)regs->regs[1]))
		return 0;

	/* void return value: only the instruction pointer matters */
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * show_smap(struct seq_file *m, void *v) -> int
 *
 * Returning 0 is exactly what upstream does for a hidden VMA; it keeps the
 * seq_file iteration going while printing nothing for this entry.
 */
static int susfs_map_pre_smap(struct kprobe *kp, struct pt_regs *regs)
{
	if (!susfs_map_should_hide((struct vm_area_struct *)regs->regs[1]))
		return 0;

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * walk_page_vma(vma, ops, private) -> int
 *
 * smap_gather_stats() (inlined in this kernel) walks each VMA with
 * smaps_walk_ops or, for a shared shmem mapping, smaps_shmem_walk_ops.
 * Skipping the walk leaves `mss` untouched, so a hidden VMA contributes
 * nothing to /proc/<pid>/smaps_rollup - the same figure upstream gets by
 * never calling smap_gather_stats() for it.  Other walk tables
 * (show_numa_ops, ...) are left alone.
 */
static int susfs_map_pre_walk_vma(struct kprobe *kp, struct pt_regs *regs)
{
	unsigned long ops = (unsigned long)regs->regs[1];

	if (ops != READ_ONCE(susfs_map_smaps_walk_ops) &&
	    ops != READ_ONCE(susfs_map_smaps_shmem_walk_ops))
		return 0;

	if (!susfs_map_should_hide((struct vm_area_struct *)regs->regs[0]))
		return 0;

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * walk_page_range(mm, start, end, ops, private) -> int
 *
 * pagemap_read() passes pagemap_ops and walks one 128 KiB chunk at a time.
 * Upstream jumps over walk_page_range() for a chunk whose first VMA is
 * hidden (goto bypass_orig_flow), which leaves pm.pos at 0 so not a single
 * entry is copied out for it.  Returning 0 from the walk produces the very
 * same state: pagemap_read() copies PM_ENTRY_BYTES * pm.pos == 0 bytes and
 * moves on to the next chunk.  Those pages therefore never read back as
 * present, and no PFN leaks.
 */
static int susfs_map_pre_walk_range(struct kprobe *kp, struct pt_regs *regs)
{
	if ((unsigned long)regs->regs[3] != READ_ONCE(susfs_map_pagemap_ops))
		return 0;

	if (!susfs_map_should_hide(
		    susfs_map_vma_at((struct mm_struct *)regs->regs[0],
				     (unsigned long)regs->regs[1])))
		return 0;

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * __access_remote_vm(tsk, mm, addr, buf, len, gup_flags) -> int
 *
 * Returns the number of bytes actually transferred, so 0 is the same answer
 * upstream produces when it breaks out of the copy loop before the first
 * iteration.  Covers /proc/<pid>/mem, ptrace PEEKDATA/POKEDATA and every
 * other caller reaching into a foreign address space.  Upstream re-checks
 * the VMA on every page it copies; here the answer is decided once per call,
 * which is equivalent in practice because every caller of
 * access_remote_vm() transfers at most one page per call (mem_rw(),
 * access_process_vm(), the coredump reader) and a page never straddles two
 * VMAs.  /proc/<pid>/cmdline also uses this path, but it reads the stack,
 * which is never a hidden mapping.
 */
static int susfs_map_pre_remote_vm(struct kprobe *kp, struct pt_regs *regs)
{
	struct mm_struct *mm = (struct mm_struct *)regs->regs[1];
	unsigned long addr = (unsigned long)regs->regs[2];
	bool hide;

	if (!susfs_map_rules_active() || !mm)
		return 0;

	/*
	 * This probe is on the function *entry*, i.e. before the
	 * down_read_killable(&mm->mmap_sem) a few instructions in, whereas
	 * upstream hides the region from inside the copy loop with the lock
	 * held.  Walking mm->mmap without it could dereference a VMA that a
	 * concurrent munmap is freeing, so take the read side here - the
	 * trylock form never sleeps, which is mandatory in a kprobe.  If a
	 * writer is active we simply do not hide this one access.
	 */
	if (!down_read_trylock(&mm->mmap_sem))
		return 0;

	hide = susfs_map_should_hide(susfs_map_vma_at(mm, addr));

	up_read(&mm->mmap_sem);

	if (!hide)
		return 0;

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

/*
 * shmem_swap_usage(vma) -> unsigned long, called by smap_gather_stats()
 * *before* the walk for shmem-backed VMAs.  Zeroing it keeps a hidden tmpfs
 * mapping's swap accounting out of the rollup total.
 */
static int susfs_map_shmem_swap_entry(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	*(unsigned long *)ri->data = (unsigned long)regs->regs[0];
	return 0;
}

static int susfs_map_shmem_swap_ret(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	if (susfs_map_should_hide(
		    (struct vm_area_struct *)*(unsigned long *)ri->data))
		regs->regs[0] = 0;
	return 0;
}

/* ------------------------------------------------------------------ */
/* arming                                                             */
/* ------------------------------------------------------------------ */

/*
 * Undo a partial arm.  `last` is the highest step index known to be
 * registered; the steps are the ones susfs_map_arm() walks through in order.
 */
static void susfs_map_unarm(int last)
{
	switch (last) {
	case 5:
		unregister_kretprobe(&susfs_map_krp_shmem_swap);
		memset(&susfs_map_krp_shmem_swap, 0,
		       sizeof(susfs_map_krp_shmem_swap));
		/* fall through */
	case 4:
		unregister_kprobe(&susfs_map_kp_remote_vm);
		memset(&susfs_map_kp_remote_vm, 0,
		       sizeof(susfs_map_kp_remote_vm));
		/* fall through */
	case 3:
		unregister_kprobe(&susfs_map_kp_walk_range);
		memset(&susfs_map_kp_walk_range, 0,
		       sizeof(susfs_map_kp_walk_range));
		/* fall through */
	case 2:
		unregister_kprobe(&susfs_map_kp_walk_vma);
		memset(&susfs_map_kp_walk_vma, 0,
		       sizeof(susfs_map_kp_walk_vma));
		/* fall through */
	case 1:
		unregister_kprobe(&susfs_map_kp_smap);
		memset(&susfs_map_kp_smap, 0, sizeof(susfs_map_kp_smap));
		/* fall through */
	case 0:
		unregister_kprobe(&susfs_map_kp_vma);
		memset(&susfs_map_kp_vma, 0, sizeof(susfs_map_kp_vma));
		/* fall through */
	default:
		break;
	}
}

static int susfs_map_arm(void)
{
	int ret = 0;
	int step;

	if (READ_ONCE(susfs_map_armed))
		return READ_ONCE(susfs_map_arm_err);

	mutex_lock(&susfs_map_arm_mutex);
	if (susfs_map_armed) {
		ret = READ_ONCE(susfs_map_arm_err);
		mutex_unlock(&susfs_map_arm_mutex);
		return ret;
	}

	/*
	 * One hook per surface that can turn a VMA into user visible output.
	 * All of them or none: a rule that hides the path from maps but not
	 * from smaps_rollup or /proc/<pid>/mem would be a half-truth, so a
	 * partial install is rolled back and reported as "not supported".
	 */
	for (step = 0; step < 6 && !ret; step++) {
		switch (step) {
		case 0:
			ret = susfs_register_kprobe_at(&susfs_map_kp_vma,
						       "show_map_vma",
						       susfs_map_pre_map_vma);
			break;
		case 1:
			ret = susfs_register_kprobe_at(&susfs_map_kp_smap,
						       "show_smap",
						       susfs_map_pre_smap);
			break;
		case 2:
			ret = susfs_register_kprobe_at(&susfs_map_kp_walk_vma,
						       "walk_page_vma",
						       susfs_map_pre_walk_vma);
			break;
		case 3:
			ret = susfs_register_kprobe_at(&susfs_map_kp_walk_range,
						       "walk_page_range",
						       susfs_map_pre_walk_range);
			break;
		case 4:
			ret = susfs_register_kprobe_at(&susfs_map_kp_remote_vm,
						       "__access_remote_vm",
						       susfs_map_pre_remote_vm);
			break;
		default:
			susfs_map_krp_shmem_swap.maxactive = 64;
			ret = susfs_register_kretprobe(
				&susfs_map_krp_shmem_swap, "shmem_swap_usage",
				susfs_map_shmem_swap_entry,
				susfs_map_shmem_swap_ret, sizeof(unsigned long));
			break;
		}
	}

	if (!ret)
		SUSFS_LOGI("sus_map hooks armed\n");
	else if (step > 0)
		susfs_map_unarm(step - 1);

	/*
	 * A failed arm is remembered instead of being retried on every add:
	 * the probes either install or they do not, and userspace must learn
	 * about the failure rather than get a rule that does nothing.
	 */
	WRITE_ONCE(susfs_map_arm_err, ret);
	WRITE_ONCE(susfs_map_armed, true);
	mutex_unlock(&susfs_map_arm_mutex);
	return ret;
}

/* ------------------------------------------------------------------ */
/* userspace command                                                  */
/* ------------------------------------------------------------------ */

void susfs_add_sus_map(void __user **user_info)
{
	struct st_susfs_sus_map info;
	struct path path;
	struct inode *inode;
	int err;

	if (copy_from_user(&info,
			   (struct st_susfs_sus_map __user *)*user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy;
	}

	/*
	 * The name is a fixed size array: the last byte must be NUL or the
	 * userspace string did not fit, in which case kern_path() would walk
	 * past the struct.
	 */
	if (!info.target_pathname[0] ||
	    info.target_pathname[SUSFS_MAX_LEN_PATHNAME - 1]) {
		info.err = -EINVAL;
		goto out_copy;
	}

	if (!READ_ONCE(susfs_map_core_ok)) {
		/* the probes are not registrable on this kernel */
		info.err = -EOPNOTSUPP;
		goto out_copy;
	}

	err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
	if (err) {
		SUSFS_LOGE("failed opening file '%s'\n", info.target_pathname);
		info.err = err;
		goto out_copy;
	}

	inode = d_backing_inode(path.dentry);
	if (!inode || !inode->i_mapping) {
		SUSFS_LOGE("inode || inode->i_mapping is NULL\n");
		info.err = -ENOENT;
		goto out_path_put;
	}

	/*
	 * Arm first, flag second: a rule that was accepted must be one that
	 * can actually be honoured.  Arming itself cannot hide anything (the
	 * probes are no-ops while no inode carries the bit), so the window
	 * between the two steps only means "not hidden yet".
	 */
	err = susfs_map_arm();
	if (err) {
		info.err = err;
		SUSFS_LOGE("failed to arm sus_map, err: %d\n", err);
		goto out_path_put;
	}

	set_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags);
	atomic_inc(&susfs_map_flagged);

	info.err = 0;
	SUSFS_LOGI("pathname: '%s', is flagged as AS_FLAGS_SUS_MAP\n",
		   info.target_pathname);

out_path_put:
	path_put(&path);
out_copy:
	if (copy_to_user(
		    &((struct st_susfs_sus_map __user *)*user_info)->err,
		    &info.err, sizeof(info.err)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_MAP -> ret: %d\n", info.err);
}

/* ------------------------------------------------------------------ */
/* availability / init                                                */
/* ------------------------------------------------------------------ */

/*
 * Same rule as the other phases: never advertise a feature whose hooks are
 * not live.  `susfs_map_arm_err` is only ever written after a real install
 * attempt, so before the first rule this answers from the trial result.
 */
bool susfs_map_available(void)
{
	return READ_ONCE(susfs_map_core_ok) && !READ_ONCE(susfs_map_arm_err);
}

/*
 * Trial-register one probe and remove it again: proves the symbol resolves
 * and is probeable right now, so `available()` can be answered truthfully
 * before the first rule arrives.
 */
static int susfs_map_trial(const char *symbol, kprobe_pre_handler_t pre)
{
	struct kprobe kp;
	int ret;

	ret = susfs_register_kprobe_at(&kp, symbol, pre);
	if (ret) {
		SUSFS_LOGE("%s probe unavailable (%d), sus_map stays off\n",
			   symbol, ret);
		return ret;
	}
	unregister_kprobe(&kp);
	return 0;
}

void susfs_map_init(void)
{
	struct kretprobe krp;
	int ret;

	/*
	 * The range hooks recognise their caller by the walk table pointer,
	 * so those three symbols have to resolve before anything else is
	 * worth trying.
	 */
	susfs_map_smaps_walk_ops = susfs_lookup_symbol("smaps_walk_ops");
	susfs_map_smaps_shmem_walk_ops =
		susfs_lookup_symbol("smaps_shmem_walk_ops");
	susfs_map_pagemap_ops = susfs_lookup_symbol("pagemap_ops");
	if (!susfs_map_smaps_walk_ops || !susfs_map_smaps_shmem_walk_ops ||
	    !susfs_map_pagemap_ops) {
		SUSFS_LOGE("sus_map walk tables unresolved, sus_map stays off\n");
		return;
	}

	if (susfs_map_trial("show_map_vma", susfs_map_pre_map_vma))
		return;
	if (susfs_map_trial("show_smap", susfs_map_pre_smap))
		return;
	if (susfs_map_trial("walk_page_vma", susfs_map_pre_walk_vma))
		return;
	if (susfs_map_trial("walk_page_range", susfs_map_pre_walk_range))
		return;
	if (susfs_map_trial("__access_remote_vm", susfs_map_pre_remote_vm))
		return;

	memset(&krp, 0, sizeof(krp));
	krp.maxactive = 64;
	ret = susfs_register_kretprobe(&krp, "shmem_swap_usage",
				       susfs_map_shmem_swap_entry,
				       susfs_map_shmem_swap_ret,
				       sizeof(unsigned long));
	if (ret) {
		SUSFS_LOGE("shmem_swap_usage probe unavailable (%d), sus_map stays off\n",
			   ret);
		return;
	}
	unregister_kretprobe(&krp);

	WRITE_ONCE(susfs_map_core_ok, true);
	SUSFS_LOGI("sus_map ready, hooks arm on first rule\n");
}
