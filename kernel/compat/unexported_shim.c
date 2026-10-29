// SPDX-License-Identifier: GPL-2.0-only
/*
 * shims for kernel functions that EXIST on the device (kallsyms) but are not
 * EXPORT_SYMBOL'd -- the module would otherwise fail to resolve at
 * finit_module time (modpost is a no-op without Module.symvers).
 *
 * Each wrapper carries the kernel's EXACT prototype: the indirect call
 * through the function pointer is CFI-checked (CONFIG_CFI_CLANG) against the
 * callee's record, so any deviation panics at load time. The prototype
 * headers pulled in below double as compile-time ABI verification (a
 * conflicting definition would fail the build).
 *
 * Slots are bound by ksu_resolve_unexported() immediately after
 * ksu_init_symbol_resolver() in core/init.c; the NULL guards are belt only
 * (kernelsu_init aborts on resolve failure, so wrappers cannot run unbound).
 *
 * The 7 unexported data symbols use a different scheme and live in
 * compat/unexported_data.h (macro rewrite of the kernel's own extern decls);
 * their slots are bound in the same table below.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/uaccess.h>		/* strncpy_from_unsafe_user */
#include <linux/syslog.h>		/* do_syslog */
#include <linux/fs.h>			/* do_mount, struct super_block */
#include <linux/fs_struct.h>		/* set_fs_pwd */
#include <linux/pid.h>			/* change_pid, enum pid_type */
#include <linux/sched/user.h>		/* alloc_uid, free_uid */
#include <linux/proc_ns.h>		/* ns_get_path */
#include <linux/syscalls.h>		/* ksys_unshare */
#include <linux/task_work.h>		/* task_work_add */
#include <linux/seccomp.h>		/* put_seccomp_filter */
#include <linux/cred.h>
#include <linux/key.h>			/* struct key */
#include <linux/spinlock.h>		/* rwlock_t (tasklist slot type) */
#include <linux/lsm_hooks.h>		/* struct security_hook_heads */
#include <security.h>			/* selinux state-era protos + struct selinux_state */
#include "avc.h"			/* avc_has_perm */
#include "avc_ss.h"			/* avc_ss_reset */
#include "ss/hashtab.h"
#include "ss/avtab.h"
#include "ss/ebitmap.h"
#include "ss/policydb.h"
#include "ss/sidtab.h"
#include "compat/kernel_compat.h"	/* __arm64_sys_* pt_regs externs (ksyscall block) */
#include "compat/unexported_data.h"	/* ksu_g_* externs; macros unused in this TU */
#include "infra/symbol_resolver.h"	/* find_kernel_symbol_exact */

/* Manual externs: no header declares these on 5.4 (same mirrors the module
 * already uses in compat/kernel_compat.c and runtime/boot_event.c). */
extern int install_session_keyring_to_cred(struct cred *cred, struct key *keyring);
extern void ext4_unregister_sysfs(struct super_block *sb);
extern long __arm64_sys_setns(const struct pt_regs *regs);
extern long __arm64_sys_umount(const struct pt_regs *regs);

/* fwd decls for slot types (pointer-only here, no deref) */
struct mm_struct;
struct vfsmount;
struct av_decision;
struct common_audit_data;

/* ---- slot storage: kernel data (holds address-of the real object) ---- */
struct mm_struct *ksu_g_init_mm;
rwlock_t *ksu_g_tasklist_lock;
const struct proc_ns_operations *ksu_g_mntns_operations;
struct vfsmount **ksu_g_selinuxfs_mount;
struct blob_size_offsets *ksu_g_selinux_blob_sizes;
struct selinux_state *ksu_g_selinux_state;
struct security_hook_heads *ksu_g_security_hook_heads;

/* ---- wrappers ----
 * args = (param declarations), call = (argument names); both pre-parenthesised
 * so each is a single macro argument. */
#define KSU_SHIM(ret, name, fail, args, call)				\
	typedef ret (*ksu_shim_##name##_t) args;			\
	static ksu_shim_##name##_t ksu_shim_##name;			\
	ret name args							\
	{								\
		if (unlikely(!ksu_shim_##name)) {			\
			pr_err("ksu: shim %s called unbound\n", #name);	\
			return fail;					\
		}							\
		return ksu_shim_##name call;				\
	}

#define KSU_SHIM_V(name, args, call)					\
	typedef void (*ksu_shim_##name##_t) args;			\
	static ksu_shim_##name##_t ksu_shim_##name;			\
	void name args							\
	{								\
		if (unlikely(!ksu_shim_##name)) {			\
			pr_err("ksu: shim %s called unbound\n", #name);	\
			return;						\
		}							\
		ksu_shim_##name call;					\
	}

/* value-returning */
KSU_SHIM(long, strncpy_from_unsafe_user, -EFAULT,
	 (char *dst, const void __user *unsafe_addr, long count),
	 (dst, unsafe_addr, count))
KSU_SHIM(int, do_syslog, -EINVAL,
	 (int type, char __user *buf, int count, int source),
	 (type, buf, count, source))
KSU_SHIM(long, do_mount, -ENOSYS,
	 (const char *dev_name, const char __user *dir_name,
	  const char *type, unsigned long flags, void *data),
	 (dev_name, dir_name, type, flags, data))
KSU_SHIM(struct user_struct *, alloc_uid, NULL, (kuid_t uid), (uid))
KSU_SHIM(void *, ns_get_path, ERR_PTR(-ENOSYS),
	 (struct path *path, struct task_struct *task,
	  const struct proc_ns_operations *ns),
	 (path, task, ns))
KSU_SHIM(int, ksys_unshare, -EINVAL, (unsigned long unshare_flags),
	 (unshare_flags))
KSU_SHIM(int, task_work_add, -ESRCH,
	 (struct task_struct *task, struct callback_head *twork,
	  bool notify),
	 (task, twork, notify))
KSU_SHIM(int, avc_has_perm, -EACCES,
	 (struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
	  u32 requested, struct common_audit_data *auditdata),
	 (state, ssid, tsid, tclass, requested, auditdata))
KSU_SHIM(int, avc_ss_reset, -ENOSYS,
	 (struct selinux_avc *avc, u32 seqno), (avc, seqno))
KSU_SHIM(int, avtab_alloc, -ENOMEM, (struct avtab *h, u32 nrpts),
	 (h, nrpts))
KSU_SHIM(struct avtab_node *, avtab_insert_nonunique, NULL,
	 (struct avtab *h, struct avtab_key *key, struct avtab_datum *datum),
	 (h, key, datum))
KSU_SHIM(struct avtab_node *, avtab_search_node, NULL,
	 (struct avtab *h, struct avtab_key *key), (h, key))
KSU_SHIM(struct avtab_node *, avtab_search_node_next, NULL,
	 (struct avtab_node *node, int specified), (node, specified))
KSU_SHIM(int, ebitmap_get_bit, -EINVAL,
	 (struct ebitmap *e, unsigned long bit), (e, bit))
KSU_SHIM(int, ebitmap_set_bit, -ENOMEM,
	 (struct ebitmap *e, unsigned long bit, int value), (e, bit, value))
KSU_SHIM(int, hashtab_insert, -ENOMEM,
	 (struct hashtab *h, void *k, void *d), (h, k, d))
KSU_SHIM(void *, hashtab_search, NULL,
	 (struct hashtab *h, const void *k), (h, k))
KSU_SHIM(int, install_session_keyring_to_cred, -ENOMEM,
	 (struct cred *cred, struct key *keyring), (cred, keyring))
KSU_SHIM(int, policydb_load_isids, -EINVAL,
	 (struct policydb *p, struct sidtab *s), (p, s))
KSU_SHIM(int, policydb_read, -EINVAL, (struct policydb *p, void *fp),
	 (p, fp))
KSU_SHIM(int, policydb_write, -EINVAL, (struct policydb *p, void *fp),
	 (p, fp))
KSU_SHIM(int, security_context_str_to_sid, -EINVAL,
	 (struct selinux_state *state, const char *scontext, u32 *sid,
	  gfp_t gfp),
	 (state, scontext, sid, gfp))
KSU_SHIM(int, security_context_to_sid, -EINVAL,
	 (struct selinux_state *state, const char *scontext,
	  u32 scontext_len, u32 *sid, gfp_t gfp),
	 (state, scontext, scontext_len, sid, gfp))
KSU_SHIM(int, security_sid_to_context, -EINVAL,
	 (struct selinux_state *state, u32 sid, char **scontext,
	  u32 *scontext_len),
	 (state, sid, scontext, scontext_len))
KSU_SHIM(long, __arm64_sys_close, -ENOSYS,
	 (const struct pt_regs *regs), (regs))
KSU_SHIM(long, __arm64_sys_setns, -ENOSYS,
	 (const struct pt_regs *regs), (regs))
KSU_SHIM(long, __arm64_sys_umount, -ENOSYS,
	 (const struct pt_regs *regs), (regs))

/* void-returning */
KSU_SHIM_V(set_fs_pwd,
	   (struct fs_struct *fs, const struct path *path), (fs, path))
KSU_SHIM_V(change_pid,
	   (struct task_struct *task, enum pid_type type, struct pid *pid),
	   (task, type, pid))
KSU_SHIM_V(free_uid, (struct user_struct *user), (user))
KSU_SHIM_V(avtab_destroy, (struct avtab *h), (h))
KSU_SHIM_V(ext4_unregister_sysfs, (struct super_block *sb), (sb))
KSU_SHIM_V(put_seccomp_filter, (struct task_struct *tsk), (tsk))
KSU_SHIM_V(policydb_destroy, (struct policydb *p), (p))
KSU_SHIM_V(sidtab_destroy, (struct sidtab *s), (s))
KSU_SHIM_V(selnl_notify_policyload, (u32 seqno), (seqno))
KSU_SHIM_V(security_compute_av_user,
	   (struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
	    struct av_decision *avd),
	   (state, ssid, tsid, tclass, avd))
KSU_SHIM_V(selinux_status_update_policyload,
	   (struct selinux_state *state, int seqno), (state, seqno))

/* ---- resolve table: name -> slot address ---- */
static const struct {
	const char *name;
	void *slot;
} ksu_unres_tbl[] = {
	/* data */
	{ "init_mm", &ksu_g_init_mm },
	{ "tasklist_lock", &ksu_g_tasklist_lock },
	{ "mntns_operations", &ksu_g_mntns_operations },
	{ "selinuxfs_mount", &ksu_g_selinuxfs_mount },
	{ "selinux_blob_sizes", &ksu_g_selinux_blob_sizes },
	{ "selinux_state", &ksu_g_selinux_state },
	{ "security_hook_heads", &ksu_g_security_hook_heads },
	/* functions */
	{ "strncpy_from_unsafe_user", &ksu_shim_strncpy_from_unsafe_user },
	{ "do_syslog", &ksu_shim_do_syslog },
	{ "do_mount", &ksu_shim_do_mount },
	{ "alloc_uid", &ksu_shim_alloc_uid },
	{ "ns_get_path", &ksu_shim_ns_get_path },
	{ "ksys_unshare", &ksu_shim_ksys_unshare },
	{ "task_work_add", &ksu_shim_task_work_add },
	{ "avc_has_perm", &ksu_shim_avc_has_perm },
	{ "avc_ss_reset", &ksu_shim_avc_ss_reset },
	{ "avtab_alloc", &ksu_shim_avtab_alloc },
	{ "avtab_insert_nonunique", &ksu_shim_avtab_insert_nonunique },
	{ "avtab_search_node", &ksu_shim_avtab_search_node },
	{ "avtab_search_node_next", &ksu_shim_avtab_search_node_next },
	{ "ebitmap_get_bit", &ksu_shim_ebitmap_get_bit },
	{ "ebitmap_set_bit", &ksu_shim_ebitmap_set_bit },
	{ "hashtab_insert", &ksu_shim_hashtab_insert },
	{ "hashtab_search", &ksu_shim_hashtab_search },
	{ "install_session_keyring_to_cred",
	  &ksu_shim_install_session_keyring_to_cred },
	{ "policydb_load_isids", &ksu_shim_policydb_load_isids },
	{ "policydb_read", &ksu_shim_policydb_read },
	{ "policydb_write", &ksu_shim_policydb_write },
	{ "security_compute_av_user", &ksu_shim_security_compute_av_user },
	{ "security_context_str_to_sid",
	  &ksu_shim_security_context_str_to_sid },
	{ "security_context_to_sid", &ksu_shim_security_context_to_sid },
	{ "security_sid_to_context", &ksu_shim_security_sid_to_context },
	{ "__arm64_sys_close", &ksu_shim___arm64_sys_close },
	{ "__arm64_sys_setns", &ksu_shim___arm64_sys_setns },
	{ "__arm64_sys_umount", &ksu_shim___arm64_sys_umount },
	{ "set_fs_pwd", &ksu_shim_set_fs_pwd },
	{ "change_pid", &ksu_shim_change_pid },
	{ "free_uid", &ksu_shim_free_uid },
	{ "avtab_destroy", &ksu_shim_avtab_destroy },
	{ "ext4_unregister_sysfs", &ksu_shim_ext4_unregister_sysfs },
	{ "policydb_destroy", &ksu_shim_policydb_destroy },
	{ "sidtab_destroy", &ksu_shim_sidtab_destroy },
	{ "selnl_notify_policyload", &ksu_shim_selnl_notify_policyload },
	{ "put_seccomp_filter", &ksu_shim_put_seccomp_filter },
	{ "selinux_status_update_policyload",
	  &ksu_shim_selinux_status_update_policyload },
};

int ksu_resolve_unexported(void)
{
	size_t i;
	int failed = 0;

	for (i = 0; i < ARRAY_SIZE(ksu_unres_tbl); i++) {
		unsigned long addr =
			find_kernel_symbol_exact(ksu_unres_tbl[i].name);

		if (!addr) {
			pr_err("ksu: symbol %s not found in running kernel\n",
			       ksu_unres_tbl[i].name);
			failed++;
			continue;
		}
		*(void **)ksu_unres_tbl[i].slot = (void *)addr;
	}
	if (failed)
		pr_err("ksu: %d unexported symbol(s) unresolved\n", failed);
	return failed ? -ENOENT : 0;
}
