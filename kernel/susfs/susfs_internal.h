/* SPDX-License-Identifier: GPL-2.0 */
/*
 * susfs_internal.h - private glue shared by the SuSFS LKM sources.
 *
 * Nothing in here is part of the SuSFS userspace ABI: the ABI lives in
 * <linux/susfs.h> (structs + command codes) and <linux/susfs_def.h>
 * (flags / inline helpers).  This header only carries what several of our
 * .c files need to agree on:
 *
 *   - the logging macros (upstream keeps them inside fs/susfs.c because
 *     the whole feature is one file there; we are split up),
 *   - the "does this kernel symbol exist / is it kprobe-able" helper that
 *     every phase uses to register its hooks,
 *   - the per-phase init prototypes.
 */

#ifndef __KSU_SUSFS_INTERNAL_H
#define __KSU_SUSFS_INTERNAL_H

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/sched.h>

#include <linux/susfs.h>
#include <linux/susfs_def.h>

/*
 * Logging.
 *
 * Upstream defaults to "on" so that a freshly loaded module explains
 * itself; userspace can turn it off with `ksud susfs enable_log 0`.  Keep
 * that behaviour, but note that every line carries uid/pid/func, so it is
 * chatty by design.
 *
 * Upstream implements the switch with DEFINE_STATIC_KEY_TRUE().  We use a
 * plain flag instead: every SuSFS command reaches us from the
 * __NR_reboot syscall-table hook, i.e. from an ordinary process context
 * (see supercall/supercall.c), but the command handlers run under the
 * caller's task and may already hold arbitrary locks; toggling a static
 * key takes jump_label_mutex plus cpus_read_lock() and patches text on
 * other CPUs, which is needless work and needless lock-ordering risk for
 * a debugging switch.  A READ_ONCE()/WRITE_ONCE() flag has identical
 * userspace-visible semantics.  The one-off cost is a predictable load
 * where the static key would have patched in a nop.
 */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
extern bool susfs_log_enabled;
#define SUSFS_LOGI(fmt, ...)                                                   \
	do {                                                                   \
		if (READ_ONCE(susfs_log_enabled))                              \
			pr_info("susfs:[%u][%d][%s] " fmt, current_uid().val,  \
				current->pid, __func__, ##__VA_ARGS__);        \
	} while (0)
#define SUSFS_LOGE(fmt, ...)                                                   \
	do {                                                                   \
		if (READ_ONCE(susfs_log_enabled))                              \
			pr_err("susfs:[%u][%d][%s]" fmt, current_uid().val,    \
			       current->pid, __func__, ##__VA_ARGS__);         \
	} while (0)
#else
#define SUSFS_LOGI(fmt, ...)                                                   \
	do {                                                                   \
	} while (0)
#define SUSFS_LOGE(fmt, ...)                                                   \
	do {                                                                   \
	} while (0)
#endif

/*
 * Register a kprobe by symbol name, falling back to the CFI-suffixed
 * variant (`foo$0123abcd...`) when the kernel built `foo` as an indirect
 * call target.  A large part of the fs/proc and fs/notify helpers we hook
 * are static functions reached through function pointers, so their
 * kallsyms entry carries a kCFI type hash and the bare name does not
 * exist.  Returns 0 on success and a negative errno on failure; `kp` must
 * outlive the registration.
 */
int susfs_register_kprobe(struct kprobe *kp, const char *symbol_name,
			  kprobe_pre_handler_t pre,
			  kprobe_post_handler_t post);

/* Same, for kretprobes (entry + return handler). */
int susfs_register_kretprobe(struct kretprobe *krp, const char *symbol_name,
			     kretprobe_handler_t entry,
			     kretprobe_handler_t ret_handler, int data_size);

/*
 * Register by resolved address, following a kCFI jump-table stub to the
 * real body first.  Use this instead of susfs_register_kprobe() whenever
 * the function may also be called directly from inside the kernel.
 */
int susfs_register_kprobe_at(struct kprobe *kp, const char *symbol_name,
			     kprobe_pre_handler_t pre);

/* Resolve a symbol to an address, CFI-suffixed variants included. */
unsigned long susfs_lookup_symbol(const char *symbol_name);

/*
 * Follow a `.cfi_jt` stub (`b <body>`) to the real function body.  Needed
 * whenever a hook must see both direct and indirect callers.  Returns the
 * address unchanged when it is not a stub, 0 when it is not in .text.
 */
unsigned long susfs_unwrap_jump_table(unsigned long addr);

/*
 * First `bl <target>` in [start, start + size); returns the address after
 * the branch (the callee's x30), or 0 when there is none.
 */
unsigned long susfs_find_bl_to(unsigned long start, unsigned long size,
			       unsigned long target);

/* ------------------------------------------------------------------ */
/* per-phase init                                                      */
/* ------------------------------------------------------------------ */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
void susfs_kstat_init(void);
/*
 * True when the core stat() spoof point is known to be installable.  The
 * hooks themselves are armed lazily on the first add_sus_kstat, so this is
 * answered from an init-time trial registration - advertising the feature
 * without it would be a lie.
 */
bool susfs_kstat_available(void);
#else
static inline void susfs_kstat_init(void)
{
}
static inline bool susfs_kstat_available(void)
{
	return false;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
void susfs_uname_init(void);
/*
 * Runtime availability: the syscall table patch can fail (table not
 * resolved, fixmap write refused).  Advertising a feature whose hook is
 * not live would be a lie, so the feature list asks this first.
 */
bool susfs_uname_available(void);
#else
static inline void susfs_uname_init(void)
{
}
static inline bool susfs_uname_available(void)
{
	return false;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
void susfs_cmdline_init(void);
/* Same runtime gate as SPOOF_UNAME: the cmdline_proc_show probe can fail
 * to register, in which case the feature must not be advertised. */
bool susfs_cmdline_available(void);
#else
static inline void susfs_cmdline_init(void)
{
}
static inline bool susfs_cmdline_available(void)
{
	return false;
}
#endif

#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
void susfs_kallsyms_init(void);
/* Gated on the s_show probe actually being registered: kallsyms_op may be
 * missing, or the jump-table entry may not decode. */
bool susfs_kallsyms_available(void);
#else
static inline void susfs_kallsyms_init(void)
{
}
static inline bool susfs_kallsyms_available(void)
{
	return false;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
/*
 * susfs_add_sus_path()/susfs_add_sus_path_loop() are declared in the
 * pristine ABI header (susfs/include/linux/susfs.h) because the supercall
 * dispatcher calls them; only the module-internal entry points live here.
 */
void susfs_path_init(void);
/*
 * Runtime availability, same rule as the other phases: the two probes the
 * open/stat path depends on are trial-registered at init and the flag is
 * cleared again if arming later fails, so the feature list never claims
 * something that is not actually hooked.
 */
bool susfs_path_available(void);
/* Called from susfs_extra_works when SuSFS umounts a package. */
void susfs_path_loop_run(void);
#else
static inline void susfs_path_init(void)
{
}
static inline bool susfs_path_available(void)
{
	return false;
}
static inline void susfs_path_loop_run(void)
{
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
/*
 * susfs_add_sus_map() is declared in the ABI header (the supercall
 * dispatcher calls it); the module-internal entry points live here.
 */
void susfs_map_init(void);
/*
 * Same runtime gate as the other phases: the two /proc probes are
 * trial-registered at init, so this is false only when they cannot be
 * installed at all (or when a real arm attempt failed afterwards).
 */
bool susfs_map_available(void);
#else
static inline void susfs_map_init(void)
{
}
static inline bool susfs_map_available(void)
{
	return false;
}
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
/*
 * susfs_add_open_redirect() itself is declared in the ABI header (the
 * supercall dispatcher calls it); the module-internal entry points live
 * here.
 */
void susfs_open_redirect_init(void);
/*
 * Same runtime gate as the other phases, but stricter: all three hooks
 * (openat replacement, prepend_path display, maps dev/ino columns) are
 * treated as core, so this is false unless every one of them is installed.
 */
bool susfs_open_redirect_available(void);
#else
static inline void susfs_open_redirect_init(void)
{
}
static inline bool susfs_open_redirect_available(void)
{
	return false;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
/*
 * susfs_set_hide_sus_mnts_for_non_su_procs() is declared in the ABI header
 * (the supercall dispatcher calls it); the module-internal entry points live
 * here.
 */
void susfs_mount_init(void);
/*
 * True only when all three parts are usable: the two marking kretprobes
 * (alloc_vfsmnt/clone_mnt) are installed, the four hiding hooks can be
 * installed, and both mnt_id_ida and the ksu SID were resolved.  Mount
 * marking is live as soon as this is true; hiding is armed on request.
 */
bool susfs_mount_available(void);
#else
static inline void susfs_mount_init(void)
{
}
static inline bool susfs_mount_available(void)
{
	return false;
}
#endif

#endif /* __KSU_SUSFS_INTERNAL_H */
