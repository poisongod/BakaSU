/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Indirection for kernel data symbols that exist on the device but are not
 * EXPORT_SYMBOL'd, so we cannot bind them as UND.
 *
 * The #defines below rewrite the kernel's own `extern T sym;' declarations
 * (sched/signal.h -> tasklist_lock, proc_ns.h -> mntns_operations, objsec.h ->
 * selinux_blob_sizes, ...) into `extern T (*ksu_g_sym);' pointer variables.
 * ksu_resolve_unexported() (compat/unexported_shim.c) then binds each pointer
 * to the real object address found via kallsyms, before any consumer runs.
 *
 * MUST be the first #include of every consuming TU: the macros have to be
 * active before any kernel header parses the declarations they rewrite.
 */
#ifndef __KSU_UNEXPORTED_DATA_H
#define __KSU_UNEXPORTED_DATA_H

/*
 * selinux_state / security_hook_heads cannot use the macro trick: their type
 * names are identical to the variable names (`struct selinux_state' /
 * `struct security_hook_heads'), so a macro would rewrite the type as well.
 * Call sites are sed'd to use ksu_g_* directly instead.
 */
struct selinux_state;
struct security_hook_heads;
extern struct selinux_state *ksu_g_selinux_state;
extern struct security_hook_heads *ksu_g_security_hook_heads;

#define init_mm (*ksu_g_init_mm)
#define tasklist_lock (*ksu_g_tasklist_lock)
#define mntns_operations (*ksu_g_mntns_operations)
#define selinuxfs_mount (*ksu_g_selinuxfs_mount)
#define selinux_blob_sizes (*ksu_g_selinux_blob_sizes)

#endif /* __KSU_UNEXPORTED_DATA_H */
