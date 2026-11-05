// SPDX-License-Identifier: GPL-2.0
/*
 * susfs.c - SuSFS for KernelSU, LKM (loadable module) edition.
 *
 * Upstream SuSFS is a *kernel patch*: it edits ~25 files (fs/namei.c,
 * fs/namespace.c, the fs/proc and security/selinux directories, ...) and
 * drops fs/susfs.c into the tree.  We cannot patch the kernel here: the
 * boot image is stock and locked, the module is insmod'ed after the fact.
 *
 * So this file is a port of upstream fs/susfs.c where every former
 * "call site inside the kernel" is replaced by a kprobe/kretprobe
 * registered from susfs_hooks.c.  The userspace ABI (command codes,
 * struct layouts, err semantics) is kept bit-identical, so the stock
 * `ksud susfs ...` commands and the BakaSU manager work unchanged.
 *
 * Design rule for this file: NEVER report a feature as working when it
 * is not.  `susfs_get_enabled_features()` is driven purely by the
 * CONFIG_KSU_SUSFS_* macros, and a macro is only defined once the
 * corresponding hook set is actually implemented and tested.  Commands
 * that are dispatched unconditionally but not implemented yet answer
 * ERR_CMD_NOT_SUPPORTED (126), which userspace renders as
 * "Unsupported SuSFS command: 0x...".
 *
 * Implementation status (keep in sync with docs/susfs-lkm-feasibility.md).
 * Every entry below is wired here, and every one except the last is a real
 * implementation with a defined CONFIG_KSU_SUSFS_* macro - i.e. exactly the
 * set `susfs_get_enabled_features()` reports:
 *
 *   version / variant / enabled_features / enable_log        DONE
 *   SUS_KSTAT   susfs_kstat.c        vfs_getattr_nosec/vfs_statfs kretprobes,
 *                                    show_vma_header_prefix, seq_printf.
 *                                    fdinfo has no "ino:" line on this
 *                                    kernel (fs/proc/fd.c prints pos/flags/
 *                                    mnt_id only) and mnt_id already comes
 *                                    from SUS_MOUNT's fake id, so there is
 *                                    no fdinfo site to hook - upstream has
 *                                    nothing to hide there either.
 *   SUS_PATH    susfs_path.c         inode bit + 12 choke points (open, delete,
 *                                    create, link, chmod, faccessat, readdir)
 *   SUS_MOUNT   susfs_mount.c        IDA-based fake mnt_id + /proc hides
 *   SUS_MAP     susfs_map.c          inode bit + 6 choke points: show_map_vma,
 *                                    show_smap, walk_page_vma (smaps_rollup),
 *                                    walk_page_range (pagemap),
 *                                    __access_remote_vm (/proc/pid/mem) and a
 *                                    shmem_swap_usage kretprobe for rollup
 *                                    Swap.  Deliberate gaps: map_files and
 *                                    numa_maps (see susfs_map.c).
 *   OPEN_REDIRECT susfs_open_redirect.c  __NR_openat hook + prepend_path and
 *                                    show_vma_header_prefix probes
 *   SPOOF_UNAME susfs_uname.c        __NR_uname syscall table hook
 *   SPOOF_CMDLINE_OR_BOOTCONFIG susfs_cmdline.c  cmdline_proc_show kprobe
 *                                    (this kernel has no CONFIG_BOOT_CONFIG,
 *                                    so /proc/bootconfig does not exist and
 *                                    only the cmdline half can apply)
 *   HIDE_KSU_SUSFS_SYMBOLS susfs_kallsyms.c  s_show kprobe
 *
 *   avc_log_spoofing                                     NOT IMPLEMENTED
 *
 * `ENABLE_AVC_LOG_SPOOFING` is the one command with no macro: it is matched
 * in the dispatcher and leaves `err` untouched, so userspace keeps its
 * ERR_CMD_NOT_SUPPORTED initial value and prints "Unsupported SuSFS
 * command: 0x60010".  That is the intended, honest answer.
 */

#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "susfs_internal.h"
#include "ksu.h"

/*
 * The logging macros live in susfs_internal.h because every SuSFS source
 * file has to agree on them.  The flag itself is defined here, once.
 */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
bool susfs_log_enabled = true;
#endif

/*
 * Every handler receives `void __user **user_info`: the address of the
 * userspace pointer, i.e. userspace passed the address of its own struct
 * as the `arg` of reboot(2).  Upstream writes the result back into the
 * struct's `err` field (or the whole struct) and leaves the syscall's
 * return value at 0; the errno travels *inside* the struct.  Keep that.
 */

/* ------------------------------------------------------------------ */
/* log control                                                         */
/* ------------------------------------------------------------------ */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_enable_log(void __user **user_info)
{
	struct st_susfs_log info = { 0 };

	if (copy_from_user(&info, (struct st_susfs_log __user *)*user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (info.enabled) {
		WRITE_ONCE(susfs_log_enabled, true);
	} else {
		WRITE_ONCE(susfs_log_enabled, false);
	}

	info.err = 0;
out:
	if (copy_to_user((struct st_susfs_log __user *)*user_info, &info,
			 sizeof(info)))
		info.err = -EFAULT;
	pr_info("susfs: CMD_SUSFS_ENABLE_LOG -> ret: %d\n", info.err);
}
#endif /* CONFIG_KSU_SUSFS_ENABLE_LOG */

/* ------------------------------------------------------------------ */
/* show version / variant / enabled features                           */
/* ------------------------------------------------------------------ */
void susfs_show_version(void __user **user_info)
{
	struct st_susfs_version info = { 0 };

	if (copy_from_user(&info, (struct st_susfs_version __user *)*user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	strscpy(info.susfs_version, SUSFS_VERSION, SUSFS_MAX_VERSION_BUFSIZE - 1);
	info.err = 0;
out:
	if (copy_to_user((struct st_susfs_version __user *)*user_info, &info,
			 sizeof(info)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_SHOW_VERSION -> ret: %d\n", info.err);
}

void susfs_show_variant(void __user **user_info)
{
	struct st_susfs_variant info = { 0 };

	if (copy_from_user(&info, (struct st_susfs_variant __user *)*user_info,
			   sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	strscpy(info.susfs_variant, SUSFS_VARIANT, SUSFS_MAX_VARIANT_BUFSIZE - 1);
	info.err = 0;
out:
	if (copy_to_user((struct st_susfs_variant __user *)*user_info, &info,
			 sizeof(info)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", info.err);
}

static int copy_config_to_buf(const char *config_string, char *buf_ptr,
			      size_t *copied_size, size_t bufsize)
{
	size_t tmp_size = strlen(config_string);

	*copied_size += tmp_size;
	if (*copied_size >= bufsize) {
		SUSFS_LOGE("bufsize is not big enough to hold the string.\n");
		return -EINVAL;
	}
	memcpy(buf_ptr, config_string, tmp_size);
	return 0;
}

/*
 * The advertised feature list is compiled in, not probed: a macro is
 * only defined for features whose hooks are live.  This is what makes
 * the manager's "enabled features" panel trustworthy.
 */
void susfs_get_enabled_features(void __user **user_info)
{
	struct st_susfs_enabled_features *info;
	char *buf_ptr = NULL;
	size_t copied_size = 0;
	int err = 0;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		if (copy_to_user(
			    &((struct st_susfs_enabled_features __user *)*user_info)
				     ->err,
			    &err, sizeof(err)))
			err = -EFAULT;
		SUSFS_LOGI("CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", err);
		return;
	}

	if (copy_from_user(info,
			   (struct st_susfs_enabled_features __user *)*user_info,
			   sizeof(*info))) {
		info->err = -EFAULT;
		goto out;
	}

	buf_ptr = info->enabled_features;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	if (susfs_path_available()) {
		info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_PATH\n",
					       buf_ptr, &copied_size,
					       SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	if (susfs_kstat_available()) {
		info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_KSTAT\n",
					       buf_ptr, &copied_size,
					       SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (susfs_uname_available()) {
		info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SPOOF_UNAME\n",
					       buf_ptr, &copied_size,
					       SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_ENABLE_LOG\n", buf_ptr,
				       &copied_size,
				       SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err)
		goto out;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	if (susfs_kallsyms_available()) {
		info->err = copy_config_to_buf(
			"CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS\n", buf_ptr,
			&copied_size, SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (susfs_cmdline_available()) {
		info->err = copy_config_to_buf(
			"CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n", buf_ptr,
			&copied_size, SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	if (susfs_open_redirect_available()) {
		info->err = copy_config_to_buf(
			"CONFIG_KSU_SUSFS_OPEN_REDIRECT\n", buf_ptr, &copied_size,
			SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	if (susfs_map_available()) {
		info->err = copy_config_to_buf(
			"CONFIG_KSU_SUSFS_SUS_MAP\n", buf_ptr, &copied_size,
			SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (susfs_mount_available()) {
		info->err = copy_config_to_buf(
			"CONFIG_KSU_SUSFS_SUS_MOUNT\n", buf_ptr, &copied_size,
			SUSFS_ENABLED_FEATURES_SIZE);
		if (info->err)
			goto out;
		buf_ptr = info->enabled_features + copied_size;
	}
#endif

	info->err = 0;
out:
	if (copy_to_user((struct st_susfs_enabled_features __user *)*user_info,
			 info, sizeof(*info)))
		info->err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", info->err);
	kfree(info);
}

/* ------------------------------------------------------------------ */
/* not implemented yet - answer honestly                               */
/* ------------------------------------------------------------------ */
/*
 * AVC log spoofing needs the security/selinux/avc.c hook
 * (avc_audit_pre_callback rewrites `avc->a->selinux_audit_data`).
 * Until that kprobe exists, refuse the command instead of pretending.
 */
void susfs_set_avc_log_spoofing(void __user **user_info)
{
	int err = ERR_CMD_NOT_SUPPORTED;

	if (copy_to_user(
		    &((struct st_susfs_avc_log_spoofing __user *)*user_info)->err,
		    &err, sizeof(err)))
		err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING -> unsupported (%d)\n",
		   err);
}

/*
 * Upstream starts this from on_boot_completed(); our module is loaded
 * long after that, and in late-load mode dispatch.c never reaches the
 * call site at all.  The monitor only feeds SUS_PATH with the
 * /sdcard/Android subdirectory paths, so it stays inert until phase 3.
 */
void susfs_start_sdcard_monitor_fn(void)
{
	SUSFS_LOGI("sdcard monitor not started (sus_path not implemented yet)\n");
}

/*
 * Deferred SuSFS work.  feature/kernel_umount.c schedules this right after
 * it has umounted a package (and marked the calling task with
 * TIF_PROC_UMOUNTED) instead of doing the work inline, so the setresuid()
 * path is not slowed down and cannot be used as a timing side channel.
 *
 * The only consumer today is SUS_PATH: loop entries name paths that may
 * appear at any time, and this is the point where they are re-resolved.
 */
struct work_struct susfs_extra_works;

static void susfs_run_extra_works(struct work_struct *work)
{
	if (!ksu_cred)
		return;
	susfs_path_loop_run();
}

/*
 * Called by the KernelSU core at module init.  Kept as the single place
 * where later phases register their kprobes, so the core never has to
 * know which hooks exist.
 */
void susfs_init(void)
{
	pr_info("susfs: %s (%s) lkm edition, features:"
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		" enable_log"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		" sus_kstat"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		" sus_path"
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		" spoof_uname"
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		" spoof_cmdline"
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		" hide_symbols"
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		" open_redirect"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		" sus_map"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		" sus_mount"
#endif
		"\n",
		SUSFS_VERSION, SUSFS_VARIANT);

	SUSFS_LOGI("Initializing susfs_extra_works\n");
	INIT_WORK(&susfs_extra_works, susfs_run_extra_works);

	susfs_kstat_init();
	susfs_path_init();
	susfs_uname_init();
	susfs_cmdline_init();
	susfs_kallsyms_init();
	susfs_open_redirect_init();
	susfs_map_init();
	susfs_mount_init();
}
