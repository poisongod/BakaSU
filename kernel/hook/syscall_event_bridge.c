#include "linux/compiler.h"
#include "linux/cred.h"
#include "linux/jump_label.h"
#include "linux/printk.h"
#include "selinux/selinux.h"
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/static_key.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/tp_marker.h"
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "policy/app_profile.h"
#include "sulog/event.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "feature/adb_root.h"

#include "compat/kernel_compat.h"
#include "ksu.h"
#include "manager/manager_identity.h"
#include "supercall/supercall.h"
#include "uapi/supercall.h"

// Legacy prctl cmd values (manager cpp legacy.c); only the version query is
// answered here, everything else just needs the fd installed.
#define KSU_LEGACY_CMD_GET_VERSION 2

static int ksu_handle_init_mark_tracker(const char __user **filename_user)
{
    char path[64];
    unsigned long addr;
    const char __user *fn;
    long ret;

    if (unlikely(!filename_user))
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    ret = strncpy_from_user(path, fn, sizeof(path));
    if (ret < 0)
        return 0;

    path[sizeof(path) - 1] = '\0';
    if (unlikely(strcmp(path, KSUD_PATH) == 0)) {
        pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
        escape_to_root_for_init();
    } else if (likely(strstr(path, "/app_process") == NULL && strstr(path, "/adbd") == NULL &&
                      strstr(path, "/stub_zygote") == NULL)) {
        pr_info("hook_manager: unmark %d exec %s\n", current->pid, path);
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }

    return 0;
}

long  ksu_hook_newfstatat(int orig_nr, const struct pt_regs *regs)
{
    if (!static_branch_unlikely(&ksu_su_compat_enabled))
        return ksu_syscall_table[orig_nr](regs);

    return ksu_handle_stat_sucompat_internal(orig_nr, (struct pt_regs *)regs);
}

long  ksu_hook_faccessat(int orig_nr, const struct pt_regs *regs)
{
    if (!static_branch_unlikely(&ksu_su_compat_enabled))
        return ksu_syscall_table[orig_nr](regs);

    return ksu_handle_faccessat_sucompat_internal(orig_nr, (struct pt_regs *)regs);
}

// there are for tracepoint syscall redirect hook
// It are only support for GKI2 kernel
// I think we no need ifdef 4.3- kernel compatible in there?
extern struct static_key_true ksud_execve_key;

static long  ksu_hook_execve_common(int orig_nr, const struct pt_regs *regs, bool execveat)
{
    const char __user **filename_user =
        execveat ? (const char __user **)&PT_REGS_PARM2(regs) : (const char __user **)&PT_REGS_SYSCALL_PARM1(regs);
    const char __user *const __user *argv_user = execveat ? (const char __user *const __user *)PT_REGS_PARM3(regs) :
                                                            (const char __user *const __user *)PT_REGS_PARM2(regs);
    bool current_is_init = is_init(current_cred());
    struct ksu_sulog_pending_event *pending_root_execve = NULL;
    long ret;

    if (static_branch_unlikely(&ksud_execve_key)) {
        if (execveat) {
            ksu_execveat_hook_ksud(regs);
        } else {
            ksu_execve_hook_ksud(regs);
        }
    }

    if (current_euid().val == 0)
        pending_root_execve = ksu_sulog_capture_root_execve_tracepoint(*filename_user, argv_user, GFP_KERNEL);

    if (current->pid != 1 && current_is_init) {
        ksu_handle_init_mark_tracker(filename_user);
        ret = execveat ? ksu_adb_root_handle_execveat_tracepoint((struct pt_regs *)regs) :
                         ksu_adb_root_handle_execve_tracepoint((struct pt_regs *)regs);
        if (ret) {
            pr_err("adb root failed: %ld\n", ret);
        }
    } else if (static_branch_likely(&ksu_su_compat_enabled)) {
        // Plan B (task #4): if this exec is the manager spawning ksud, hand
        // the fresh image a non-CLOEXEC driver fd -- its zygote seccomp
        // filter blocks the reboot(magic) fallback and the manager's own
        // fd is O_CLOEXEC (never survives exec).  No-op for every other
        // exec (uid/path check inside).
        ksu_hand_fd_for_ksud_exec(*filename_user);
        ret = execveat ? ksu_handle_execveat_sucompat_internal(filename_user, orig_nr, (struct pt_regs *)regs) :
                         ksu_handle_execve_sucompat_internal(filename_user, orig_nr, (struct pt_regs *)regs);
        ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
        return ret;
    }

    ret = ksu_syscall_table[orig_nr](regs);
    ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
    return ret;
}

long  ksu_hook_execve(int orig_nr, const struct pt_regs *regs)
{
    return ksu_hook_execve_common(orig_nr, regs, false);
}

long  ksu_hook_execveat(int orig_nr, const struct pt_regs *regs)
{
    return ksu_hook_execve_common(orig_nr, regs, true);
}

long  ksu_hook_setresuid(int orig_nr, const struct pt_regs *regs)
{
    uid_t old_uid = ksu_get_uid_t(current_uid());
    long ret = ksu_syscall_table[orig_nr](regs);

    if (ret < 0)
        return ret;

    ksu_handle_setuid(ksu_get_uid_t(current_uid()), old_uid);
    return ret;
}

// Active driver-fd hand-off for the manager.  When the manager has no driver
// fd yet (e.g. right after a reinstall: the zygote setresuid window was
// missed), its legacy fallback (manager cpp legacy.c ksuctl) issues
// prctl(KERNEL_SU_OPTION, cmd, ...) as a last-ditch probe.  Recognise that
// magic here and hand the calling manager a CLOEXEC driver fd so its very
// next ksuctl() finds it via scan_driver_fd() and takes the ioctl path.
//
// Identity gate: ksu_is_manager_uid() -- the appId RCU list, populated only
// by throne_tracker's signature-verified crown or by root writing
// ksu_debug_manager_appid.  Same gate as ksu_hand_fd_for_ksud_exec; unknown
// apps fail it and see a plain -EINVAL from the real prctl.
long  ksu_hook_prctl(int orig_nr, const struct pt_regs *regs)
{
    long ret = ksu_syscall_table[orig_nr](regs);
    unsigned long option, cmd;
    void __user *arg1, *arg2, *res;

    option = (unsigned long) PT_REGS_PARM1(regs);
    if (option != KERNEL_SU_OPTION)
        return ret;

    if (!ksu_is_manager_uid(ksu_get_uid_t(current_uid())))
        return ret;

    if (!ksu_current_has_driver_fd()) {
        int fd = ksu_install_fd();
        if (fd >= 0)
            pr_info("active driver fd %d installed for manager prctl (pid %d)\n",
                    fd, current->pid);
    }

    // Answer CMD_GET_VERSION with real data so legacy_get_info() (the jni
    // getVersion fallback) succeeds on this very first call.  Any other cmd
    // only needs the fd installed -- answering e.g. CMD_CHECK_SAFEMODE with
    // the magic would falsely report safe mode.
    cmd = (unsigned long) PT_REGS_PARM2(regs);
    if (cmd == KSU_LEGACY_CMD_GET_VERSION) {
        int version = KERNEL_SU_VERSION;
        int flags = 0;
        int magic = KERNEL_SU_OPTION;

#ifdef MODULE
        flags |= KSU_GET_INFO_FLAG_LKM;
#endif
        if (is_manager())
            flags |= KSU_GET_INFO_FLAG_MANAGER;
        if (ksu_late_loaded)
            flags |= KSU_GET_INFO_FLAG_LATE_LOAD;

        arg1 = (void __user *) PT_REGS_PARM3(regs);
        arg2 = (void __user *) PT_REGS_PARM4(regs);
        res = (void __user *) PT_REGS_PARM5(regs);
        if (arg1)
            copy_to_user(arg1, &version, sizeof(version));
        if (arg2)
            copy_to_user(arg2, &flags, sizeof(flags));
        if (res)
            copy_to_user(res, &magic, sizeof(magic));
    }

    return ret;
}
