#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/unistd.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "compat/kernel_compat.h"
#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "hook/syscall_hook.h"
#include "runtime/ksud.h"
#include "manager/manager_identity.h"
#include "klog.h" // IWYU pragma: keep

extern int ksu_dbg_kp_rc;
extern int ksu_dbg_kp_hits;
extern int ksu_dbg_kp_reg;
extern int ksu_dbg_kp_kps;
extern int ksu_dbg_exec_fd;

#define KSU_DRIVER_PERMISSION_SU_SESSION (1UL << 0)

struct ksu_driver_context {
    unsigned long permissions;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    kfree(filp->private_data);
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(filp, cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

static int ksu_install_fd_with_permissions(unsigned int fd_flags, unsigned long permissions)
{
    struct ksu_driver_context *context;
    struct file *filp;
    const char *name;
    int fd;

    // alloc context
    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context)
        return -ENOMEM;

    context->permissions = permissions;
    name = permissions & KSU_DRIVER_PERMISSION_SU_SESSION ? "[ksu_driver_su]" : "[ksu_driver]";

    // Get unused fd
    fd = get_unused_fd_flags(fd_flags);
    if (fd < 0) {
        pr_err("%s: failed to get unused fd\n", __func__);
        kfree(context);
        return fd;
    }

    // Create anonymous inode file
    filp = anon_inode_getfile(name, &anon_ksu_fops, context, O_RDWR);
    if (IS_ERR(filp)) {
        pr_err("%s: failed to create anon inode file\n", __func__);
        put_unused_fd(fd);
        kfree(context);
        return PTR_ERR(filp);
    }

    // Install fd
    fd_install(fd, filp);

    pr_info("ksu fd installed: %d, name: %s, for pid %d\n", fd, name, current->pid);

    return fd;
}

int ksu_install_fd(void)
{
    return ksu_install_fd_with_permissions(O_CLOEXEC, 0);
}

// Non-CLOEXEC variant: used to hand the fd across an exec boundary.
int ksu_install_fd_no_cloexec(void)
{
    return ksu_install_fd_with_permissions(0, 0);
}

// True when the calling task's fdtable already holds a driver fd.  Keeps the
// manager's repeated legacy prctl fallbacks (see ksu_hook_prctl) from
// stacking duplicate fds.
bool ksu_current_has_driver_fd(void)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	unsigned int i;
	bool found = false;

	if (!files)
		return false;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	for (i = 0; i < fdt->max_fds; i++) {
		struct file *f = fdt->fd[i];
		if (f && f->f_op == &anon_ksu_fops) {
			found = true;
			break;
		}
	}
	spin_unlock(&files->file_lock);

	return found;
}

// Hand the driver fd to the about-to-exec ksud image.
//
// Two callers need this, for the same underlying reason (the <5.10
// keep-filter policy): the driver fd a task holds is O_CLOEXEC, so it never
// survives the exec into ksud, and the reboot(magic) fallback is the only
// remaining way in.
//   * the manager spawns ksud / libksud.so (its own fd is O_CLOEXEC too);
//   * the /product/bin/su wrapper execs the ksud copy staged in
//     /data/local/tmp for every non-root `su` caller (shell, allow-listed
//     apps) -- that caller has no driver fd at all.
//
// At sys_enter the current task IS the forked child that is about to become
// ksud; a non-CLOEXEC fd installed now lands in its fdtable and stays after
// exec.  Every exec runs against a fresh forked fdtable, so repeated spawns
// never accumulate fds in the parent.
//
// This deliberately does NOT skip when the task already holds a driver fd:
// that inherited fd is O_CLOEXEC and is closed by this very exec, so
// deduplicating here would hand ksud nothing.
//
// Identity gate: allowed_for_su() -- the manager, or any uid the allow list
// already lets run su (shell included under CONFIG_KSU_DEBUG).  The fd is
// only a handle: every ioctl handler re-checks the caller's uid (perm.c), so
// this grants an allow-listed caller nothing beyond what su already grants
// it, and an unknown app fails the gate and gets nothing.
void ksu_hand_fd_for_ksud_exec(const char __user *filename_user)
{
    char path[256];
    long ret;
    int fd;
    const char *base;

    if (!allowed_for_su())
        return;

    ret = strncpy_from_user(path, untagged_addr((unsigned long)filename_user), sizeof(path));
    if (ret < 0 || ret >= (long)sizeof(path))
        return;
    path[ret] = '\0';

    if (strcmp(path, KSUD_PATH) != 0) {
        // Match the ksud image by basename: the manager execs its bundled
        // libksud.so at <nativeLibraryDir>/libksud.so (the path carries
        // installer random segments), the /product/bin/su and
        // /product/bin/ksud wrappers exec the ksud copy staged in
        // /data/local/tmp.  Basename matching is what keeps this working
        // across staging-path changes; the allowed_for_su() gate above
        // keeps it tight.
        base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (strcmp(base, "libksud.so") != 0 && strcmp(base, "ksud") != 0)
            return;
    }

    fd = ksu_install_fd_no_cloexec();
    ksu_dbg_exec_fd++;
    pr_info("hand driver fd %d to exec'ing %s (pid %d)\n", fd, path, current->pid);
}

int ksu_install_su_fd(void)
{
    // This descriptor must be installed after the exec into ksud.
    return ksu_install_fd_with_permissions(O_CLOEXEC, KSU_DRIVER_PERMISSION_SU_SESSION);
}

bool ksu_is_su_session_fd(const struct file *filp)
{
    const struct ksu_driver_context *context = filp->private_data;

    return context && (context->permissions & KSU_DRIVER_PERMISSION_SU_SESSION);
}

#ifdef CONFIG_KSU_TOOLKIT_SUPPORT
extern int ksu_try_handle_toolkit_cmd(int magic2, unsigned int cmd, void __user **arg);
#endif

#ifdef CONFIG_KSU_SUSFS
extern int ksu_handle_susfs_cmd(unsigned int cmd, void __user **arg);
#endif

// downstream: make sure to pass arg as reference, this can allow us to extend things.
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
    if (magic1 != KSU_INSTALL_MAGIC1)
        return -EINVAL;

#ifdef CONFIG_KSU_DEBUG
    pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1, magic2);
#endif

    // Check if this is a request to install KSU fd
    if (magic2 == KSU_INSTALL_MAGIC2) {
        int fd = ksu_install_fd();
        pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

        if (copy_to_user((int __user *)*arg, &fd, sizeof(fd))) {
            pr_err("install ksu fd reply err\n");
            ksu_close_fd(fd);
        }
        return 0;
    }

    // extensions

#if !defined(CONFIG_KSU_TOOLKIT_SUPPORT) && !defined(CONFIG_KSU_SUSFS)
    return 0;
#endif

    // other sys_reboot extensions are fully require uid 0,
    // so let's check it before
    if (ksu_get_uid_t(current_uid()) != 0)
        return 0;

#ifdef CONFIG_KSU_TOOLKIT_SUPPORT
    if (ksu_try_handle_toolkit_cmd(magic2, cmd, arg))
        return 0;
#endif

#ifdef CONFIG_KSU_SUSFS
    // If magic2 is susfs and current process is root
    if (magic2 == SUSFS_MAGIC) {
        return ksu_handle_susfs_cmd(cmd, arg);
    }
#endif
    return 0;
}

#ifdef CONFIG_KSU_TRACEPOINT_HOOK
/*
 * The reboot magic is intercepted through the syscall table, not a kprobe.
 *
 * A kprobe on __arm64_sys_reboot() runs inside the debug exception, i.e. with
 * IRQs masked and no preemption.  Everything the supercall handlers need is
 * forbidden there:
 *   - register_kprobe()/unregister_kprobe() end up in
 *     aarch64_insn_patch_text() -> stop_machine_cpuslocked(), which needs the
 *     local stopper thread to be scheduled (it cannot be, IRQs are off);
 *   - kern_path()/filename_lookup() take sleeping locks (namei, rename_lock);
 *   - kmalloc(GFP_KERNEL) may schedule under memory pressure.
 * Upstream SuSFS does not have this problem because its patch calls
 * ksu_handle_sys_reboot() from the body of SYSCALL_DEFINE4(reboot), which is
 * ordinary process context.  Replacing the table entry gives us exactly the
 * same context, and BakaSU already patches the table for
 * __NR_init_module/__NR_finit_module/__NR_execve, so the mechanism is proven
 * on this kernel (fixmap + stop_machine, once, at module load - never from a
 * probe).
 *
 * The original entry is still called afterwards.  magic1 is KSU_INSTALL_MAGIC1
 * (0xdeadbeef) here, which the real SYSCALL_DEFINE4(reboot) rejects with
 * -EINVAL before touching anything, so the return value userspace sees stays
 * exactly what it was with the kprobe arrangement.
 */
static syscall_fn_t ksu_sys_reboot_orig;

static long ksu_sys_reboot_hook(const struct pt_regs *regs)
{
    int magic1 = (int)regs->regs[0];
    int magic2 = (int)regs->regs[1];
    unsigned int cmd = (unsigned int)regs->regs[2];
    /* regs[3] is where the syscall ABI keeps the 4th argument.
     * ksu_handle_sys_reboot() only dereferences this slot. */
    void __user **arg = (void __user **)(uintptr_t)&regs->regs[3];

    if (magic1 == KSU_INSTALL_MAGIC1) {
        ksu_dbg_kp_hits++;
        pr_info("KSUDBG reboot_pre m1=0x%x m2=0x%x\n", (unsigned)magic1,
                (unsigned)magic2);
        ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
    }

    return ksu_sys_reboot_orig(regs);
}

/*
 * Backup path for the driver-fd handshake only.
 *
 * The syscall-table hook above is the primary path because it runs in
 * ordinary process context.  It is, however, a single point of failure: if
 * the table patch is refused (read-only mapping, symbol moved, ...) every
 * supercall silently dies and ksud cannot obtain its driver fd at all -
 * which looks exactly like "could not retrieve kernelsu driver fd".
 *
 * So we additionally keep a kprobe on __arm64_sys_reboot(), the arrangement
 * that shipped before the table hook and is proven to work on this kernel.
 * It must not do more than install the fd: kprobe handlers run inside the
 * debug exception with IRQs masked, so the SUSFS commands (which need
 * kern_path()/kmalloc(GFP_KERNEL)/kprobe registration) still go through the
 * table hook exclusively.
 *
 * Both paths can be live at the same time - ksu_sys_reboot_hook() calls the
 * original entry, which is exactly the probed function.  Two guards keep
 * that harmless:
 *   1. only the fd magic is handled here;
 *   2. ksu_current_has_driver_fd() prevents installing a second fd when the
 *      table hook already ran for this very call.
 *
 * Note there is deliberately no "table hook is healthy, skip the probe"
 * early-out: the probe is the only thing that still works when the table
 * patch is silently refused, and that failure mode is indistinguishable
 * from a healthy boot until something asks for a driver fd.
 */
static int ksu_reboot_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
    int magic1, magic2;

    regs = PT_REAL_REGS(regs);
    magic1 = (int)PT_REGS_SYSCALL_PARM1(regs);
    magic2 = (int)PT_REGS_PARM2(regs);

    if (magic1 != KSU_INSTALL_MAGIC1 || magic2 != KSU_INSTALL_MAGIC2)
        return 0;

    if (ksu_current_has_driver_fd())
        return 0;

    ksu_dbg_kp_kps++;
    pr_info("KSUDBG reboot_kp m1=0x%x m2=0x%x pid=%d\n", (unsigned)magic1,
            (unsigned)magic2, current->pid);
    ksu_handle_sys_reboot(magic1, magic2, (unsigned int)PT_REGS_PARM3(regs),
                          (void __user **)(uintptr_t)&PT_REGS_SYSCALL_PARM4(regs));
    return 0;
}

static struct kprobe ksu_reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = ksu_reboot_kp_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
    int rc;

    ksu_supercall_dump_commands();

#ifdef CONFIG_KSU_TRACEPOINT_HOOK
    /* Register the backup first: it has to keep working even when the table
     * patch below is refused or the table is unavailable. */
    rc = register_kprobe(&ksu_reboot_kp);
    ksu_dbg_kp_reg = rc;
    if (rc)
        pr_err("reboot kprobe backup failed: %d\n", rc);
    else
        pr_info("reboot kprobe backup installed\n");

    if (!ksu_syscall_table) {
        ksu_dbg_kp_rc = -ENOENT;
        pr_err("reboot hook: sys_call_table unavailable (kprobe backup only)\n");
        return;
    }

    ksu_syscall_table_hook(__NR_reboot, ksu_sys_reboot_hook, &ksu_sys_reboot_orig);

    /* ksu_syscall_table_hook() ignores the patch result, so read the slot
     * back: a silent failure here would disable every supercall (ksud could
     * not install its driver fd at all). */
    if (!ksu_sys_reboot_orig ||
        READ_ONCE(ksu_syscall_table[__NR_reboot]) != ksu_sys_reboot_hook) {
        ksu_dbg_kp_rc = -EIO;
        pr_err("reboot syscall hook failed (kprobe backup only)\n");
        return;
    }

    ksu_dbg_kp_rc = 0;
    pr_info("reboot syscall hook installed at nr %d (orig %px)\n", __NR_reboot,
            ksu_sys_reboot_orig);
#endif
}

void __exit ksu_supercalls_exit(void)
{
#ifdef CONFIG_KSU_TRACEPOINT_HOOK
    if (ksu_dbg_kp_reg == 0)
        unregister_kprobe(&ksu_reboot_kp);
    ksu_syscall_table_unhook(__NR_reboot);
#endif
    ksu_supercall_cleanup_state();
}
