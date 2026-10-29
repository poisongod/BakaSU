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

#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "compat/kernel_compat.h"
#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "runtime/ksud.h"
#include "manager/manager_identity.h"
#include "klog.h" // IWYU pragma: keep

extern int ksu_dbg_kp_rc;
extern int ksu_dbg_kp_hits;

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

// Hand the driver fd to the about-to-exec ksud image (exec'd by the manager,
// e.g. KsuCli / daemon spawn).  With the <5.10 keep-filter policy the
// manager keeps its zygote seccomp filter, so ksud's reboot(magic) install
// fallback gets SIGSYS, and the fd ksu_handle_setuid installed into the
// manager is O_CLOEXEC so it never survives the child's exec.  Cover it
// here: at sys_enter the current task IS the forked child that is about to
// become ksud; a non-CLOEXEC fd installed now lands in its fdtable and
// stays after exec.  Every exec runs against a fresh forked fdtable, so
// repeated spawns never accumulate fds in the manager itself.
void ksu_hand_fd_for_ksud_exec(const char __user *filename_user)
{
    char path[256];
    long ret;
    int fd;
    const char *base;

    if (!ksu_is_manager_uid(ksu_get_uid_t(current_uid())))
        return;

    ret = strncpy_from_user(path, untagged_addr((unsigned long)filename_user), sizeof(path));
    if (ret < 0 || ret >= (long)sizeof(path))
        return;
    path[ret] = '\0';

    if (strcmp(path, KSUD_PATH) != 0) {
        // The manager's root shell (KsuCli.createRootShell) execs its
        // bundled libksud.so at <nativeLibraryDir>/libksud.so — the path
        // carries installer random segments, so match by basename.  The
        // manager-uid check above keeps this tight: only the manager's own
        // execs of libksud.so / ksud ever hit this.
        base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (strcmp(base, "libksud.so") != 0)
            return;
    }

    fd = ksu_install_fd_no_cloexec();
    pr_info("hand driver fd %d to exec'ing ksud (pid %d)\n", fd, current->pid);
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
// Reboot hook for installing fd
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_SYSCALL_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);
    int cmd = (int)PT_REGS_PARM3(real_regs);
    void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);

    ksu_dbg_kp_hits++;
    pr_info("KSUDBG reboot_pre real=%px m1=0x%x m2=0x%x\n", real_regs,
            (unsigned)magic1, (unsigned)magic2);
    ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
    int rc;

    ksu_supercall_dump_commands();

#ifdef CONFIG_KSU_TRACEPOINT_HOOK
    rc = register_kprobe(&reboot_kp);
    ksu_dbg_kp_rc = rc;
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }
#endif
}

void __exit ksu_supercalls_exit(void)
{
#ifdef CONFIG_KSU_TRACEPOINT_HOOK
    unregister_kprobe(&reboot_kp);
#endif
    ksu_supercall_cleanup_state();
}
