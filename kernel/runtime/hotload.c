/* Post-hotload init API: exposes the internal primitives that a companion
 * module could use to complete KernelSU init when the driver is finitmod'ed
 * long after boot.
 *
 * Historical note: an earlier revision of this fork forced
 * ksu_late_loaded=false so the built-in init path ran, which left the
 * allowlist unloaded, the manager observer dead, no manager scan and
 * boot_completed false -- and a companion module (kernelsu_hotload_init.ko)
 * existed purely to patch those four gaps back in.  The driver now reports
 * the real load timing and takes the late-load path itself, which performs
 * exactly that sequence inside kernelsu_init(); the companion module is no
 * longer needed.  The vtable stays exported so the out-of-tree companion can
 * still be built/loaded for diagnostics, and it remains append-only. */

#include "runtime/hotload.h"

#include "feature/selinux_hide.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "policy/allowlist.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"

static const struct ksu_hotload_api ksu_hotload_api = {
    .struct_size = sizeof(struct ksu_hotload_api),
    .load_allow_list = ksu_load_allow_list,
    .observer_init = ksu_observer_init,
    .stop_input_hook_runtime = ksu_stop_input_hook_runtime,
    .selinux_hide_post_fs_data = ksu_selinux_hide_handle_post_fs_data,
    .track_throne = track_throne,
    .boot_completed = &ksu_boot_completed,
};

const struct ksu_hotload_api *ksu_hotload_api_get(void)
{
    return &ksu_hotload_api;
}
EXPORT_SYMBOL_GPL(ksu_hotload_api_get);
