/* Post-hotload init API: exposes the internal primitives that the
 * kernelsu-init-hotload companion module sequences to complete KernelSU init
 * when the driver is finitmod'ed long after boot.  Two things never fire on
 * their own in that scenario: the late-load branch of kernelsu_init() (this
 * fork deliberately forces ksu_late_loaded=false -- rationale in the
 * assignment's comment in core/init.c), and on_post_fs_data()'s trigger
 * (first zygote exec after init second stage, hundreds of seconds before the
 * module load).  Without this table the allowlist stays unloaded, the
 * manager observer is dead, no manager scan runs, and boot_completed stays
 * false -- the manager app then sees a featureless driver.
 *
 * The sequencing itself (ordering, diagnostics, struct_size validation) lives
 * in the companion module so this driver stays close to upstream; only this
 * small api table is added here. */

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
