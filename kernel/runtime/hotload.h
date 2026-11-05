#ifndef __KSU_H_HOTLOAD
#define __KSU_H_HOTLOAD

#include <linux/types.h>

/* Vtable handed to the kernelsu-init-hotload companion module.  Append-only
 * evolution: never reorder/remove fields; the companion validates
 * struct_size == sizeof(struct ksu_hotload_api) on its side before
 * sequencing anything, so a size mismatch fails safe. */
struct ksu_hotload_api {
    u32 struct_size;
    /* policy/allowlist.h */
    void (*load_allow_list)(void);
    /* manager/manager_observer.h */
    int (*observer_init)(void);
    /* runtime/ksud.h -- input-hook teardown step from on_post_fs_data() */
    void (*stop_input_hook_runtime)(void);
    /* feature/selinux_hide.h */
    void (*selinux_hide_post_fs_data)(void);
    /* manager/throne_tracker.h -- flags: TRACK_THRONE_* */
    void (*track_throne)(unsigned int flags);
    /* runtime/ksud_boot.h -- companion sets this true after sequencing */
    bool *boot_completed;
};

const struct ksu_hotload_api *ksu_hotload_api_get(void);

#endif
