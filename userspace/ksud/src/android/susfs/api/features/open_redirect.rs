use anyhow::{Result, anyhow};

use crate::android::susfs::{
    api::{
        magic::{CMD_SUSFS_ADD_OPEN_REDIRECT, ERR_CMD_NOT_SUPPORTED, SUSFS_MAX_LEN_PATHNAME},
        susfsctl::{parse_err, susfsctl},
    },
    enums::UidScheme,
    utils::str_to_c_array,
};

#[repr(C)]
struct SusfsOpenRedirect {
    target_pathname: [u8; SUSFS_MAX_LEN_PATHNAME],
    redirected_pathname: [u8; SUSFS_MAX_LEN_PATHNAME],
    uid_scheme: i32,
    err: i32,
}

impl Default for SusfsOpenRedirect {
    fn default() -> Self {
        Self {
            uid_scheme: 0,
            target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
            redirected_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
            err: 0,
        }
    }
}

pub fn add_open_redirect(
    target_path: &str,
    redirected_path: &str,
    uid_scheme: &UidScheme,
) -> Result<()> {
    /*
     * The spelling matters: a rule is keyed on the string the target process
     * uses, so canonicalising here would silently move the rule to a different
     * name (e.g. /system/etc/security/otacerts.zip is a symlink into
     * /my_engineering/..., and a package opening the /system spelling would no
     * longer match).  Both spellings of the same file are accepted by the
     * kernel (it stores the canonical name as an alias), so only require an
     * absolute path here and let the kernel resolve and validate it.
     */
    if !target_path.starts_with('/') {
        return Err(anyhow!("target path must be absolute: {target_path}"));
    }
    if !redirected_path.starts_with('/') {
        return Err(anyhow!("redirect path must be absolute: {redirected_path}"));
    }

    let mut info = SusfsOpenRedirect::default();
    str_to_c_array(target_path, &mut info.target_pathname);
    str_to_c_array(redirected_path, &mut info.redirected_pathname);

    info.uid_scheme = (*uid_scheme) as i32;
    info.err = ERR_CMD_NOT_SUPPORTED;

    susfsctl(CMD_SUSFS_ADD_OPEN_REDIRECT, &mut info);
    parse_err(CMD_SUSFS_ADD_OPEN_REDIRECT, info.err)?;
    Ok(())
}
