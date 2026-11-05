use anyhow::Result;

use crate::android::susfs::{
    api::{
        magic::{
            CMD_SUSFS_ADD_SUS_PATH, CMD_SUSFS_ADD_SUS_PATH_LOOP, ERR_CMD_NOT_SUPPORTED,
            SUSFS_MAX_LEN_PATHNAME,
        },
        susfsctl::{parse_err, susfsctl},
    },
    utils::str_to_c_array,
};

#[repr(C)]
struct SusfsSusPath {
    target_pathname: [u8; SUSFS_MAX_LEN_PATHNAME],
    err: i32,
}

impl Default for SusfsSusPath {
    fn default() -> Self {
        Self {
            target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
            err: 0,
        }
    }
}

pub fn add_sus_path(path: &str, is_loop: bool) -> Result<()> {
    /*
     * No existence check here: the kernel is the authority.  For a plain
     * entry it resolves the path and returns -ENOENT when it does not exist,
     * which is reported back verbatim; for a loop entry a missing path is
     * explicitly legal (the classic use is a directory the app creates
     * later), so pre-checking would reject a request the kernel accepts.
     */
    let mut info = SusfsSusPath::default();
    let magic = match is_loop {
        true => CMD_SUSFS_ADD_SUS_PATH_LOOP,
        false => CMD_SUSFS_ADD_SUS_PATH,
    };
    str_to_c_array(path, &mut info.target_pathname);
    info.err = ERR_CMD_NOT_SUPPORTED;

    susfsctl(magic, &mut info);
    parse_err(magic, info.err)?;
    Ok(())
}
