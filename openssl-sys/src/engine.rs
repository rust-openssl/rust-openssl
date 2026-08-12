use crate::{
    stack_st_X509, stack_st_X509_NAME, CRYPTO_EX_DATA, ENGINE, EVP_PKEY, SSL, UI, UI_METHOD, X509,
};
use libc::*;

extern "C" {
    pub fn ENGINE_load_builtin_engines();
    pub fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;

    pub fn ENGINE_new() -> *mut ENGINE;
    pub fn ENGINE_init(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    pub fn ENGINE_free(e: *mut ENGINE) -> c_int;

    pub fn ENGINE_ctrl_cmd(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        i: c_long,
        p: *mut c_void,
        f: Option<unsafe extern "C" fn()>,
        cmd_optional: c_int,
    ) -> c_int;
    pub fn ENGINE_ctrl_cmd_string(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        arg: *const c_char,
        cmd_optional: c_int,
    ) -> c_int;

    pub fn ENGINE_load_private_key(
        e: *mut ENGINE,
        key_id: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn ENGINE_load_public_key(
        e: *mut ENGINE,
        key_id: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut EVP_PKEY;
    pub fn ENGINE_load_ssl_client_cert(
        e: *mut ENGINE,
        ssl: *mut SSL,
        ca_dn: *mut stack_st_X509_NAME,
        pcert: *mut *mut X509,
        ppkey: *mut *mut EVP_PKEY,
        pother: *mut *mut stack_st_X509,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> c_int;
}
