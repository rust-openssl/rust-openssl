use super::super::*;
use libc::{size_t, time_t};
use std::ffi::{c_char, c_int, c_uchar, c_uint};

#[cfg(ossl400)]
pub type SSL_ech_cb_func = Option<unsafe extern "C" fn(s: *mut SSL, str: *const c_char) -> c_uint>;

#[cfg(ossl400)]
pub const OSSL_ECH_RFC9849_VERSION: u16 = 0xfe0d;
#[cfg(ossl400)]
pub const OSSL_ECH_CURRENT_VERSION: u16 = 0xfe0d;

#[cfg(ossl400)]
pub const OSSL_ECH_FOR_RETRY: c_int = 1;
#[cfg(ossl400)]
pub const OSSL_ECH_NO_RETRY: c_int = 0;

#[cfg(ossl400)]
pub const OSSL_ECHSTORE_LAST: c_int = -1;
#[cfg(ossl400)]
pub const OSSL_ECHSTORE_ALL: c_int = -2;

#[cfg(ossl400)]
pub const SSL_ECH_STATUS_SUCCESS: c_int = 1;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_FAILED: c_int = 0;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_GREASE: c_int = 2;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_GREASE_ECH: c_int = 3;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_BACKEND: c_int = 4;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_BAD_CALL: c_int = -100;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_NOT_TRIED: c_int = -101;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_BAD_NAME: c_int = -102;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_NOT_CONFIGURED: c_int = -103;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_FAILED_ECH: c_int = -105;
#[cfg(ossl400)]
pub const SSL_ECH_STATUS_FAILED_ECH_BAD_NAME: c_int = -106;

#[cfg(ossl400)]
pub const OSSL_HPKE_KEM_ID_P256: u16 = 0x0010;
#[cfg(ossl400)]
pub const OSSL_HPKE_KEM_ID_P384: u16 = 0x0011;
#[cfg(ossl400)]
pub const OSSL_HPKE_KEM_ID_P521: u16 = 0x0012;
#[cfg(ossl400)]
pub const OSSL_HPKE_KEM_ID_X25519: u16 = 0x0020;
#[cfg(ossl400)]
pub const OSSL_HPKE_KEM_ID_X448: u16 = 0x0021;

#[cfg(ossl400)]
pub const OSSL_HPKE_KDF_ID_HKDF_SHA256: u16 = 0x0001;
#[cfg(ossl400)]
pub const OSSL_HPKE_KDF_ID_HKDF_SHA384: u16 = 0x0002;
#[cfg(ossl400)]
pub const OSSL_HPKE_KDF_ID_HKDF_SHA512: u16 = 0x0003;

#[cfg(ossl400)]
pub const OSSL_HPKE_AEAD_ID_AES_GCM_128: u16 = 0x0001;
#[cfg(ossl400)]
pub const OSSL_HPKE_AEAD_ID_AES_GCM_256: u16 = 0x0002;
#[cfg(ossl400)]
pub const OSSL_HPKE_AEAD_ID_CHACHA_POLY1305: u16 = 0x0003;
#[cfg(ossl400)]
pub const OSSL_HPKE_AEAD_ID_EXPORTONLY: u16 = 0xFFFF;

extern "C" {
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char)
        -> *mut OSSL_ECHSTORE;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_free(es: *mut OSSL_ECHSTORE);
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_new_config(
        es: *mut OSSL_ECHSTORE,
        echversion: u16,
        max_name_length: u8,
        public_name: *const c_char,
        suite: OSSL_HPKE_SUITE,
    ) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_write_pem(es: *mut OSSL_ECHSTORE, index: c_int, out: *mut BIO) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_read_echconfiglist(es: *mut OSSL_ECHSTORE, in_: *mut BIO) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_get1_info(
        es: *mut OSSL_ECHSTORE,
        index: c_int,
        loaded_secs: *mut time_t,
        public_name: *mut *mut c_char,
        echconfig: *mut *mut c_char,
        has_private: *mut c_int,
        for_retry: *mut c_int,
    ) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_downselect(es: *mut OSSL_ECHSTORE, index: c_int) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_set1_key_and_read_pem(
        es: *mut OSSL_ECHSTORE,
        priv_: *mut EVP_PKEY,
        in_: *mut BIO,
        for_retry: c_int,
    ) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_read_pem(es: *mut OSSL_ECHSTORE, in_: *mut BIO, for_retry: c_int)
        -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_num_entries(es: *const OSSL_ECHSTORE, numentries: *mut c_int) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_num_keys(es: *mut OSSL_ECHSTORE, numkeys: *mut c_int) -> c_int;
    #[cfg(ossl400)]
    pub fn OSSL_ECHSTORE_flush_keys(es: *mut OSSL_ECHSTORE, age: time_t) -> c_int;

    #[cfg(ossl400)]
    pub fn SSL_CTX_set1_echstore(ctx: *mut SSL_CTX, es: *mut OSSL_ECHSTORE) -> c_int;
    #[cfg(ossl400)]
    pub fn SSL_set1_echstore(s: *mut SSL, es: *mut OSSL_ECHSTORE) -> c_int;
    #[cfg(ossl400)]
    pub fn SSL_CTX_get1_echstore(ctx: *const SSL_CTX) -> *mut OSSL_ECHSTORE;
    #[cfg(ossl400)]
    pub fn SSL_get1_echstore(s: *const SSL) -> *mut OSSL_ECHSTORE;
    #[cfg(ossl400)]
    pub fn SSL_ech_get1_status(
        s: *mut SSL,
        inner_sni: *mut *mut c_char,
        outer_sni: *mut *mut c_char,
    ) -> c_int;
    #[cfg(ossl400)]
    pub fn SSL_ech_set_callback(s: *mut SSL, f: SSL_ech_cb_func);
    #[cfg(ossl400)]
    pub fn SSL_ech_get1_retry_config(
        s: *mut SSL,
        ec: *mut *mut c_uchar,
        eclen: *mut size_t,
    ) -> c_int;
    #[cfg(ossl400)]
    pub fn SSL_CTX_ech_set_callback(ctx: *mut SSL_CTX, f: SSL_ech_cb_func);
    #[cfg(ossl400)]
    pub fn SSL_set1_ech_config_list(ssl: *mut SSL, ecl: *const u8, ecl_len: size_t) -> c_int;
}
