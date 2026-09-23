use super::super::*;
use libc::*;

extern "C" {
    pub fn OSSL_HPKE_CTX_new(
        mode: c_int,
        suite: OSSL_HPKE_SUITE,
        role: c_int,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> *mut OSSL_HPKE_CTX;
    pub fn OSSL_HPKE_CTX_free(ctx: *mut OSSL_HPKE_CTX);
    pub fn OSSL_HPKE_encap(
        ctx: *mut OSSL_HPKE_CTX,
        enc: *mut u8,
        enclen: *mut usize,
        pub_: *const u8,
        publen: usize,
        info: *const u8,
        infolen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_seal(
        ctx: *mut OSSL_HPKE_CTX,
        ct: *mut u8,
        ctlen: *mut usize,
        aad: *const u8,
        aadlen: usize,
        pt: *const u8,
        ptlen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_keygen(
        suite: OSSL_HPKE_SUITE,
        pub_: *mut u8,
        publen: *mut usize,
        priv_: *mut *mut EVP_PKEY,
        ikm: *const u8,
        ikmlen: usize,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> c_int;
    pub fn OSSL_HPKE_decap(
        ctx: *mut OSSL_HPKE_CTX,
        enc: *const u8,
        enclen: usize,
        recippriv: *mut EVP_PKEY,
        info: *const u8,
        infolen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_open(
        ctx: *mut OSSL_HPKE_CTX,
        pt: *mut u8,
        ptlen: *mut usize,
        aad: *const u8,
        aadlen: usize,
        ct: *const u8,
        ctlen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_export(
        ctx: *mut OSSL_HPKE_CTX,
        secret: *mut u8,
        secretlen: usize,
        label: *const u8,
        labellen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_CTX_set1_authpriv(ctx: *mut OSSL_HPKE_CTX, priv_: *mut EVP_PKEY) -> c_int;
    pub fn OSSL_HPKE_CTX_set1_authpub(
        ctx: *mut OSSL_HPKE_CTX,
        pub_: *const u8,
        publen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_CTX_set1_psk(
        ctx: *mut OSSL_HPKE_CTX,
        pskid: *const c_char,
        psk: *const u8,
        psklen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_CTX_set1_ikme(
        ctx: *mut OSSL_HPKE_CTX,
        ikme: *const u8,
        ikmelen: usize,
    ) -> c_int;
    pub fn OSSL_HPKE_CTX_set_seq(ctx: *mut OSSL_HPKE_CTX, seq: u64) -> c_int;
    pub fn OSSL_HPKE_CTX_get_seq(ctx: *mut OSSL_HPKE_CTX, seq: *mut u64) -> c_int;
    pub fn OSSL_HPKE_suite_check(suite: OSSL_HPKE_SUITE) -> c_int;
    pub fn OSSL_HPKE_get_grease_value(
        suite_in: *const OSSL_HPKE_SUITE,
        suite: *mut OSSL_HPKE_SUITE,
        enc: *mut u8,
        enclen: *mut usize,
        ct: *mut u8,
        ctlen: usize,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> c_int;
    pub fn OSSL_HPKE_str2suite(str_: *const c_char, suite: *mut OSSL_HPKE_SUITE) -> c_int;
    pub fn OSSL_HPKE_get_ciphertext_size(suite: OSSL_HPKE_SUITE, clearlen: usize) -> usize;
    pub fn OSSL_HPKE_get_public_encap_size(suite: OSSL_HPKE_SUITE) -> usize;
    pub fn OSSL_HPKE_get_recommended_ikmelen(suite: OSSL_HPKE_SUITE) -> usize;
}
