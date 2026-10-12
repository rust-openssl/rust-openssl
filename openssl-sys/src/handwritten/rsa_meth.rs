use super::super::*;
use libc::*;

#[cfg(ossl110)]
extern "C" {
    pub fn RSA_meth_new(name: *const c_char, flags: i32) -> *mut RSA_METHOD;

    pub fn RSA_meth_free(meth: *mut RSA_METHOD);

    pub fn RSA_meth_dup(meth: *const RSA_METHOD) -> *mut RSA_METHOD;

    pub fn RSA_meth_get0_name(meth: *const RSA_METHOD) -> *const c_char;
    pub fn RSA_meth_set1_name(meth: *mut RSA_METHOD, name: *const c_char) -> i32;

    pub fn RSA_meth_get_flags(meth: *const RSA_METHOD) -> i32;
    pub fn RSA_meth_set_flags(meth: *mut RSA_METHOD, flags: i32) -> i32;

    pub fn RSA_meth_get0_app_data(meth: *const RSA_METHOD) -> *mut c_void;
    pub fn RSA_meth_set0_app_data(meth: *mut RSA_METHOD, app_data: *mut c_void) -> i32;

    pub fn RSA_meth_set_pub_enc(
        rsa: *mut RSA_METHOD,
        pub_enc: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> i32;

    pub fn RSA_meth_set_pub_dec(
        rsa: *mut RSA_METHOD,
        pub_dec: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> i32;

    pub fn RSA_meth_set_priv_enc(
        rsa: *mut RSA_METHOD,
        priv_enc: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> i32;
    pub fn RSA_meth_set_priv_dec(
        rsa: *mut RSA_METHOD,
        priv_dec: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> i32;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_mod_exp(
        rsa: *mut RSA_METHOD,
        mod_exp: Option<
            unsafe extern "C" fn(
                r0: *mut BIGNUM,
                i: *const BIGNUM,
                rsa: *mut RSA,
                ctx: *mut BN_CTX,
            ) -> i32,
        >,
    ) -> i32;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_bn_mod_exp(
        rsa: *mut RSA_METHOD,
        bn_mod_exp: Option<
            unsafe extern "C" fn(
                r: *mut BIGNUM,
                a: *const BIGNUM,
                p: *const BIGNUM,
                m: *const BIGNUM,
                ctx: *mut BN_CTX,
                m_ctx: *mut BN_MONT_CTX,
            ) -> i32,
        >,
    ) -> i32;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_init(
        rsa: *mut RSA_METHOD,
        init: Option<unsafe extern "C" fn(rsa: *mut RSA) -> i32>,
    ) -> i32;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_finish(
        rsa: *mut RSA_METHOD,
        finish: Option<unsafe extern "C" fn(rsa: *mut RSA) -> i32>,
    ) -> i32;

    pub fn RSA_meth_set_sign(
        rsa: *mut RSA_METHOD,
        sign: Option<
            unsafe extern "C" fn(
                _type: i32,
                m: *const u8,
                m_length: u32,
                sigret: *mut u8,
                siglen: *mut u32,
                rsa: *const RSA,
            ) -> i32,
        >,
    ) -> i32;

    pub fn RSA_meth_set_verify(
        rsa: *mut RSA_METHOD,
        verify: Option<
            unsafe extern "C" fn(
                dtype: i32,
                m: *const u8,
                m_length: u32,
                sigbuf: *const u8,
                siglen: u32,
                rsa: *const RSA,
            ) -> i32,
        >,
    ) -> i32;

    pub fn RSA_meth_set_keygen(
        rsa: *mut RSA_METHOD,
        keygen: Option<
            unsafe extern "C" fn(
                rsa: *mut RSA,
                bits: i32,
                e: *mut BIGNUM,
                cb: *mut BN_GENCB,
            ) -> i32,
        >,
    ) -> i32;

    #[cfg(ossl111)]
    pub fn RSA_meth_set_multi_prime_keygen(
        meth: *mut RSA_METHOD,
        keygen: Option<
            unsafe extern "C" fn(
                rsa: *mut RSA,
                bits: i32,
                primes: i32,
                e: *mut BIGNUM,
                cb: *mut BN_GENCB,
            ) -> i32,
        >,
    ) -> i32;
}
