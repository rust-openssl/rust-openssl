//! RSA Methods
//!
//! The [`RsaMethod`] type is a structure used for the provisioning of custom RSA implementations.
//! It provides a set of functions used by OpenSSL for the implementation of the various RSA
//! capabilities. See the wrapper's [RSA](/rsa) documentation, or the manual's documentation
//! [`RSA_METHOD`](https://www.openssl.org/docs/man1.1.1/man3/RSA_meth_new.html) for more details.

use crate::error::ErrorStack;
use crate::{cvt, cvt_p, cvt_p_const};
use ffi::{BIGNUM, BN_CTX, BN_GENCB, BN_MONT_CTX, RSA};
use openssl_macros::corresponds;
use std::ffi::{c_void, CStr, CString};

pub struct RsaMethod(*mut ffi::RSA_METHOD);

impl RsaMethod {
    /// Creates a new `RSA_METHOD` structure.
    #[corresponds(RSA_meth_new)]
    #[inline]
    pub fn new(name: &str, flags: i32) -> Result<Self, ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            let ptr = cvt_p(ffi::RSA_meth_new(name.as_ptr(), flags))?;
            Ok(RsaMethod::from_ptr(ptr))
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::RSA_METHOD {
        self.0
    }

    pub fn from_ptr(ptr: *mut ffi::RSA_METHOD) -> RsaMethod {
        RsaMethod(ptr)
    }

    #[corresponds(RSA_meth_dup)]
    #[inline]
    fn duplicate(&self) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::RSA_meth_dup(self.as_ptr()))?;
            Ok(RsaMethod::from_ptr(ptr))
        }
    }

    #[corresponds(RSA_meth_get0_name)]
    #[inline]
    pub fn get_name(&self) -> Result<String, ErrorStack> {
        unsafe {
            let name = cvt_p_const(ffi::RSA_meth_get0_name(self.as_ptr()))?;
            Ok(CStr::from_ptr(name).to_str().unwrap().to_owned())
        }
    }

    #[corresponds(RSA_meth_set1_name)]
    #[inline]
    pub fn set_name(&self, name: &str) -> Result<(), ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            cvt(ffi::RSA_meth_set1_name(self.as_ptr(), name.as_ptr()))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_get_flags)]
    #[inline]
    pub fn get_flags(&self) -> Result<i32, ErrorStack> {
        let flags = unsafe { cvt(ffi::RSA_meth_get_flags(self.as_ptr()))? };
        Ok(flags)
    }

    #[corresponds(RSA_meth_set_flags)]
    #[inline]
    pub fn set_flags(&self, flags: i32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_flags(self.as_ptr(), flags))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_get0_app_data)]
    #[inline]
    pub fn get_app_data(&self) -> Result<*mut c_void, ErrorStack> {
        let app_data: *mut c_void = unsafe { ffi::RSA_meth_get0_app_data(self.as_ptr()) };
        Ok(app_data)
    }

    /// # Safety
    ///
    /// This function allows you to pass whatever pointer you want into your RSA_METHOD. User
    /// discretion is advised.
    #[corresponds(RSA_meth_set0_app_data)]
    #[inline]
    pub unsafe fn set_app_data(&self, app_data: *mut c_void) -> Result<(), ErrorStack> {
        cvt(ffi::RSA_meth_set0_app_data(self.as_ptr(), app_data))?;
        Ok(())
    }

    #[corresponds(RSA_meth_set_pub_enc)]
    #[inline]
    pub fn set_pub_enc(
        &self,
        pub_enc: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_pub_enc(self.as_ptr(), pub_enc))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_pub_dec)]
    #[inline]
    pub fn set_pub_dec(
        &self,
        pub_dec: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_pub_dec(self.as_ptr(), pub_dec))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_priv_enc)]
    #[inline]
    pub fn set_priv_enc(
        &self,
        priv_enc: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_priv_enc(self.as_ptr(), priv_enc))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_priv_dec)]
    #[inline]
    pub fn set_priv_dec(
        &self,
        priv_dec: Option<
            unsafe extern "C" fn(
                flen: i32,
                from: *const u8,
                to: *mut u8,
                rsa: *mut RSA,
                padding: i32,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_priv_dec(self.as_ptr(), priv_dec))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_mod_exp)]
    #[inline]
    pub fn set_mod_exp(
        &self,
        mod_exp: Option<
            unsafe extern "C" fn(
                r0: *mut BIGNUM,
                i: *const BIGNUM,
                rsa: *mut RSA,
                ctx: *mut BN_CTX,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_mod_exp(self.as_ptr(), mod_exp))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_bn_mod_exp)]
    #[inline]
    pub fn set_bn_mod_exp(
        &self,
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
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_bn_mod_exp(self.as_ptr(), bn_mod_exp))?;
        }
        Ok(())
    }

    #[corresponds(RSA_met_set_init)]
    #[inline]
    pub fn set_init(
        &self,
        init: Option<unsafe extern "C" fn(rsa: *mut RSA) -> i32>,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_init(self.as_ptr(), init))?;
        }
        Ok(())
    }

    #[corresponds(RSA_met_set_finish)]
    #[inline]
    pub fn set_finish(
        &self,
        finish: Option<unsafe extern "C" fn(rsa: *mut RSA) -> i32>,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_finish(self.as_ptr(), finish))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_sign)]
    #[inline]
    pub fn set_sign(
        &self,
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
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_sign(self.as_ptr(), sign))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_verify)]
    #[inline]
    pub fn set_verify(
        &self,
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
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_verify(self.as_ptr(), verify))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_keygen)]
    #[inline]
    pub fn set_keygen(
        &self,
        keygen: Option<
            unsafe extern "C" fn(
                rsa: *mut RSA,
                bits: i32,
                e: *mut BIGNUM,
                cb: *mut BN_GENCB,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_keygen(self.as_ptr(), keygen))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_multi_prime_keygen)]
    #[inline]
    #[cfg(ossl111)]
    pub fn set_multi_prime_keygen(
        &self,
        keygen: Option<
            unsafe extern "C" fn(
                rsa: *mut RSA,
                bits: i32,
                primes: i32,
                e: *mut BIGNUM,
                cb: *mut BN_GENCB,
            ) -> i32,
        >,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_multi_prime_keygen(self.as_ptr(), keygen))?;
        }
        Ok(())
    }
}

impl Drop for RsaMethod {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_meth_free(self.as_ptr());
        }
    }
}

impl Clone for RsaMethod {
    fn clone(&self) -> Self {
        self.duplicate().unwrap()
    }
}

#[cfg(test)]
#[cfg(ossl111)]
mod test {
    use super::*;

    #[test]
    fn new() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn clone() {
        let rsa_method = RsaMethod::new("TEST METHOD", 0);
        drop(rsa_method.clone());
    }

    #[test]
    fn name_change() {
        let initial_name = "INITIAL NAME";
        let rsa_method = RsaMethod::new(initial_name, 0);
        assert!(rsa_method.is_ok());

        let rsa_method = rsa_method.unwrap();

        let expected_name = rsa_method.get_name().unwrap();
        assert_eq!(initial_name, expected_name);

        let updated_name = "UPDATED NAME";
        assert!(rsa_method.set_name(updated_name).is_ok());
        assert!(rsa_method.get_name().is_ok());
        assert_eq!(updated_name, rsa_method.get_name().unwrap());
    }

    #[test]
    fn flags_change() {
        let initial_flags: i32 = 0x8a8a; // nothing special, just uniquely identifiable
        let rsa_method = RsaMethod::new("TESTING METHOD", initial_flags);
        assert!(rsa_method.is_ok());

        let rsa_method = rsa_method.unwrap();

        let expected_flags = rsa_method.get_flags().unwrap();
        assert_eq!(initial_flags, expected_flags);

        let updated_flags = 0xa8a8;
        assert!(rsa_method.set_flags(updated_flags).is_ok());
        assert!(rsa_method.get_flags().is_ok());
        assert_eq!(updated_flags, rsa_method.get_flags().unwrap());
    }

    #[test]
    fn app_data() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());

        let rsa_method = rsa_method.unwrap();

        let initial_app_data = 0x8a8a as *mut c_void;
        assert!(unsafe { rsa_method.set_app_data(initial_app_data).is_ok() });
        assert_eq!(initial_app_data, rsa_method.get_app_data().unwrap());

        let updated_app_data = 0xfafa as *mut c_void;
        assert!(unsafe { rsa_method.set_app_data(updated_app_data).is_ok() });
        assert_eq!(updated_app_data, rsa_method.get_app_data().unwrap());
    }

    #[no_mangle]
    unsafe extern "C" fn test_pub_enc(
        _flen: i32,
        _from: *const u8,
        _to: *mut u8,
        _rsa: *mut RSA,
        _padding: i32,
    ) -> i32 {
        0
    }

    #[test]
    fn set_pub_enc() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_pub_enc(Some(test_pub_enc)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_pub_dec(
        _flen: i32,
        _from: *const u8,
        _to: *mut u8,
        _rsa: *mut RSA,
        _padding: i32,
    ) -> i32 {
        0
    }

    #[test]
    fn set_pub_dec() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_pub_dec(Some(test_pub_dec)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_priv_enc(
        _flen: i32,
        _from: *const u8,
        _to: *mut u8,
        _rsa: *mut RSA,
        _padding: i32,
    ) -> i32 {
        0
    }

    #[test]
    fn set_priv_enc() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method
            .unwrap()
            .set_priv_enc(Some(test_priv_enc))
            .is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_priv_dec(
        _flen: i32,
        _from: *const u8,
        _to: *mut u8,
        _rsa: *mut RSA,
        _padding: i32,
    ) -> i32 {
        0
    }

    #[test]
    fn set_priv_dec() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method
            .unwrap()
            .set_priv_dec(Some(test_priv_dec))
            .is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_mod_exp(
        _r0: *mut BIGNUM,
        _i: *const BIGNUM,
        _rsa: *mut RSA,
        _ctx: *mut BN_CTX,
    ) -> i32 {
        0
    }

    #[test]
    fn set_mod_exp() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_mod_exp(Some(test_mod_exp)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_bn_mod_exp(
        _r: *mut BIGNUM,
        _a: *const BIGNUM,
        _p: *const BIGNUM,
        _m: *const BIGNUM,
        _ctx: *mut BN_CTX,
        _m_ctx: *mut BN_MONT_CTX,
    ) -> i32 {
        0
    }

    #[test]
    fn set_bn_mod_exp() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method
            .unwrap()
            .set_bn_mod_exp(Some(test_bn_mod_exp))
            .is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_init(_rsa: *mut RSA) -> i32 {
        0
    }

    #[test]
    fn set_init() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_init(Some(test_init)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_finish(_rsa: *mut RSA) -> i32 {
        0
    }

    #[test]
    fn set_finish() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_finish(Some(test_finish)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_sign(
        _type: i32,
        _m: *const u8,
        _m_length: u32,
        _sigret: *mut u8,
        _siglen: *mut u32,
        _rsa: *const RSA,
    ) -> i32 {
        0
    }

    #[test]
    fn set_sign() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_sign(Some(test_sign)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_verify(
        _dtype: i32,
        _m: *const u8,
        _m_length: u32,
        _sigbuf: *const u8,
        _siglen: u32,
        _rsa: *const RSA,
    ) -> i32 {
        0
    }

    #[test]
    fn set_verify() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_verify(Some(test_verify)).is_ok());
    }

    #[no_mangle]
    unsafe extern "C" fn test_keygen(
        _rsa: *mut RSA,
        _bits: i32,
        _e: *mut BIGNUM,
        _cb: *mut BN_GENCB,
    ) -> i32 {
        0
    }

    #[test]
    fn set_keygen() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method.unwrap().set_keygen(Some(test_keygen)).is_ok());
    }

    #[no_mangle]
    #[cfg(ossl111)]
    unsafe extern "C" fn test_multi_prime_keygen(
        _rsa: *mut RSA,
        _bits: i32,
        _primes: i32,
        _e: *mut BIGNUM,
        _cb: *mut BN_GENCB,
    ) -> i32 {
        0
    }

    #[cfg(ossl111)]
    #[test]
    fn set_multi_prime_keygen() {
        let rsa_method = RsaMethod::new("TESTING METHOD", 0);
        assert!(rsa_method.is_ok());
        assert!(rsa_method
            .unwrap()
            .set_multi_prime_keygen(Some(test_multi_prime_keygen))
            .is_ok());
    }
}
