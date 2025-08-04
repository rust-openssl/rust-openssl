//! OSSL_PARAM management for OpenSSL 3.*
//!
//! The OSSL_PARAM structure represents an array of generic
//! attributes that can represent various
//! properties in OpenSSL, including keys and operations.
//!
//! This is always represented as an array of OSSL_PARAM
//! structures, terminated by an entry with a NULL key.
//!
//! For convenience, the OSSL_PARAM_BLD builder can be used to
//! dynamically construct these structures.
//!
//! Note, that this module is available only in OpenSSL 3.* and
//! only internally for this crate.

use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::util;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_void};
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr;

foreign_type_and_impl_send_sync! {
    // This is the singular type, but it is always allocated
    // and used as an array of such types.
    type CType = ffi::OSSL_PARAM;
    // OSSL_PARMA_free correctly frees the entire array.
    fn drop = ffi::OSSL_PARAM_free;

    /// `OsslParamArray` constructed using `OsslParamBuilder`.
    /// Internally this is a pointer to an array of the OSSL_PARAM
    /// structures.
    pub struct OsslParamArray;
    /// Reference to `OsslParamArray`.
    pub struct OsslParamArrayRef;
}

impl OsslParamArray {
    /// Locate a parameter by the given key (returning a const reference).
    #[corresponds(OSSL_PARAM_locate_const)]
    fn locate_const(&self, key: &CStr) -> Option<*const ffi::OSSL_PARAM> {
        let param = unsafe { ffi::OSSL_PARAM_locate_const(self.as_ptr(), key.as_ptr()) };
        if param.is_null() {
            None
        } else {
            Some(param)
        }
    }

    /// Locates the individual `OSSL_PARAM` element representing an
    /// octet string identified by the key in the `OsslParamArray`
    /// array and returns a reference to it.
    ///
    /// Combines OSSL_PARAM_locate and OSSL_PARAM_get_octet_string.
    #[corresponds(OSSL_PARAM_get_octet_string)]
    #[allow(dead_code)] // TODO: remove when when used by ML-DSA / ML-KEM
    pub(crate) fn locate_octet_string<'a>(&'a self, key: &CStr) -> Result<&'a [u8], ErrorStack> {
        let param = self.locate_const(key).ok_or_else(ErrorStack::get)?;
        unsafe {
            let mut val: *const c_void = ptr::null_mut();
            let mut val_len: usize = 0;
            cvt(ffi::OSSL_PARAM_get_octet_string_ptr(
                param,
                &mut val,
                &mut val_len,
            ))?;
            Ok(util::from_raw_parts(val as *const u8, val_len))
        }
    }

    /// Locates the individual `OSSL_PARAM` element representing a BigNum identified by the key in
    /// the `OsslParamArray` array and returns a reference to it.
    ///
    /// Combines OSSL_PARAM_locate and OSSL_PARAM_get_BN.
    #[corresponds(OSSL_PARAM_get_BN)]
    #[allow(dead_code)]
    fn locate_bn(&self, key: &CStr) -> Result<BigNum, ErrorStack> {
        let param = self.locate_const(key).ok_or_else(ErrorStack::get)?;
        let mut bn_ptr = ptr::null_mut();
        cvt(unsafe { ffi::OSSL_PARAM_get_BN(param, &mut bn_ptr) })?;
        Ok(unsafe { BigNum::from_ptr(bn_ptr) })
    }
}

impl OsslParamArrayRef {
    /// Merges two `ParamsRef` objects into a new `Params` object.
    #[corresponds(OSSL_PARAM_merge)]
    #[allow(dead_code)]
    pub fn merge(&self, other: &OsslParamArrayRef) -> Result<OsslParamArray, ErrorStack> {
        // OSSL_PARAM_merge shallow copies the params
        // OSSL_PARAM_free  deep frees (so the params and values will be freed)
        // OSSL_PARAM_dup   deep copies
        // Dupe both params[] so we don't end up pointing to freed memory.
        cvt_p(unsafe {
            ffi::OSSL_PARAM_merge(
                ffi::OSSL_PARAM_dup(self.as_ptr()),
                ffi::OSSL_PARAM_dup(other.as_ptr()),
            )
        })
        .map(|p| unsafe { OsslParamArray::from_ptr(p) })
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_PARAM_BLD;
    fn drop = ffi::OSSL_PARAM_BLD_free;

    /// Builder used to construct `OsslParamArray`.
    pub struct OsslParamBuilderInternal;
    /// Reference to `OsslParamBuilderInternal`.
    pub struct OsslParamBuilderRefInternal;
}

/// Wrapper around the internal OsslParamBuilderInternal that adds lifetime management
/// since the builder does not own the key and value data that is added to it.
pub struct OsslParamBuilder<'a> {
    builder: OsslParamBuilderInternal,
    _marker: PhantomData<&'a ()>,
}

impl<'a> OsslParamBuilder<'a> {
    /// Returns a builder for an OsslParamArray.
    ///
    /// The array is initially empty.
    #[corresponds(OSSL_PARAM_BLD_new)]
    pub(crate) fn new() -> Result<OsslParamBuilder<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::OSSL_PARAM_BLD_new()).map(|builder| OsslParamBuilder {
                builder: OsslParamBuilderInternal(builder),
                _marker: PhantomData,
            })
        }
    }

    /// Constructs the `OsslParamArray` and clears this builder.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_param(&'a mut self) -> Result<OsslParamArray, ErrorStack> {
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.as_ptr()))?;
            Ok(OsslParamArray::from_ptr(params))
        }
    }

    /// Adds an octet string to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_octet_string)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn add_octet_string(
        &mut self,
        key: &'a CStr,
        buf: &'a [u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_octet_string(
                self.as_ptr(),
                key.as_ptr(),
                buf.as_ptr() as *const c_void,
                buf.len(),
            ))
            .map(|_| ())
        }
    }

    /// Adds an unsigned int to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_uint)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn add_uint(&mut self, key: &'a CStr, val: u32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_uint(
                self.as_ptr(),
                key.as_ptr(),
                val,
            ))
            .map(|_| ())
        }
    }

    /// Adds a `BigNum` to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    pub(crate) fn add_bn(&mut self, key: &'a CStr, bn: &'a BigNumRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::OSSL_PARAM_BLD_push_BN(self.as_ptr(), key.as_ptr(), bn.as_ptr()) })
            .map(|_| ())
    }

    /// Adds a utf8 string to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_utf8_string)]
    #[allow(dead_code)] // TODO: remove when when used by EVP_KEY.from_data
    pub(crate) fn add_utf8_string(
        &mut self,
        key: &'a CStr,
        value: &'a str,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::OSSL_PARAM_BLD_push_utf8_string(
                self.as_ptr(),
                key.as_ptr(),
                value.as_ptr().cast::<c_char>(),
                value.len(),
            )
        })
        .map(|_| ())
    }

    /// Returns a raw pointer to the underlying `OSSL_PARAM_BLD` structure.
    pub(crate) unsafe fn as_ptr(&mut self) -> *mut ffi::OSSL_PARAM_BLD {
        self.builder.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::BigNum;
    use crate::pkey::{
        OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_RSA_D,
        OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_N, OSSL_SIGNATURE_PARAM_NONCE_TYPE,
    };

    #[test]
    fn test_builder_locate_octet_string() {
        let mut builder = OsslParamBuilder::new().unwrap();
        builder
            .add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, b"value1")
            .unwrap();
        let params = builder.to_param().unwrap();

        assert!(params
            .locate_octet_string(CStr::from_bytes_with_nul(b"invalid\0").unwrap())
            .is_err());
        assert_eq!(
            params.locate_octet_string(OSSL_PKEY_PARAM_PUB_KEY).unwrap(),
            b"value1"
        );
    }

    fn assert_param(params: &OsslParamArray, key: &CStr, is_null: bool) {
        match params.locate_const(key) {
            Some(_) => assert!(!is_null, "Unexpectedly found param: {key:?}"),
            None => assert!(is_null, "Failed to find param: {key:?}"),
        }
    }

    fn assert_bn_equal(params: &OsslParamArray, key: &CStr, expected: &BigNum) {
        let bn = params.locate_bn(key).unwrap();
        assert_eq!(bn, *expected);
    }

    #[test]
    fn test_param_builder_uint() {
        let mut builder = OsslParamBuilder::new().unwrap();
        builder
            .add_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, 42)
            .unwrap();
        let params = builder.to_param().unwrap();

        assert_param(&params, OSSL_SIGNATURE_PARAM_NONCE_TYPE, false);
        assert_param(&params, OSSL_PKEY_PARAM_GROUP_NAME, true);
    }

    #[test]
    fn test_param_builder_bignum() {
        let n = BigNum::from_u32(0xbc747fc5).unwrap();
        let e = BigNum::from_u32(0x10001).unwrap();
        let d = BigNum::from_u32(0x7b133399).unwrap();

        let mut builder = OsslParamBuilder::new().unwrap();
        builder.add_bn(OSSL_PKEY_PARAM_RSA_N, &n).unwrap();
        builder.add_bn(OSSL_PKEY_PARAM_RSA_E, &e).unwrap();
        builder.add_bn(OSSL_PKEY_PARAM_RSA_D, &d).unwrap();
        let params = builder.to_param().unwrap();

        for (param, expected) in [
            (OSSL_PKEY_PARAM_RSA_N, n),
            (OSSL_PKEY_PARAM_RSA_E, e),
            (OSSL_PKEY_PARAM_RSA_D, d),
        ] {
            assert_bn_equal(&params, param, &expected);
        }

        assert_param(&params, OSSL_PKEY_PARAM_GROUP_NAME, true);
    }

    #[test]
    fn test_param_builder_string() {
        let mut builder = OsslParamBuilder::new().unwrap();
        builder
            .add_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "primve256v1")
            .unwrap();
        let params = builder.to_param().unwrap();

        assert_param(&params, OSSL_PKEY_PARAM_GROUP_NAME, false);
        assert_param(&params, OSSL_PKEY_PARAM_RSA_N, true);
    }

    #[test]
    fn test_param_builder_octet_string() {
        let mut builder = OsslParamBuilder::new().unwrap();
        builder
            .add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, b"foobar")
            .unwrap();
        let params = builder.to_param().unwrap();

        assert_param(&params, OSSL_PKEY_PARAM_PUB_KEY, false);
        assert_param(&params, OSSL_PKEY_PARAM_GROUP_NAME, true);
    }

    #[test]
    fn test_merge() {
        let (n, e, d) = (0xbc747fc5, 0x10001, 0x7b133399);
        let mut merged_params: OsslParamArray;

        // Create a param array with just n in a scoped block so that bn_n, and the builder are dropped
        {
            let bn_n = BigNum::from_u32(n).unwrap();
            let mut builder = OsslParamBuilder::new().unwrap();
            builder.add_bn(OSSL_PKEY_PARAM_RSA_N, &bn_n).unwrap();
            merged_params = builder.to_param().unwrap();
        }

        // We should still be able to pull back n and get the correct value, but not e or d (yet)
        let bn_n = BigNum::from_u32(n).unwrap();
        assert_bn_equal(&merged_params, OSSL_PKEY_PARAM_RSA_N, &bn_n);
        assert_param(&merged_params, OSSL_PKEY_PARAM_RSA_E, true);
        assert_param(&merged_params, OSSL_PKEY_PARAM_RSA_D, true);

        // Create a new param array with just e and merge it in
        {
            let bn_e = BigNum::from_u32(e).unwrap();
            let mut builder = OsslParamBuilder::new().unwrap();
            builder.add_bn(OSSL_PKEY_PARAM_RSA_E, &bn_e).unwrap();
            let params = builder.to_param().unwrap();
            merged_params = merged_params.merge(&params).unwrap();
        }

        // We should still be able to pull back n & e and get the correct value, but not d (yet)
        let bn_e = BigNum::from_u32(e).unwrap();
        assert_bn_equal(&merged_params, OSSL_PKEY_PARAM_RSA_N, &bn_n);
        assert_bn_equal(&merged_params, OSSL_PKEY_PARAM_RSA_E, &bn_e);
        assert_param(&merged_params, OSSL_PKEY_PARAM_RSA_D, true);

        // Again, create a new param array with just d and merge it in
        {
            let bn_d = BigNum::from_u32(d).unwrap();
            let mut builder = OsslParamBuilder::new().unwrap();
            builder.add_bn(OSSL_PKEY_PARAM_RSA_D, &bn_d).unwrap();
            let params = builder.to_param().unwrap();
            merged_params = merged_params.merge(&params).unwrap();
        }

        // We should be able to pull all of n, e & d out and get the correct values
        let bn_d = BigNum::from_u32(d).unwrap();
        assert_bn_equal(&merged_params, OSSL_PKEY_PARAM_RSA_N, &bn_n);
        assert_bn_equal(&merged_params, OSSL_PKEY_PARAM_RSA_E, &bn_e);
        assert_bn_equal(&merged_params, OSSL_PKEY_PARAM_RSA_D, &bn_d);
    }
}
