use crate::error::ErrorStack;
use crate::{cvt, cvt_p};
use foreign_types::ForeignType;
use openssl_macros::corresponds;
use std::ffi::CString;

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_LIB_CTX;
    fn drop = ffi::OSSL_LIB_CTX_free;

    pub struct LibCtx;
    pub struct LibCtxRef;
}

impl LibCtx {
    #[corresponds(OSSL_LIB_CTX_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::OSSL_LIB_CTX_new())?;
            Ok(LibCtx::from_ptr(ptr))
        }
    }

    #[corresponds(OSSL_LIB_CTX_get0_global_default)]
    pub fn global_default() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::OSSL_LIB_CTX_get0_global_default())?;
            Ok(LibCtx::from_ptr(ptr))
        }
    }

    #[corresponds(EVP_set_default_properties)]
    pub fn set_default_properties(&self, propq: &str) -> Result<(), ErrorStack> {
        let propq = CString::new(propq).unwrap();
        unsafe {
            cvt(ffi::EVP_set_default_properties(
                self.as_ptr(),
                propq.as_ptr(),
            ))
            .map(|_| ())
        }
    }
}
