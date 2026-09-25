//! Wraps `EVP_SIGNATURE` objects.

#[cfg(ossl350)]
use crate::cvt_p;
#[cfg(ossl350)]
use crate::error::ErrorStack;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::fmt;
#[cfg(ossl350)]
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_SIGNATURE;
    fn drop = ffi::EVP_SIGNATURE_free;

    /// A signature algorithm.
    pub struct Signature;

    /// Reference to `Signature`.
    pub struct SignatureRef;
}

impl ToOwned for SignatureRef {
    type Owned = Signature;

    fn to_owned(&self) -> Signature {
        unsafe {
            ffi::EVP_SIGNATURE_up_ref(self.as_ptr());
            Signature::from_ptr(self.as_ptr())
        }
    }
}

impl SignatureRef {
    /// Returns the name of the signature algorithm.
    #[corresponds(EVP_SIGNATURE_get0_name)]
    pub fn name(&self) -> &str {
        unsafe { CStr::from_ptr(ffi::EVP_SIGNATURE_get0_name(self.as_ptr())) }
            .to_str()
            .expect("identifier to be in UTF8")
    }

    /// Returns a human-readable description of the signature
    /// algorithm.
    #[corresponds(EVP_SIGNATURE_get0_description)]
    pub fn description(&self) -> &str {
        unsafe { CStr::from_ptr(ffi::EVP_SIGNATURE_get0_description(self.as_ptr())) }
            .to_str()
            .expect("description to be in UTF8")
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl Clone for Signature {
    fn clone(&self) -> Signature {
        SignatureRef::to_owned(self)
    }
}

impl Signature {
    /// Creates a new `Signature` for use with ML-DSA.
    #[cfg(ossl350)]
    pub fn for_ml_dsa(variant: crate::pkey_ml_dsa::Variant) -> Result<Signature, ErrorStack> {
        unsafe {
            Ok(Signature(cvt_p(ffi::EVP_SIGNATURE_fetch(
                ptr::null_mut(),
                variant.as_cstr().as_ptr(),
                ptr::null(),
            ))?))
        }
    }
}

#[cfg(test)]
mod tests {

    #[cfg(ossl350)]
    use super::*;

    #[cfg(ossl350)]
    #[test]
    fn test_alloc_free() {
        let sig = Signature::for_ml_dsa(crate::pkey_ml_dsa::Variant::MlDsa44).unwrap();
        drop(sig);
    }
}
