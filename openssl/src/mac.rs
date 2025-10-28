use crate::cipher::CipherRef;
use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::lib_ctx::LibCtxRef;
use crate::ossl_param::{OsslParamArray, OsslParamBuilder};
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::{CStr, CString};
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_MAC;
    fn drop = ffi::EVP_MAC_free;

    /// A MAC algorithm context
    pub struct Mac;
    /// A reference to a [`crate::mac::Mac`].
    pub struct MacRef;
}

cstr_const!(OSSL_MAC_PARAM_CIPHER, b"cipher\0");
cstr_const!(OSSL_MAC_PARAM_DIGEST, b"digest\0");

impl Mac {
    /// Fetches a MAC object corresponding to the specified algorithm name and properties.
    ///
    /// Requires OpenSSL 3.0.0 or newer.
    #[corresponds(EVP_MAC_fetch)]
    pub fn fetch(
        ctx: Option<&LibCtxRef>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> Result<Self, ErrorStack> {
        ffi::init();
        let algorithm = CString::new(algorithm).unwrap();
        let properties = properties.map(|s| CString::new(s).unwrap());

        let ptr = cvt_p(unsafe {
            ffi::EVP_MAC_fetch(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                algorithm.as_ptr(),
                properties.as_ref().map_or(ptr::null_mut(), |s| s.as_ptr()),
            )
        })?;

        Ok(unsafe { Mac::from_ptr(ptr) })
    }

    pub fn cmac() -> Self {
        Self::fetch(None, "cmac", None).unwrap()
    }

    pub fn hmac() -> Self {
        Self::fetch(None, "hmac", None).unwrap()
    }
}

impl MacRef {
    #[corresponds(EVP_MAC_get0_name)]
    pub fn name(&self) -> String {
        let name = unsafe { CStr::from_ptr(ffi::EVP_MAC_get0_name(self.as_ptr())) };
        String::from_utf8_lossy(name.to_bytes()).into_owned()
    }

    #[corresponds(EVP_MAC_get0_description)]
    pub fn description(&self) -> String {
        let buf = unsafe { ffi::EVP_MAC_get0_description(self.as_ptr()) };
        if buf.is_null() {
            String::new()
        } else {
            String::from_utf8_lossy(unsafe { CStr::from_ptr(buf).to_bytes() }).into()
        }
    }
}

impl ToOwned for MacRef {
    type Owned = Mac;

    fn to_owned(&self) -> Self::Owned {
        unsafe {
            ffi::EVP_MAC_up_ref(self.as_ptr());
            Self::Owned::from_ptr(self.as_ptr())
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_MAC_CTX;
    fn drop = ffi::EVP_MAC_CTX_free;
    fn clone = ffi::EVP_MAC_CTX_dup;

    /// A MAC computation context
    pub struct MacCtx;
    /// A reference to a [`crate::mac::MacCtx`].
    pub struct MacCtxRef;
}

impl MacCtx {
    /// Create a `MacCtx` from a `Mac`
    #[corresponds(EVP_MAC_CTX_new)]
    pub fn new(mac: &MacRef) -> Result<Self, ErrorStack> {
        let ctx = cvt_p(unsafe { ffi::EVP_MAC_CTX_new(mac.as_ptr()) })?;
        Ok(unsafe { MacCtx::from_ptr(ctx) })
    }
}

#[allow(clippy::len_without_is_empty)]
impl MacCtxRef {
    #[corresponds(EVP_MAC_CTX_get0_mac)]
    pub fn mac(&self) -> Result<Mac, ErrorStack> {
        let mac = cvt_p(unsafe { ffi::EVP_MAC_CTX_get0_mac(self.as_ptr()) })?;
        Ok(unsafe { Mac::from_ptr(mac) })
    }

    #[corresponds(EVP_MAC_CTX_get_mac_size)]
    pub fn mac_size(&self) -> usize {
        unsafe { ffi::EVP_MAC_CTX_get_mac_size(self.as_ptr()) as usize }
    }

    #[corresponds(EVP_MAC_CTX_get_block_size)]
    pub fn block_size(&self) -> usize {
        unsafe { ffi::EVP_MAC_CTX_get_block_size(self.as_ptr()) as usize }
    }

    /// Initialise the `MacCtx`
    #[corresponds(EVP_MAC_init)]
    pub(crate) fn init(
        &mut self,
        key: &[u8],
        params: Option<&OsslParamArray>,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::EVP_MAC_init(
                self.as_ptr(),
                key.as_ptr(),
                key.len(),
                params.map_or(ptr::null(), |s| s.as_ptr()),
            )
        })
        .map(|_| ())
    }

    /// Initialise the `MacCtx` with a cipher parameter
    pub fn init_cipher(&mut self, key: &[u8], cipher: &CipherRef) -> Result<(), ErrorStack> {
        let mut builder = OsslParamBuilder::new()?;
        builder.add_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher.nid().short_name()?)?;
        let params = builder.to_param()?;
        self.init(key, Some(&params))
    }

    /// Initialise the `MacCtx` with a digest parameter
    pub fn init_digest(&mut self, key: &[u8], digest: &MessageDigest) -> Result<(), ErrorStack> {
        let mut builder = OsslParamBuilder::new()?;
        builder.add_utf8_string(OSSL_MAC_PARAM_DIGEST, digest.type_().short_name()?)?;
        let params = builder.to_param()?;
        self.init(key, Some(&params))
    }

    /// Feed data into the `MacCtx`
    #[corresponds(EVP_MAC_update)]
    pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::EVP_MAC_update(self.as_ptr(), data.as_ptr(), data.len()) }).map(|_| ())
    }

    /// Computes an upper bound on the MAC length.
    #[corresponds(EVP_MAC_final)]
    pub fn len(&mut self) -> Result<usize, ErrorStack> {
        let mut out_size = 0;
        cvt(unsafe { ffi::EVP_MAC_final(self.as_ptr(), ptr::null_mut(), &mut out_size, 0) })?;

        Ok(out_size)
    }

    /// Writes the calculated MAC into the provided buffer, returning the number of bytes written.
    ///
    /// This method will fail if the buffer is not large enough for the signature. Use the `len`
    /// method to get an upper bound on the required size.
    #[corresponds(EVP_MAC_final)]
    pub fn finalize(&mut self, out: &mut [u8]) -> Result<usize, ErrorStack> {
        let mut written = 0;
        cvt(unsafe {
            ffi::EVP_MAC_final(self.as_ptr(), out.as_mut_ptr(), &mut written, out.len())
        })?;

        Ok(written)
    }

    /// Returns the calculated MAC
    ///
    /// This is a convenience wrapper over `len` and `finalize`.
    pub fn finalize_to_vec(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let mut out_buf = vec![0u8; self.len()?];
        self.finalize(&mut out_buf)?;
        Ok(out_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Cipher;
    use crate::ossl_param::OsslParamBuilder;
    use hex::ToHex;

    #[test]
    fn test_get_mac() {
        let mac = Mac::fetch(None, "cmac", None).unwrap();
        assert_eq!(mac.name(), "CMAC");
        let mac2 = &mac.to_owned();
        assert_eq!(mac2.description(), "");
    }

    #[test]
    fn test_ctx_getters() {
        let mac = Mac::cmac();
        let mut ctx = MacCtx::new(&mac).unwrap();
        assert_eq!(ctx.block_size(), 0);
        assert_eq!(ctx.mac_size(), 0);

        let cipher = b"aes-256-cbc";
        let mut param_builder = OsslParamBuilder::new().unwrap();
        cvt(unsafe {
            ffi::OSSL_PARAM_BLD_push_utf8_string(
                param_builder.as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"cipher\0").as_ptr(),
                cipher.as_ptr().cast::<libc::c_char>(),
                cipher.len(),
            )
        })
        .unwrap();
        let params = param_builder.to_param().unwrap();

        ctx.init(b"secret0123456789secret0123456789", Some(&params))
            .unwrap();

        assert_eq!(ctx.block_size(), 16);
        assert_eq!(ctx.mac_size(), 16);
    }

    #[test]
    fn test_cmac() {
        let mac = Mac::cmac();
        let mut ctx = MacCtx::new(&mac).unwrap();

        let secret_key = b"secret0123456789";
        let cipher = Cipher::aes_128_cbc();

        ctx.init_cipher(secret_key, cipher).unwrap();
        ctx.update(b"foobar").unwrap();
        let hash = ctx.finalize_to_vec().unwrap();
        assert_eq!(
            hash.encode_hex::<String>(),
            "bf6136dc2ab41ecfe324455203a934b9"
        );
    }

    #[test]
    fn test_hmac() {
        let mac = Mac::hmac();
        let mut ctx = MacCtx::new(&mac).unwrap();

        let secret_key = b"secret0123456789";
        let digest = MessageDigest::sha1();

        ctx.init_digest(secret_key, &digest).unwrap();
        ctx.update(b"foobar").unwrap();
        let hash = ctx.finalize_to_vec().unwrap();
        assert_eq!(
            hash.encode_hex::<String>(),
            "c761a6cb7703581f5d79a8132bacd947559969c9"
        );
    }
}
