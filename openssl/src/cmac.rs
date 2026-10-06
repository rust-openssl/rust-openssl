//! CMAC (Cipher-based Message Authentication Code).
//!
//! CMAC is a MAC algorithm based on AES-CBC, defined in RFC 4493.
//! https://tools.ietf.org/html/rfc4493#section-2.3.
//!
//! # Examples
//!
//! ```
//! use openssl::cmac::CmacCtx;
//! use openssl::symm::Cipher;
//!
//! let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
//! let mut ctx = CmacCtx::new(&Cipher::aes_128_cbc(), &key).unwrap();
//! ctx.update(b"Hi There").unwrap();
//! let mac = ctx.finalize_to_vec().unwrap();
//! assert_eq!(mac.len(), 16);
//! ```

use std::io;
use std::io::Write;
use std::ptr;

use crate::error::ErrorStack;
use crate::symm::Cipher;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

foreign_type_and_impl_send_sync! {
    type CType = ffi::CMAC_CTX;
    fn drop = ffi::CMAC_CTX_free;

    /// A context for computing CMAC values.
    pub struct CmacCtx;
    /// A reference to a [`CmacCtx`].
    pub struct CmacCtxRef;
}

impl CmacCtx {
    /// Creates a new `CmacCtx` initialized with the given cipher and key.
    ///
    /// The CMAC RFC only specifies the use of AES-128, so `cipher` should be
    /// [`Cipher::aes_128_cbc()`] and `key` should be 16 bytes. However, this
    /// implementation also supports AES-256 by using [`Cipher::aes_256_cbc()`]
    /// with a 32-byte key.
    #[corresponds(CMAC_Init)]
    pub fn new(cipher: &Cipher, key: &[u8]) -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = cvt_p(ffi::CMAC_CTX_new())?;
            let r = ffi::CMAC_Init(
                ctx,
                key.as_ptr() as *const _,
                key.len(),
                cipher.as_ptr(),
                ptr::null_mut(),
            );
            if r != 1 {
                ffi::CMAC_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            assert!(!ctx.is_null());

            Ok(CmacCtx::from_ptr(ctx))
        }
    }
}

impl CmacCtxRef {
    /// Feeds more data into the CMAC computation.
    #[corresponds(CMAC_Update)]
    pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::CMAC_Update(self.as_ptr(), data.as_ptr() as *const _, data.len()) })?;
        Ok(())
    }

    /// Returns the expected length of the CMAC output.
    #[corresponds(CMAC_Final)]
    pub fn len(&self) -> Result<usize, ErrorStack> {
        let mut len: usize = 0;
        cvt(unsafe { ffi::CMAC_Final(self.as_ptr(), ptr::null_mut(), &mut len) })?;
        Ok(len)
    }

    /// Finalizes the CMAC computation, writing the MAC into `buf` and returning the number
    /// of bytes written. This method will fail if the buffer is not large enough for the
    /// CMAC. Use `len` to get the required size.
    #[corresponds(CMAC_Final)]
    pub fn finalize(&mut self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
        let mut len: usize = buf.len();
        cvt(unsafe { ffi::CMAC_Final(self.as_ptr(), buf.as_mut_ptr(), &mut len) })?;
        Ok(len)
    }

    /// Finalizes the CMAC computation and returns the MAC value.
    ///
    /// This is a simple convenience wrapper over `len` and `finalize`.
    #[corresponds(CMAC_Final)]
    pub fn finalize_to_vec(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let mut buf = vec![0u8; self.len()?];
        self.finalize(&mut buf)?;
        Ok(buf)
    }
}

impl Write for CmacCtxRef {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symm::Cipher;

    #[test]
    fn test_cmac_aes128() {
        // RFC 4493 test vector
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let data = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();

        let mut ctx = CmacCtx::new(&Cipher::aes_128_cbc(), &key).unwrap();
        ctx.update(&data).unwrap();
        let mac = ctx.finalize_to_vec().unwrap();

        let expected = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_cmac_aes192() {
        // NIST SP 800-38B test vector for AES-192
        let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let data = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();

        let mut ctx = CmacCtx::new(&Cipher::aes_192_cbc(), &key).unwrap();
        ctx.update(&data).unwrap();
        let mac = ctx.finalize_to_vec().unwrap();

        let expected = hex::decode("9e99a7bf31e710900662f65e617c5184").unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_cmac_aes256() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let data = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();

        let mut ctx = CmacCtx::new(&Cipher::aes_256_cbc(), &key).unwrap();
        ctx.update(&data).unwrap();
        let mac = ctx.finalize_to_vec().unwrap();

        let expected = hex::decode("28a7023f452e8f82bd4bf28d8c37c35c").unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_cmac_write() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let data = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();

        let mut ctx = CmacCtx::new(&Cipher::aes_128_cbc(), &key).unwrap();
        ctx.write_all(&data).unwrap();
        let mac = ctx.finalize_to_vec().unwrap();

        let expected = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_cmac_invalid_key_len() {
        // AES-128 requires exactly 16 bytes
        let short_key = vec![0u8; 5];
        assert!(CmacCtx::new(&Cipher::aes_128_cbc(), &short_key).is_err());

        // AES-256 requires exactly 32 bytes
        let short_key = vec![0u8; 16];
        assert!(CmacCtx::new(&Cipher::aes_256_cbc(), &short_key).is_err());
    }

    #[test]
    fn test_cmac_invalid_cipher() {
        let key = vec![0u8; 16];
        // CTR mode not supported
        assert!(CmacCtx::new(&Cipher::aes_128_ctr(), &key).is_err());
        // GCM mode not supported
        assert!(CmacCtx::new(&Cipher::aes_128_gcm(), &key).is_err());
        // OFB mode not supported
        assert!(CmacCtx::new(&Cipher::aes_128_ofb(), &key).is_err());
    }

    #[test]
    fn test_cmac_len() {
        let key128 = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let ctx = CmacCtx::new(&Cipher::aes_128_cbc(), &key128).unwrap();
        assert_eq!(ctx.len().unwrap(), 16);

        let key256 =
            hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .unwrap();
        let ctx = CmacCtx::new(&Cipher::aes_256_cbc(), &key256).unwrap();
        assert_eq!(ctx.len().unwrap(), 16);
    }

    #[test]
    fn test_cmac_finalize_into_buf() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let data = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();

        let mut ctx = CmacCtx::new(&Cipher::aes_128_cbc(), &key).unwrap();
        ctx.update(&data).unwrap();

        let len = ctx.len().unwrap();
        assert_eq!(len, 16);

        let mut buf = [0u8; 16];
        let written = ctx.finalize(&mut buf).unwrap();

        assert_eq!(written, 16);
        let expected = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
        assert_eq!(&buf[..written], expected.as_slice());
    }

    #[test]
    fn test_cmac_non_block_aligned() {
        // RFC 4493 test vector #3: 40 bytes (not a multiple of 16-byte block size)
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let data = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        )
        .unwrap();
        assert_eq!(data.len(), 40);

        let mut ctx = CmacCtx::new(&Cipher::aes_128_cbc(), &key).unwrap();
        ctx.update(&data).unwrap();
        let mac = ctx.finalize_to_vec().unwrap();

        let expected = hex::decode("dfa66747de9ae63030ca32611497c827").unwrap();
        assert_eq!(mac, expected);
    }
}
