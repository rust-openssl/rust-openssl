//! ML-DSA unified API
//!
//! This module provides a unified high-level API for ML-DSA (Module-Lattice-Based
//! Digital Signature Algorithm) that works with both OpenSSL 3.5+ and BoringSSL backends.
//!
//! # Example
//!
//! ```no_run
//! use openssl::ml_dsa::{MlDsaKeyPair, Variant};
//!
//! // Generate a new key pair
//! let keypair = MlDsaKeyPair::generate(Variant::MlDsa65).unwrap();
//!
//! // Sign a message
//! let message = b"Hello, world!";
//! let signature = keypair.sign(message, None).unwrap();
//!
//! // Verify the signature
//! assert!(keypair.verify(message, &signature, None).unwrap());
//! ```

use crate::error::ErrorStack;

pub use crate::pkey_ml_dsa::Variant;

#[cfg(ossl350)]
use crate::{pkey::PKey, pkey_ctx::PkeyCtx, signature::Signature};
#[cfg(ossl350)]
use foreign_types::ForeignType;

#[cfg(boringssl)]
use crate::pkey_ml_dsa::{PKeyMlDsaParams, Private};

/// An ML-DSA key pair that can sign and verify messages.
pub struct MlDsaKeyPair {
    variant: Variant,
    #[cfg(ossl350)]
    pkey: PKey<crate::pkey::Private>,
    #[cfg(boringssl)]
    params: PKeyMlDsaParams<Private>,
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA key pair.
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack> {
        #[cfg(ossl350)]
        {
            let pkey = PKey::generate_ml_dsa(variant)?;
            Ok(MlDsaKeyPair { variant, pkey })
        }

        #[cfg(boringssl)]
        {
            let params = PKeyMlDsaParams::<Private>::generate(variant)?;
            Ok(MlDsaKeyPair { variant, params })
        }
    }

    /// Create an ML-DSA key pair from a seed.
    ///
    /// The seed must be exactly 32 bytes.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack> {
        #[cfg(ossl350)]
        {
            use crate::ossl_param::OsslParamBuilder;
            use std::ffi::CStr;

            const OSSL_PKEY_PARAM_SEED: &CStr =
                unsafe { CStr::from_bytes_with_nul_unchecked(b"seed\0") };

            let mut bld = OsslParamBuilder::new()?;
            bld.add_octet_string(OSSL_PKEY_PARAM_SEED, seed)?;
            let mut ctx = PkeyCtx::new_from_name(None, variant.as_str(), None)?;
            ctx.fromdata_init()?;
            let params = bld.to_param()?;
            unsafe {
                let evp = crate::cvt_p(ffi::EVP_PKEY_new())?;
                let pkey = PKey::from_ptr(evp);
                crate::cvt(ffi::EVP_PKEY_fromdata(
                    ctx.as_ptr(),
                    &mut pkey.as_ptr(),
                    ffi::EVP_PKEY_KEYPAIR,
                    params.as_ptr(),
                ))?;
                Ok(MlDsaKeyPair { variant, pkey })
            }
        }

        #[cfg(boringssl)]
        {
            let params = PKeyMlDsaParams::<Private>::from_seed(variant, seed)?;
            Ok(MlDsaKeyPair { variant, params })
        }
    }

    /// Sign a message with optional context.
    ///
    /// The context, if provided, must be at most 255 bytes.
    pub fn sign(&self, message: &[u8], context: Option<&[u8]>) -> Result<Vec<u8>, ErrorStack> {
        #[cfg(ossl350)]
        {
            use crate::pkey_ml_dsa::sign_with_context;

            if let Some(ctx) = context {
                sign_with_context(&self.pkey, self.variant, message, ctx)
            } else {
                let mut algo = Signature::for_ml_dsa(self.variant)?;
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(&self.pkey)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(message, &mut signature)?;
                Ok(signature)
            }
        }

        #[cfg(boringssl)]
        {
            self.params.sign(message, context)
        }
    }

    /// Verify a signature on a message with optional context.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    #[cfg(ossl350)]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> Result<bool, ErrorStack> {
        use crate::pkey_ml_dsa::verify_with_context;

        if let Some(ctx) = context {
            verify_with_context(&self.pkey, self.variant, message, signature, ctx)
        } else {
            let mut algo = Signature::for_ml_dsa(self.variant)?;
            let mut ctx = PkeyCtx::new(&self.pkey)?;
            ctx.verify_message_init(&mut algo)?;
            ctx.verify(message, signature)
        }
    }

    /// Verify a signature on a message with optional context.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    #[cfg(boringssl)]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> Result<bool, ErrorStack> {
        let pub_params = self.params.to_public();
        pub_params.verify(message, signature, context)
    }

    /// Get the public key bytes in encoded form.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, ErrorStack> {
        #[cfg(ossl350)]
        {
            self.pkey.raw_public_key()
        }

        #[cfg(boringssl)]
        {
            Ok(self.params.public_key()?.to_vec())
        }
    }

    /// Get the private key seed.
    pub fn private_key_seed(&self) -> Result<Vec<u8>, ErrorStack> {
        #[cfg(ossl350)]
        {
            let params = self.pkey.ml_dsa(self.variant)?.unwrap();
            params.private_key_seed().map(|s| s.to_vec())
        }

        #[cfg(boringssl)]
        {
            self.params.private_key_seed().map(|s| s.to_vec())
        }
    }

    /// Get the variant of this key pair.
    pub fn variant(&self) -> Variant {
        self.variant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let keypair = MlDsaKeyPair::generate(Variant::MlDsa65).unwrap();
        let message = b"Hello, world!";
        let signature = keypair.sign(message, None).unwrap();

        // Signature should be the correct length
        assert_eq!(signature.len(), Variant::MlDsa65.signature_bytes());
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let keypair1 = MlDsaKeyPair::from_seed(Variant::MlDsa44, &seed).unwrap();
        let keypair2 = MlDsaKeyPair::from_seed(Variant::MlDsa44, &seed).unwrap();

        // Same seed should produce same public key
        assert_eq!(
            keypair1.public_key_bytes().unwrap(),
            keypair2.public_key_bytes().unwrap()
        );
    }

    #[test]
    fn test_sign_with_context() {
        let keypair = MlDsaKeyPair::generate(Variant::MlDsa87).unwrap();
        let message = b"Test message";
        let context = b"example.com/api/v1";

        let sig_with_ctx = keypair.sign(message, Some(context)).unwrap();
        let sig_no_ctx = keypair.sign(message, None).unwrap();

        // Different contexts should produce different signatures
        assert_ne!(sig_with_ctx, sig_no_ctx);
    }

    #[test]
    #[cfg(ossl350)]
    fn test_verify() {
        let keypair = MlDsaKeyPair::generate(Variant::MlDsa65).unwrap();
        let message = b"Verify this";
        let signature = keypair.sign(message, None).unwrap();

        // Should verify correctly
        assert!(keypair.verify(message, &signature, None).unwrap());

        // Wrong message should fail (may return false or error)
        let wrong_message = b"Wrong message";
        let result = keypair.verify(wrong_message, &signature, None);
        assert!(matches!(result, Ok(false) | Err(_)));
    }
}
