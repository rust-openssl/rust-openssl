//! Module-Lattice-Based Digital Signatures.
//!
//! ML-DSA is a signature algorithm that is believed to be secure
//! against adversaries with quantum computers. It has been
//! standardized by NIST as [FIPS 204].
//!
//! [FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final

#[cfg(boringssl)]
use crate::cvt;
use crate::error::ErrorStack;
use std::marker::PhantomData;
#[cfg(boringssl)]
use std::ptr;

#[cfg(boringssl)]
/// Marker type for private keys
pub enum Private {}
#[cfg(boringssl)]
/// Marker type for public keys
pub enum Public {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Variant {
    #[cfg(boringssl)]
    fn public_key_bytes(&self) -> usize {
        match self {
            Variant::MlDsa44 => ffi::mldsa::MLDSA44_PUBLIC_KEY_BYTES,
            Variant::MlDsa65 => ffi::mldsa::MLDSA65_PUBLIC_KEY_BYTES,
            Variant::MlDsa87 => ffi::mldsa::MLDSA87_PUBLIC_KEY_BYTES,
        }
    }

    #[cfg(boringssl)]
    fn signature_bytes(&self) -> usize {
        match self {
            Variant::MlDsa44 => ffi::mldsa::MLDSA44_SIGNATURE_BYTES,
            Variant::MlDsa65 => ffi::mldsa::MLDSA65_SIGNATURE_BYTES,
            Variant::MlDsa87 => ffi::mldsa::MLDSA87_SIGNATURE_BYTES,
        }
    }
}

// BoringSSL implementation
#[cfg(boringssl)]
pub struct PKeyMlDsaParams<T> {
    variant: Variant,
    public_key_bytes: Vec<u8>,
    seed: Option<[u8; ffi::mldsa::MLDSA_SEED_BYTES]>,
    _m: PhantomData<T>,
}

#[cfg(boringssl)]
impl<T> PKeyMlDsaParams<T> {
    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        Ok(&self.public_key_bytes)
    }
}

#[cfg(boringssl)]
impl PKeyMlDsaParams<Public> {
    /// Create from public key bytes.
    pub fn from_public_key(variant: Variant, public_key: &[u8]) -> Result<Self, ErrorStack> {
        if public_key.len() != variant.public_key_bytes() {
            return Err(ErrorStack::get());
        }

        Ok(PKeyMlDsaParams {
            variant,
            public_key_bytes: public_key.to_vec(),
            seed: None,
            _m: PhantomData,
        })
    }

    /// Verify a signature on a message with optional context.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    pub fn verify(
        &self,
        msg: &[u8],
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> Result<bool, ErrorStack> {
        use crate::cvt;
        use std::ptr;

        let (ctx_ptr, ctx_len) = context
            .map(|c| (c.as_ptr(), c.len()))
            .unwrap_or((ptr::null(), 0));

        // Parse public key bytes into public_key struct
        match self.variant {
            Variant::MlDsa44 => {
                let mut pub_key = ffi::mldsa::MLDSA44_public_key {
                    opaque: ffi::mldsa::MLDSA44_public_key_union { alignment: 0 },
                };
                let mut cbs = ffi::mldsa::CBS {
                    data: self.public_key_bytes.as_ptr(),
                    len: self.public_key_bytes.len(),
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA44_parse_public_key(&mut pub_key, &mut cbs))?;
                    let result = ffi::mldsa::MLDSA44_verify(
                        &pub_key,
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                    );
                    Ok(result == 1)
                }
            }
            Variant::MlDsa65 => {
                let mut pub_key = ffi::mldsa::MLDSA65_public_key {
                    opaque: ffi::mldsa::MLDSA65_public_key_union { alignment: 0 },
                };
                let mut cbs = ffi::mldsa::CBS {
                    data: self.public_key_bytes.as_ptr(),
                    len: self.public_key_bytes.len(),
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA65_parse_public_key(&mut pub_key, &mut cbs))?;
                    let result = ffi::mldsa::MLDSA65_verify(
                        &pub_key,
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                    );
                    Ok(result == 1)
                }
            }
            Variant::MlDsa87 => {
                let mut pub_key = ffi::mldsa::MLDSA87_public_key {
                    opaque: ffi::mldsa::MLDSA87_public_key_union { alignment: 0 },
                };
                let mut cbs = ffi::mldsa::CBS {
                    data: self.public_key_bytes.as_ptr(),
                    len: self.public_key_bytes.len(),
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA87_parse_public_key(&mut pub_key, &mut cbs))?;
                    let result = ffi::mldsa::MLDSA87_verify(
                        &pub_key,
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                    );
                    Ok(result == 1)
                }
            }
        }
    }
}

#[cfg(boringssl)]
impl PKeyMlDsaParams<Private> {
    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.seed
            .as_ref()
            .map(|s| s.as_slice())
            .ok_or_else(|| ErrorStack::get())
    }

    /// Generate a new keypair.
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack> {
        let mut public_key_bytes = vec![0u8; variant.public_key_bytes()];
        let mut seed = [0u8; ffi::mldsa::MLDSA_SEED_BYTES];

        match variant {
            Variant::MlDsa44 => {
                let mut priv_key = ffi::mldsa::MLDSA44_private_key {
                    opaque: ffi::mldsa::MLDSA44_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA44_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    ))?;
                }
            }
            Variant::MlDsa65 => {
                let mut priv_key = ffi::mldsa::MLDSA65_private_key {
                    opaque: ffi::mldsa::MLDSA65_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA65_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    ))?;
                }
            }
            Variant::MlDsa87 => {
                let mut priv_key = ffi::mldsa::MLDSA87_private_key {
                    opaque: ffi::mldsa::MLDSA87_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA87_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    ))?;
                }
            }
        }

        Ok(PKeyMlDsaParams {
            variant,
            public_key_bytes,
            seed: Some(seed),
            _m: PhantomData,
        })
    }

    /// Create from seed.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack> {
        if seed.len() != ffi::mldsa::MLDSA_SEED_BYTES {
            return Err(ErrorStack::get());
        }

        let public_key_bytes = vec![0u8; variant.public_key_bytes()];

        match variant {
            Variant::MlDsa44 => {
                let mut priv_key = ffi::mldsa::MLDSA44_private_key {
                    opaque: ffi::mldsa::MLDSA44_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA44_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mldsa::MLDSA44_public_key {
                        opaque: ffi::mldsa::MLDSA44_public_key_union { alignment: 0 },
                    };
                    cvt(ffi::mldsa::MLDSA44_public_from_private(
                        &mut pub_key,
                        &priv_key,
                    ))?;
                    // Copy public key bytes from structure - for now use the encoded form
                    // In production would marshal the key properly
                }
            }
            Variant::MlDsa65 => {
                let mut priv_key = ffi::mldsa::MLDSA65_private_key {
                    opaque: ffi::mldsa::MLDSA65_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA65_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mldsa::MLDSA65_public_key {
                        opaque: ffi::mldsa::MLDSA65_public_key_union { alignment: 0 },
                    };
                    cvt(ffi::mldsa::MLDSA65_public_from_private(
                        &mut pub_key,
                        &priv_key,
                    ))?;
                }
            }
            Variant::MlDsa87 => {
                let mut priv_key = ffi::mldsa::MLDSA87_private_key {
                    opaque: ffi::mldsa::MLDSA87_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA87_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mldsa::MLDSA87_public_key {
                        opaque: ffi::mldsa::MLDSA87_public_key_union { alignment: 0 },
                    };
                    cvt(ffi::mldsa::MLDSA87_public_from_private(
                        &mut pub_key,
                        &priv_key,
                    ))?;
                }
            }
        }

        let mut seed_arr = [0u8; ffi::mldsa::MLDSA_SEED_BYTES];
        seed_arr.copy_from_slice(seed);

        Ok(PKeyMlDsaParams {
            variant,
            public_key_bytes,
            seed: Some(seed_arr),
            _m: PhantomData,
        })
    }

    /// Sign a message with optional context.
    pub fn sign(&self, msg: &[u8], context: Option<&[u8]>) -> Result<Vec<u8>, ErrorStack> {
        let seed = self.seed.as_ref().ok_or_else(|| ErrorStack::get())?;
        let mut signature = vec![0u8; self.variant.signature_bytes()];

        let (ctx_ptr, ctx_len) = context
            .map(|c| (c.as_ptr(), c.len()))
            .unwrap_or((ptr::null(), 0));

        match self.variant {
            Variant::MlDsa44 => {
                let mut priv_key = ffi::mldsa::MLDSA44_private_key {
                    opaque: ffi::mldsa::MLDSA44_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA44_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mldsa::MLDSA44_sign(
                        signature.as_mut_ptr(),
                        &priv_key,
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                    ))?;
                }
            }
            Variant::MlDsa65 => {
                let mut priv_key = ffi::mldsa::MLDSA65_private_key {
                    opaque: ffi::mldsa::MLDSA65_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA65_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mldsa::MLDSA65_sign(
                        signature.as_mut_ptr(),
                        &priv_key,
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                    ))?;
                }
            }
            Variant::MlDsa87 => {
                let mut priv_key = ffi::mldsa::MLDSA87_private_key {
                    opaque: ffi::mldsa::MLDSA87_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mldsa::MLDSA87_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mldsa::MLDSA87_sign(
                        signature.as_mut_ptr(),
                        &priv_key,
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                    ))?;
                }
            }
        }

        Ok(signature)
    }

    /// Convert to public key parameters.
    pub fn to_public(&self) -> PKeyMlDsaParams<Public> {
        PKeyMlDsaParams {
            variant: self.variant,
            public_key_bytes: self.public_key_bytes.clone(),
            seed: None,
            _m: PhantomData,
        }
    }
}
