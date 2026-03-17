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

        let mut public_key_bytes = vec![0u8; variant.public_key_bytes()];

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

                    // Marshal public key to bytes
                    let mut cbb: ffi::mldsa::CBB = std::mem::zeroed();
                    cvt(ffi::mldsa::CBB_init(&mut cbb, variant.public_key_bytes()))?;
                    cvt(ffi::mldsa::MLDSA44_marshal_public_key(&mut cbb, &pub_key))?;

                    let len = ffi::mldsa::CBB_len(&cbb);
                    let data = ffi::mldsa::CBB_data(&cbb);
                    public_key_bytes = std::slice::from_raw_parts(data, len).to_vec();
                    ffi::mldsa::CBB_cleanup(&mut cbb);
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

                    // Marshal public key to bytes
                    let mut cbb: ffi::mldsa::CBB = std::mem::zeroed();
                    cvt(ffi::mldsa::CBB_init(&mut cbb, variant.public_key_bytes()))?;
                    cvt(ffi::mldsa::MLDSA65_marshal_public_key(&mut cbb, &pub_key))?;

                    let len = ffi::mldsa::CBB_len(&cbb);
                    let data = ffi::mldsa::CBB_data(&cbb);
                    public_key_bytes = std::slice::from_raw_parts(data, len).to_vec();
                    ffi::mldsa::CBB_cleanup(&mut cbb);
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

                    // Marshal public key to bytes
                    let mut cbb: ffi::mldsa::CBB = std::mem::zeroed();
                    cvt(ffi::mldsa::CBB_init(&mut cbb, variant.public_key_bytes()))?;
                    cvt(ffi::mldsa::MLDSA87_marshal_public_key(&mut cbb, &pub_key))?;

                    let len = ffi::mldsa::CBB_len(&cbb);
                    let data = ffi::mldsa::CBB_data(&cbb);
                    public_key_bytes = std::slice::from_raw_parts(data, len).to_vec();
                    ffi::mldsa::CBB_cleanup(&mut cbb);
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
#[cfg(all(test, boringssl))]
mod tests_boringssl {
    use super::*;

    #[test]
    fn test_generate_ml_dsa_44() {
        test_generate(Variant::MlDsa44);
    }

    #[test]
    fn test_generate_ml_dsa_65() {
        test_generate(Variant::MlDsa65);
    }

    #[test]
    fn test_generate_ml_dsa_87() {
        test_generate(Variant::MlDsa87);
    }

    fn test_generate(variant: Variant) {
        // Generate a key pair
        let params = PKeyMlDsaParams::<Private>::generate(variant).unwrap();

        // Get public key bytes
        let pub_key_bytes = params.public_key().unwrap();
        assert_eq!(pub_key_bytes.len(), variant.public_key_bytes());

        // Sign a message
        let message = b"Some Crypto Text";
        let signature = params.sign(message, None).unwrap();
        assert_eq!(signature.len(), variant.signature_bytes());

        // Verify the signature
        let public_params = params.to_public();
        let valid = public_params.verify(message, &signature, None).unwrap();
        assert!(valid, "Signature verification failed");
    }

    // Test vector from https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/mldsa/mldsa_nist_keygen_44_tests.txt
    #[test]
    fn test_ml_dsa_nist_keygen_44() {
        let seed = hex::decode("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B")
            .unwrap();
        let correct_pub_key = hex::decode("B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0BD77B16648A344FFE486BC3E3CB5FAB9ABC4CC2F1C34901692BEC5D290D815A6CDF7E9710A3388247A7E0371615507A572C9835E6737BF30B92A796FFF3A10A730C7B550924EB1FB6D56195F02DE6D3746F9F330BEBE990C90C4D676AD415F4268D2D6B548A8BCDF27FDD467E6749C0F87B71E85C2797694772BBA88D4F1AC06C7C0E91786472CD76353708D6BBC5C28E9DB891C3940E879052D30C8FD10965CBB8EE1BD79B060D37FB839098552AABDD3A57AB1C6A82B0911D1CF148654AA5613B07014B21E4A1182B4A5501671D112F5975FB0C8A2AC45D575DC42F48977FF37FFF421DB27C45E79F8A9472007023DF0B64205CD9F57C02CE9D1F61F2AE24F7139F5641984EE8DF783B9EA43E997C6E19D09E062AFCA56E4F76AAAB8F66600FC78F6AB4F6785690D185816EE35A939458B60324EEFC60E64B11FA0D20317ACB6CB29AA03C775F151672952689FA4F8F838329CB9E6DC9945B6C7ADE4E7B663578F87D3935F2A1522097AD5042A0D990A628510B6103CB242CD8A3AFC1A5ADA52331F4DF461BC1DA51D1D224094E7ABED3D87D98F0D817084780EE80370F397631ECB75D4264B6B5E2E66C0586B5FB743516399165837A0FDFF7C6134F033BFA69C1B2416965C6E578592F40E258CB6DFB29FB8E0F54355B6E24A65F67ABAE3193D007115CC0B9FF94CB911A93B1A76C0E7662F5E2B20139E0159ED929CB932D4895F89A02E55C59DF2DBB8F6E5DD7D5B1F3CEC37B4A9166B381C5440E23E67368CDE0A29D59AA05A3C9BE24A4DC8DD75BE30E82BC635D36AAC66DE880C6701A987D7E05F0F2FF287828BEC30595089D8AB9AA390ED719CAA6E576CDBBE9B184A322E5E2DABB69C23CC696D54FC32FF57001B6B64E2A837F3062D85AEB50B3510F7EDFC34DF38E083D4D9B94FFAB0DE15D73D9AF30B9F31CC4F41C9C24F2D618B2A7C3C4BDFB745D52D3EB54589C8BDA8AC05DAD14EC744505575A0988EEC651C1715439FDFB29923380A43C1A66A86C982A841F11820A6A0E1E2F2FFF5108ECAE51A6AABC9B949226D228FF84C4E5E5D63114D80359C4931E612DCED1838B7D066AC9182CECFA223A21A4C8E155AEFA780373BCC15098AEE40C033AF22F8E7C67A0D2526DA7475E830308C04AED9D32BCCC72E719EE70A8D13F09AC11E26EA237D5CC8F98B5AE0E54F933BD0507942ED900D056FD32F8E6E81777912FD482746029B71CCE3BA69B8FC2D03EB441027C387BC2F95031A0AE7052215EB24B9EA8FB0A961B0F80BFA80D0D6257C1C22B508C5D31B97FCDFE1D1766E8A9C8771932DD598ADB7E717743F45FC571F21E4A516249F81D747F15329790F0F70A0B8E461A4EDF50504AF03F30DDF8A8818E38761E1681D6DDEF0B1DD326B2EC228CE48570F285B49D29D7C2EF37866D5446DF82B8E43B34CB248962A21A9A3946159740F8AEE8E6A16A4EB2B42D143FE2612E05EF4B5E646D813248444556A2A8BF92CE10BADECB6B8A40B080DD42D53346FEFCC4B9B40B1E4998991EC753C95AA2F2A506F311E710B0F1D36C1DCA6644EE6D1D4AE9CEA5666EF4B3E888DBDBB95A77ECFE1E8B477DE7CB07639D682D53020EC14EA6C7DD7E715389D10938429FAB8A068A1466A4CD891359F8074E0F5A142ADD731B87878D985E4FA6ECB3B73D298553418273E9503AA84092C080E5F2902F90F5C59944D24CA0271D11D0D6734606D039550A37FCA2B735850E63F540F2F06B79144B5C4ED2C700BB51C33D265B3D037389C99EFD597642D829DB1EB58643CFCD07F4DEC60B8F727D97BD7C4B59BDA1").unwrap();

        let params = PKeyMlDsaParams::<Private>::from_seed(Variant::MlDsa44, &seed).unwrap();
        let pub_key = params.public_key().unwrap();

        assert_eq!(correct_pub_key, pub_key);
    }

    #[test]
    fn test_from_seed_ml_dsa_44() {
        test_from_seed(Variant::MlDsa44);
    }

    #[test]
    fn test_from_seed_ml_dsa_65() {
        test_from_seed(Variant::MlDsa65);
    }

    #[test]
    fn test_from_seed_ml_dsa_87() {
        test_from_seed(Variant::MlDsa87);
    }

    fn test_from_seed(variant: Variant) {
        let seed = [0x42u8; ffi::mldsa::MLDSA_SEED_BYTES];

        // Create key from seed
        let params = PKeyMlDsaParams::<Private>::from_seed(variant, &seed).unwrap();

        // Get public key bytes
        let pub_key_bytes = params.public_key().unwrap();
        assert_eq!(pub_key_bytes.len(), variant.public_key_bytes());

        // Sign a message
        let message = b"Test message";
        let signature = params.sign(message, None).unwrap();
        assert_eq!(signature.len(), variant.signature_bytes());

        // Create the same key again from the same seed - should be deterministic
        let params2 = PKeyMlDsaParams::<Private>::from_seed(variant, &seed).unwrap();
        assert_eq!(params.public_key().unwrap(), params2.public_key().unwrap());
    }

    #[test]
    fn test_sign_with_context() {
        let variant = Variant::MlDsa65;
        let params = PKeyMlDsaParams::<Private>::generate(variant).unwrap();

        let message = b"Test message";
        let context = b"example.com/api/v1";

        // Sign with context
        let sig_with_ctx = params.sign(message, Some(context)).unwrap();
        assert_eq!(sig_with_ctx.len(), variant.signature_bytes());

        // Sign without context - should produce different signature
        let sig_no_ctx = params.sign(message, None).unwrap();
        assert_eq!(sig_no_ctx.len(), variant.signature_bytes());

        // Signatures should be different (probabilistically)
        assert_ne!(sig_with_ctx, sig_no_ctx);
    }
}
