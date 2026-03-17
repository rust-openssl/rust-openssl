//! Module-Lattice-Based Key-Encapsulation Mechanism.
//!
//! ML-KEM is a Key-Encapsulation Mechanism that is believed to be
//! secure against adversaries with quantum computers.  It has been
//! standardized by NIST as [FIPS 203].
//!
//! Note: BoringSSL only supports ML-KEM-768 and ML-KEM-1024 (not ML-KEM-512).
//!
//! [FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final

#[cfg(boringssl)]
use crate::cvt;
use crate::error::ErrorStack;
#[cfg(ossl350)]
use crate::ossl_param::OsslParamArray;
#[cfg(ossl350)]
use std::ffi::CStr;
use std::marker::PhantomData;

// Re-export type markers
#[cfg(ossl350)]
pub use crate::pkey::Private;

#[cfg(boringssl)]
/// Marker type for private keys
pub enum Private {}

// OpenSSL-specific constants
#[cfg(ossl350)]
const OSSL_PKEY_PARAM_SEED: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"seed\0") };
#[cfg(ossl350)]
const OSSL_PKEY_PARAM_PUB_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"pub\0") };
#[cfg(ossl350)]
const OSSL_PKEY_PARAM_PRIV_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"priv\0") };

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Variant {
    #[cfg(boringssl)]
    fn public_key_bytes(&self) -> usize {
        match self {
            Variant::MlKem512 => panic!("ML-KEM-512 not supported by BoringSSL"),
            Variant::MlKem768 => ffi::mlkem::MLKEM768_PUBLIC_KEY_BYTES,
            Variant::MlKem1024 => ffi::mlkem::MLKEM1024_PUBLIC_KEY_BYTES,
        }
    }

    #[cfg(boringssl)]
    fn ciphertext_bytes(&self) -> usize {
        match self {
            Variant::MlKem512 => panic!("ML-KEM-512 not supported by BoringSSL"),
            Variant::MlKem768 => ffi::mlkem::MLKEM768_CIPHERTEXT_BYTES,
            Variant::MlKem1024 => ffi::mlkem::MLKEM1024_CIPHERTEXT_BYTES,
        }
    }
}

// OpenSSL implementation
#[cfg(ossl350)]
pub struct PKeyMlKemParams<T> {
    params: OsslParamArray,
    _m: PhantomData<T>,
}

// BoringSSL implementation
#[cfg(boringssl)]
pub struct PKeyMlKemParams<T> {
    variant: Variant,
    public_key_bytes: Vec<u8>,
    seed: Option<[u8; ffi::mlkem::MLKEM_SEED_BYTES]>,
    _m: PhantomData<T>,
}

#[cfg(ossl350)]
impl<T> PKeyMlKemParams<T> {
    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PUB_KEY)
    }
}

#[cfg(ossl350)]
impl PKeyMlKemParams<Private> {
    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_SEED)
    }

    /// Returns the private key.
    pub fn private_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PRIV_KEY)
    }
}

#[cfg(boringssl)]
impl<T> PKeyMlKemParams<T> {
    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        Ok(&self.public_key_bytes)
    }
}

#[cfg(boringssl)]
impl PKeyMlKemParams<Private> {
    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.seed
            .as_ref()
            .map(|s| s.as_slice())
            .ok_or_else(|| ErrorStack::get())
    }

    /// Generate a new keypair.
    pub fn generate(variant: Variant) -> Result<Self, ErrorStack> {
        if variant == Variant::MlKem512 {
            // BoringSSL doesn't support ML-KEM-512
            return Err(ErrorStack::get());
        }

        let mut public_key_bytes = vec![0u8; variant.public_key_bytes()];
        let mut seed = [0u8; ffi::mlkem::MLKEM_SEED_BYTES];

        match variant {
            Variant::MlKem512 => unreachable!(),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    ffi::mlkem::MLKEM768_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    );
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    ffi::mlkem::MLKEM1024_generate_key(
                        public_key_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        &mut priv_key,
                    );
                }
            }
        }

        Ok(PKeyMlKemParams {
            variant,
            public_key_bytes,
            seed: Some(seed),
            _m: PhantomData,
        })
    }

    /// Create from seed.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<Self, ErrorStack> {
        if variant == Variant::MlKem512 {
            return Err(ErrorStack::get());
        }
        if seed.len() != ffi::mlkem::MLKEM_SEED_BYTES {
            return Err(ErrorStack::get());
        }

        let public_key_bytes: Vec<u8>;

        match variant {
            Variant::MlKem512 => unreachable!(),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM768_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mlkem::MLKEM768_public_key {
                        opaque: ffi::mlkem::MLKEM768_public_key_union { alignment: 0 },
                    };
                    ffi::mlkem::MLKEM768_public_from_private(&mut pub_key, &priv_key);

                    // Marshal public key to bytes
                    let mut cbb: ffi::mlkem::CBB = std::mem::zeroed();
                    cvt(ffi::mlkem::CBB_init(&mut cbb, variant.public_key_bytes()))?;
                    cvt(ffi::mlkem::MLKEM768_marshal_public_key(&mut cbb, &pub_key))?;

                    let len = ffi::mlkem::CBB_len(&cbb);
                    let data = ffi::mlkem::CBB_data(&cbb);
                    public_key_bytes = std::slice::from_raw_parts(data, len).to_vec();
                    ffi::mlkem::CBB_cleanup(&mut cbb);
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM1024_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mlkem::MLKEM1024_public_key {
                        opaque: ffi::mlkem::MLKEM1024_public_key_union { alignment: 0 },
                    };
                    ffi::mlkem::MLKEM1024_public_from_private(&mut pub_key, &priv_key);

                    // Marshal public key to bytes
                    let mut cbb: ffi::mlkem::CBB = std::mem::zeroed();
                    cvt(ffi::mlkem::CBB_init(&mut cbb, variant.public_key_bytes()))?;
                    cvt(ffi::mlkem::MLKEM1024_marshal_public_key(&mut cbb, &pub_key))?;

                    let len = ffi::mlkem::CBB_len(&cbb);
                    let data = ffi::mlkem::CBB_data(&cbb);
                    public_key_bytes = std::slice::from_raw_parts(data, len).to_vec();
                    ffi::mlkem::CBB_cleanup(&mut cbb);
                }
            }
        }

        let mut seed_arr = [0u8; ffi::mlkem::MLKEM_SEED_BYTES];
        seed_arr.copy_from_slice(seed);

        Ok(PKeyMlKemParams {
            variant,
            public_key_bytes,
            seed: Some(seed_arr),
            _m: PhantomData,
        })
    }

    /// Decapsulate a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let seed = self.seed.as_ref().ok_or_else(|| ErrorStack::get())?;
        let mut shared_secret = vec![0u8; ffi::mlkem::MLKEM_SHARED_SECRET_BYTES];

        match self.variant {
            Variant::MlKem512 => return Err(ErrorStack::get()),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM768_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mlkem::MLKEM768_decap(
                        shared_secret.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        &priv_key,
                    ))?;
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM1024_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    cvt(ffi::mlkem::MLKEM1024_decap(
                        shared_secret.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        &priv_key,
                    ))?;
                }
            }
        }

        Ok(shared_secret)
    }

    /// Encapsulate to generate a ciphertext and shared secret.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let seed = self.seed.as_ref().ok_or_else(|| ErrorStack::get())?;
        let mut ciphertext = vec![0u8; self.variant.ciphertext_bytes()];
        let mut shared_secret = vec![0u8; ffi::mlkem::MLKEM_SHARED_SECRET_BYTES];

        match self.variant {
            Variant::MlKem512 => return Err(ErrorStack::get()),
            Variant::MlKem768 => {
                let mut priv_key = ffi::mlkem::MLKEM768_private_key {
                    opaque: ffi::mlkem::MLKEM768_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM768_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mlkem::MLKEM768_public_key {
                        opaque: ffi::mlkem::MLKEM768_public_key_union { alignment: 0 },
                    };
                    ffi::mlkem::MLKEM768_public_from_private(&mut pub_key, &priv_key);
                    ffi::mlkem::MLKEM768_encap(
                        ciphertext.as_mut_ptr(),
                        shared_secret.as_mut_ptr(),
                        &pub_key,
                    );
                }
            }
            Variant::MlKem1024 => {
                let mut priv_key = ffi::mlkem::MLKEM1024_private_key {
                    opaque: ffi::mlkem::MLKEM1024_private_key_union { alignment: 0 },
                };
                unsafe {
                    cvt(ffi::mlkem::MLKEM1024_private_key_from_seed(
                        &mut priv_key,
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    let mut pub_key = ffi::mlkem::MLKEM1024_public_key {
                        opaque: ffi::mlkem::MLKEM1024_public_key_union { alignment: 0 },
                    };
                    ffi::mlkem::MLKEM1024_public_from_private(&mut pub_key, &priv_key);
                    ffi::mlkem::MLKEM1024_encap(
                        ciphertext.as_mut_ptr(),
                        shared_secret.as_mut_ptr(),
                        &pub_key,
                    );
                }
            }
        }

        Ok((ciphertext, shared_secret))
    }
}

#[cfg(all(test, boringssl))]
mod tests_boringssl {
    use super::*;

    #[test]
    fn test_generate_ml_kem_512() {
        // ML-KEM-512 is not supported by BoringSSL
        let result = PKeyMlKemParams::<Private>::generate(Variant::MlKem512);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_ml_kem_768() {
        test_generate(Variant::MlKem768);
    }

    #[test]
    fn test_generate_ml_kem_1024() {
        test_generate(Variant::MlKem1024);
    }

    fn test_generate(variant: Variant) {
        let params = PKeyMlKemParams::<Private>::generate(variant).unwrap();

        let pub_key_bytes = params.public_key().unwrap();
        assert_eq!(pub_key_bytes.len(), variant.public_key_bytes());

        let (ciphertext, secret1) = params.encapsulate().unwrap();
        assert_eq!(ciphertext.len(), variant.ciphertext_bytes());
        assert_eq!(secret1.len(), ffi::mlkem::MLKEM_SHARED_SECRET_BYTES);

        let secret2 = params.decapsulate(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
    }

    // Test vector from https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/mlkem/mlkem1024_keygen_tests.txt
    #[test]
    fn test_ml_kem_boringssl_keygen() {
        let seed = hex::decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f").unwrap();
        let correct_pub_key = hex::decode("537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f2944016ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b7949958f2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e72c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb7042db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f65988949a75580d049639853100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812eff3340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa048989233079aeb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c730c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f1853273555199a649318b50773345c997460856972acb43fc81ab6321b1c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c805503c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa7224461a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d173854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abfbad10738ad04cc752bc20c394746850e0c4847db").unwrap();

        let params = PKeyMlKemParams::<Private>::from_seed(Variant::MlKem1024, &seed).unwrap();
        let pub_key = params.public_key().unwrap();

        assert_eq!(correct_pub_key, pub_key);
    }

    #[test]
    fn test_from_seed_ml_kem_768() {
        test_from_seed(Variant::MlKem768);
    }

    #[test]
    fn test_from_seed_ml_kem_1024() {
        test_from_seed(Variant::MlKem1024);
    }

    fn test_from_seed(variant: Variant) {
        let seed = [0x42u8; ffi::mlkem::MLKEM_SEED_BYTES];

        // Create key from seed
        let params = PKeyMlKemParams::<Private>::from_seed(variant, &seed).unwrap();

        // Get public key bytes
        let pub_key_bytes = params.public_key().unwrap();
        assert_eq!(pub_key_bytes.len(), variant.public_key_bytes());

        // Create the same key again from the same seed - should be deterministic
        let params2 = PKeyMlKemParams::<Private>::from_seed(variant, &seed).unwrap();
        assert_eq!(params.public_key().unwrap(), params2.public_key().unwrap());
    }

    #[test]
    fn test_decapsulate_ml_kem_768() {
        test_decapsulate(Variant::MlKem768);
    }

    #[test]
    fn test_decapsulate_ml_kem_1024() {
        test_decapsulate(Variant::MlKem1024);
    }

    fn test_decapsulate(variant: Variant) {
        let params = PKeyMlKemParams::<Private>::generate(variant).unwrap();

        let (ciphertext, secret1) = params.encapsulate().unwrap();
        let secret2 = params.decapsulate(&ciphertext).unwrap();
        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), ffi::mlkem::MLKEM_SHARED_SECRET_BYTES);
    }
}
