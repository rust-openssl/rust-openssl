//! Module-Lattice-Based Key-Encapsulation Mechanism.
//!
//! ML-KEM is a Key-Encapsulation Mechanism that is believed to be
//! secure against adversaries with quantum computers.  It has been
//! standardized by NIST as [FIPS 203].
//!
//! [FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final

use crate::error::ErrorStack;
use crate::ossl_param::OsslParamArray;
use crate::pkey::Private;
use foreign_types::ForeignType;
use std::ffi::CStr;
use std::marker::PhantomData;

// Safety: these all have null terminators.
// We can remove these CStr::from_bytes_with_nul_unchecked calls
// when we upgrade to Rust 1.77+ with literal c"" syntax.
const OSSL_PKEY_PARAM_SEED: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"seed\0") };
const OSSL_PKEY_PARAM_PUB_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"pub\0") };
const OSSL_PKEY_PARAM_PRIV_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"priv\0") };

const MLKEM512_STR: &str = "ML-KEM-512";
const MLKEM768_STR: &str = "ML-KEM-768";
const MLKEM1024_STR: &str = "ML-KEM-1024";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Variant {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Variant::MlKem512 => MLKEM512_STR,
            Variant::MlKem768 => MLKEM768_STR,
            Variant::MlKem1024 => MLKEM1024_STR,
        }
    }
}

pub struct PKeyMlKemParams<T> {
    params: OsslParamArray,
    _m: PhantomData<T>,
}

impl<T> PKeyMlKemParams<T> {
    /// Creates a new `PKeyMlDsaParams` from OSSL_PARAM. Internal.
    pub(crate) unsafe fn from_params_ptr(params: *mut ffi::OSSL_PARAM) -> Self {
        unsafe {
            PKeyMlKemParams {
                params: OsslParamArray::from_ptr(params),
                _m: PhantomData,
            }
        }
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PUB_KEY)
    }
}

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

#[cfg(test)]
mod tests {

    use crate::{pkey::PKey, pkey_ctx::PkeyCtx};

    use super::*;

    /// Returns the Private ML-KEM PKey from the provided seed.
    fn new_from_seed(variant: Variant, seed: &[u8]) -> Result<PKey<Private>, ErrorStack> {
        use crate::ossl_param::OsslParamBuilder;

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
            Ok(pkey)
        }
    }

    #[test]
    fn test_generate_ml_kem_512() {
        test_generate(Variant::MlKem512);
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
        let key = PKey::<Private>::generate_ml_kem(variant).unwrap();

        // Encapsulate with the original PKEY.
        let (mut wrappedkey, mut genkey0) = (vec![], vec![]);
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.encapsulate_init().unwrap();
        ctx.encapsulate_to_vec(&mut wrappedkey, &mut genkey0)
            .unwrap();

        let mut genkey1 = vec![];
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.decapsulate_init().unwrap();
        ctx.decapsulate_to_vec(&wrappedkey, &mut genkey1).unwrap();

        assert_eq!(genkey0, genkey1);

        // Encapsulate with a PKEY derived from the public parameters.
        let key_pub =
            PKey::public_key_from_raw_bytes_ex(&key.raw_public_key().unwrap(), variant.as_str())
                .unwrap();

        let (mut wrappedkey, mut genkey0) = (vec![], vec![]);
        let mut ctx = PkeyCtx::new(&key_pub).unwrap();
        ctx.encapsulate_init().unwrap();
        ctx.encapsulate_to_vec(&mut wrappedkey, &mut genkey0)
            .unwrap();

        let mut genkey1 = vec![];
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.decapsulate_init().unwrap();
        ctx.decapsulate_to_vec(&wrappedkey, &mut genkey1).unwrap();

        assert_eq!(genkey0, genkey1);

        // Decapsulate with a PKEY derived from the private parameters.
        let key_priv =
            PKey::private_key_from_raw_bytes_ex(&key.raw_private_key().unwrap(), variant.as_str())
                .unwrap();
        let mut genkey1 = vec![];
        let mut ctx = PkeyCtx::new(&key_priv).unwrap();
        ctx.decapsulate_init().unwrap();
        ctx.decapsulate_to_vec(&wrappedkey, &mut genkey1).unwrap();
        assert_eq!(genkey0, genkey1);

        // Decapsulate with a PKEY derived from the private key seed.
        let key_priv = new_from_seed(
            variant,
            key.ml_kem(variant)
                .unwrap()
                .unwrap()
                .private_key_seed()
                .unwrap(),
        )
        .unwrap();
        let mut genkey1 = vec![];
        let mut ctx = PkeyCtx::new(&key_priv).unwrap();
        ctx.decapsulate_init().unwrap();
        ctx.decapsulate_to_vec(&wrappedkey, &mut genkey1).unwrap();
        assert_eq!(genkey0, genkey1);

        // Note that we can get the public parameter from the
        // PKeyMlKemParams::<Private> as well.  The same is not true
        // for ML-DSA, for example.
        assert_eq!(
            key_pub
                .ml_kem(variant)
                .unwrap()
                .unwrap()
                .public_key()
                .unwrap(),
            key_priv
                .ml_kem(variant)
                .unwrap()
                .unwrap()
                .public_key()
                .unwrap()
        );
    }
}
