use crate::bio::MemBio;
use crate::error::ErrorStack;
use crate::pkey::PKeyRef;
use crate::pkey_ctx::Selection;
use crate::symm::Cipher;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::{CStr, CString};
use std::ptr;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyFormat {
    /// Human-readable description of the key.
    Text,
    /// DER formatted data
    Der,
    /// PEM formatted data
    Pem,
    // MSBLOB formatted data
    MsBlob,
    // PVK formatted data
    Pvk,
}

impl From<&CStr> for KeyFormat {
    fn from(s: &CStr) -> Self {
        match s.to_bytes() {
            b"TEXT" => Self::Text,
            b"DER" => Self::Der,
            b"PEM" => Self::Pem,
            b"MSBLOB" => Self::MsBlob,
            b"PVK" => Self::Pvk,
            _ => panic!("Unknown output type"),
        }
    }
}

cstr_const!(KEY_FORMAT_TEXT, b"TEXT\0");
cstr_const!(KEY_FORMAT_DER, b"DER\0");
cstr_const!(KEY_FORMAT_PEM, b"PEM\0");
cstr_const!(KEY_FORMAT_MSBLOB, b"MSBLOB\0");
cstr_const!(KEY_FORMAT_PVK, b"PVK\0");

impl From<KeyFormat> for &CStr {
    fn from(o: KeyFormat) -> Self {
        match o {
            KeyFormat::Text => KEY_FORMAT_TEXT,
            KeyFormat::Der => KEY_FORMAT_DER,
            KeyFormat::Pem => KEY_FORMAT_PEM,
            KeyFormat::MsBlob => KEY_FORMAT_MSBLOB,
            KeyFormat::Pvk => KEY_FORMAT_PVK,
        }
    }
}

pub enum Structure<'a> {
    /// Encoding of public keys according to the Subject Public Key Info of RFC 5280
    SubjectPublicKeyInfo,
    /// Structure according to the PKCS#1 specification
    PKCS1,
    /// Structure according to the PKCS#8 specification
    PKCS8,
    /// Type-specific structure
    TypeSpecific,
    Other(&'a CStr),
}

impl<'a> From<&'a CStr> for Structure<'a> {
    fn from(s: &'a CStr) -> Self {
        match s.to_bytes() {
            b"SubjectPublicKeyInfo" => Self::SubjectPublicKeyInfo,
            b"pkcs1" => Self::PKCS1,
            b"pkcs8" => Self::PKCS8,
            b"type-specific" => Self::TypeSpecific,
            _ => Self::Other(s),
        }
    }
}

cstr_const!(STRUCTURE_SUBJECT_PUBLIC_KEY_INFO, b"SubjectPublicKeyInfo\0");
cstr_const!(STRUCTURE_PKCS1, b"pkcs1\0");
cstr_const!(STRUCTURE_PKCS8, b"pkcs8\0");
cstr_const!(STRUCTURE_TYPE_SPECIFIC, b"type-specific\0");

impl<'a> From<Structure<'a>> for &'a CStr {
    fn from(o: Structure<'a>) -> Self {
        match o {
            Structure::SubjectPublicKeyInfo => STRUCTURE_SUBJECT_PUBLIC_KEY_INFO,
            Structure::PKCS1 => STRUCTURE_PKCS1,
            Structure::PKCS8 => STRUCTURE_PKCS8,
            Structure::TypeSpecific => STRUCTURE_TYPE_SPECIFIC,
            Structure::Other(v) => v,
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_ENCODER_CTX;
    fn drop = ffi::OSSL_ENCODER_CTX_free;

    /// A context object which can perform encode operations.
    pub struct OsslEncoderCtx;
    /// A reference to an [`OsslEncoderCtx`].
    pub struct OsslEncoderCtxRef;
}

impl OsslEncoderCtx {
    /// Creates a new encoder context using the provided key.
    #[corresponds(OSSL_ENCODER_CTX_new_for_pkey)]
    #[inline]
    #[allow(dead_code)]
    fn new_for_key<T>(
        pkey: &PKeyRef<T>,
        selection: Selection,
        output: Option<KeyFormat>,
        structure: Option<Structure<'_>>,
    ) -> Result<Self, ErrorStack> {
        let output_ptr = output
            .map(|o| {
                let output: &CStr = o.into();
                output.as_ptr()
            })
            .unwrap_or_else(ptr::null);
        let structure_ptr = structure
            .map(|s| {
                let structure: &CStr = s.into();
                structure.as_ptr()
            })
            .unwrap_or_else(ptr::null);

        unsafe {
            let ptr = cvt_p(ffi::OSSL_ENCODER_CTX_new_for_pkey(
                pkey.as_ptr(),
                selection.into(),
                output_ptr,
                structure_ptr,
                ptr::null(),
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}

impl OsslEncoderCtxRef {
    // XXX: Because the only way to create an `EncoderCtx` is through `new_for_key`, don't expose
    //  set_selection, because it doesn't work if OSSL_ENCODER_CTX_new_for_key is called!
    //  See https://github.com/openssl/openssl/issues/28249
    // /// Select which parts of the key to encode.
    // #[corresponds(OSSL_ENCODER_CTX_set_selection)]
    // #[allow(dead_code)]
    // pub fn set_selection(&mut self, selection: Selection) -> Result<(), ErrorStack> {
    //     cvt(unsafe { ffi::OSSL_ENCODER_CTX_set_selection(self.as_ptr(), selection.into()) })
    //         .map(|_| ())
    // }

    /// Set the output type for the encoded data.
    #[corresponds(OSSL_ENCODER_CTX_set_output_type)]
    #[allow(dead_code)]
    fn set_output_type(&mut self, output: KeyFormat) -> Result<(), ErrorStack> {
        let output: &CStr = output.into();
        cvt(unsafe { ffi::OSSL_ENCODER_CTX_set_output_type(self.as_ptr(), output.as_ptr()) })
            .map(|_| ())
    }

    /// Set the output structure for the encoded data.
    #[corresponds(OSSL_ENCODER_CTX_set_output_structure)]
    #[allow(dead_code)]
    fn set_output_structure(&mut self, structure: Structure<'_>) -> Result<(), ErrorStack> {
        let structure: &CStr = structure.into();
        cvt(unsafe {
            ffi::OSSL_ENCODER_CTX_set_output_structure(self.as_ptr(), structure.as_ptr())
        })
        .map(|_| ())
    }

    /// Set the (optional) output cipher for the encoded data.
    ///
    /// If `cipher` is `None`, no cipher will be used (i.e., the output will not be encrypted).
    #[corresponds(OSSL_ENCODER_CTX_set_cipher)]
    #[allow(dead_code)]
    fn set_cipher(&mut self, cipher: Option<Cipher>) -> Result<(), ErrorStack> {
        let cipher_name = cipher.map(|c| CString::new(c.nid().short_name().unwrap()).unwrap());
        cvt(unsafe {
            ffi::OSSL_ENCODER_CTX_set_cipher(
                self.as_ptr(),
                cipher_name.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                ptr::null(),
            )
        })
        .map(|_| ())
    }

    /// Set the passphrase for the encoded data.
    #[corresponds(OSSL_ENCODER_CTX_set_passphrase)]
    #[allow(dead_code)]
    fn set_passphrase(&mut self, passphrase: &[u8]) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::OSSL_ENCODER_CTX_set_passphrase(
                self.as_ptr(),
                passphrase.as_ptr().cast(),
                passphrase.len(),
            )
        })
        .map(|_| ())
    }

    /// Encode the data and return the result
    #[corresponds(OSSL_ENCODER_to_bio)]
    #[allow(dead_code)]
    fn encode(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let bio = MemBio::new()?;
        unsafe {
            cvt(ffi::OSSL_ENCODER_to_bio(self.as_ptr(), bio.as_ptr()))?;
        }

        Ok(bio.get_buf().to_owned())
    }
}

pub struct Encoder<'a> {
    selection: Selection,
    format: Option<KeyFormat>,
    structure: Option<Structure<'a>>,
    cipher: Option<Cipher>,
    passphrase: Option<&'a [u8]>,
}

impl<'a> Encoder<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(selection: Selection) -> Self {
        Self {
            selection,
            format: None,
            structure: None,
            cipher: None,
            passphrase: None,
        }
    }

    #[allow(dead_code)]
    pub fn set_format(mut self, format: KeyFormat) -> Self {
        self.format = Some(format);
        self
    }

    #[allow(dead_code)]
    pub fn set_structure(mut self, structure: Structure<'a>) -> Self {
        self.structure = Some(structure);
        self
    }

    #[allow(dead_code)]
    pub fn set_cipher(mut self, cipher: Cipher) -> Self {
        self.cipher = Some(cipher);
        self
    }

    #[allow(dead_code)]
    pub fn set_passphrase(mut self, passphrase: &'a [u8]) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    #[allow(dead_code)]
    pub fn encode<T>(self, pkey: &PKeyRef<T>) -> Result<Vec<u8>, ErrorStack> {
        let mut ctx =
            OsslEncoderCtx::new_for_key(pkey, self.selection, self.format, self.structure)?;

        ctx.set_cipher(self.cipher)?;
        if let Some(passphrase) = self.passphrase {
            ctx.set_passphrase(passphrase)?;
        }

        ctx.encode()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pkey::PKey;
    use crate::rsa::Rsa;
    use std::str::from_utf8;

    mod output {
        use super::*;
        #[test]
        fn test_output_from_cstr() {
            let text: KeyFormat = KEY_FORMAT_TEXT.into();
            let der: KeyFormat = KEY_FORMAT_DER.into();
            let pem: KeyFormat = KEY_FORMAT_PEM.into();

            assert_eq!(text, KeyFormat::Text);
            assert_eq!(der, KeyFormat::Der);
            assert_eq!(pem, KeyFormat::Pem);
        }

        #[test]
        fn test_cstr_from_output() {
            let text: &CStr = KeyFormat::Text.into();
            let der: &CStr = KeyFormat::Der.into();
            let pem: &CStr = KeyFormat::Pem.into();

            assert_eq!(text.to_bytes(), b"TEXT");
            assert_eq!(der.to_bytes(), b"DER");
            assert_eq!(pem.to_bytes(), b"PEM");
        }
    }

    mod encoder {
        use super::*;

        mod params {
            use super::*;
            use crate::dh::Dh;
            use crate::pkey::Params;
            use crate::pkey_ctx::PkeyCtx;

            fn generate_dh_params() -> Result<PKey<Params>, ErrorStack> {
                let mut ctx = PkeyCtx::new_id(Id::DH)?;
                ctx.paramgen_init()?;
                ctx.set_dh_paramgen_prime_len(512)?;
                ctx.set_dh_paramgen_generator(2)?;
                ctx.paramgen()
            }

            #[test]
            fn test_dh_pem() {
                let pkey = generate_dh_params().unwrap();

                // Serialise params to PEM
                let pem = Encoder::new(Selection::KeyParameters)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::TypeSpecific)
                    .encode(&pkey)
                    .unwrap();
                let pem_str = from_utf8(&pem).unwrap();

                // We should be able to load the params back into a key
                assert!(
                    pem_str.contains("-----BEGIN DH PARAMETERS-----"),
                    "{pem_str}"
                );
                let pem_key = Dh::params_from_pem(&pem).unwrap();
                assert_eq!(pem_key.prime_p(), pkey.dh().unwrap().prime_p());
            }

            #[test]
            fn test_dh_der() {
                let pkey = generate_dh_params().unwrap();

                // Serialise parms to PEM
                let der = Encoder::new(Selection::KeyParameters)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::TypeSpecific)
                    .encode(&pkey)
                    .unwrap();

                // DER is not valid UTF-8, so we can't convert it to a string
                assert!(from_utf8(&der).is_err());

                // We should be able to load the DER back into a key
                let der_key = Dh::params_from_der(&der).unwrap();
                assert_eq!(der_key.prime_p(), pkey.dh().unwrap().prime_p());
            }
        }

        mod public {
            use super::*;

            #[test]
            fn test_rsa_pem() {
                let expected = include_bytes!("../test/rsa.pem.pub");
                let pkey = PKey::public_key_from_pem(expected).unwrap();

                // Serialise public key to PEM
                let pem = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::SubjectPublicKeyInfo)
                    .encode(&pkey)
                    .unwrap();

                // We should end up with the same PEM as the input
                assert_eq!(
                    from_utf8(&pem).unwrap(),
                    from_utf8(expected).unwrap().replace("\r\n", "\n")
                );
            }

            #[test]
            fn test_rsa_pem_pkcs1() {
                let expected = include_bytes!("../test/pkcs1.pem.pub");
                let pkey = PKey::public_key_from_pem(expected).unwrap();

                // Serialise public key to PEM
                let pem = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .encode(&pkey)
                    .unwrap();

                // We should end up with the same PEM as the input
                assert_eq!(
                    from_utf8(&pem).unwrap(),
                    from_utf8(expected).unwrap().replace("\r\n", "\n")
                );
            }

            #[test]
            fn test_rsa_der() {
                let expected = include_bytes!("../test/key.der.pub");
                let pkey = PKey::public_key_from_der(expected).unwrap();

                // Serialise public key to DER
                let der = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::SubjectPublicKeyInfo)
                    .encode(&pkey)
                    .unwrap();

                // We should end up with the same DER as the input
                assert_eq!(der, expected);
            }

            #[test]
            fn test_rsa_der_pkcs1() {
                let expected = include_bytes!("../test/rsa.pem.pub");
                let pkey = PKey::public_key_from_pem(expected).unwrap();

                // Serialise public key to DER
                let der = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::PKCS1)
                    .encode(&pkey)
                    .unwrap();

                // We should be able to load the DER back into a key
                let der_key = Rsa::public_key_from_der_pkcs1(&der).unwrap();
                assert_eq!(der_key.n(), pkey.rsa().unwrap().n());
                assert_eq!(der_key.e(), pkey.rsa().unwrap().e());
            }
        }

        mod public_from_private {
            use super::*;

            #[test]
            fn test_rsa_pem() {
                let pkey = PKey::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();

                // Serialise the public key to PEM
                let pem = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::SubjectPublicKeyInfo)
                    .encode(&pkey)
                    .unwrap();

                // Check that we have a public key PEM, and that we can load it back
                let pem_str = from_utf8(&pem).unwrap();
                assert!(pem_str.contains("-----BEGIN PUBLIC KEY-----"), "{pem_str}");

                let pem_key = Rsa::public_key_from_pem(&pem).unwrap();
                assert_eq!(pem_key.n(), pkey.rsa().unwrap().n());
                assert_eq!(pem_key.e(), pkey.rsa().unwrap().e());
            }

            #[test]
            fn test_rsa_pem_pkcs1() {
                let pkey = PKey::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();

                // Serialise the public key to PEM
                let pem = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .encode(&pkey)
                    .unwrap();

                // Check that we have a public key PEM, and that we can load it back
                let pem_str = from_utf8(&pem).unwrap();
                assert!(
                    pem_str.contains("-----BEGIN RSA PUBLIC KEY-----"),
                    "{pem_str}"
                );

                let pem_key = Rsa::public_key_from_pem_pkcs1(&pem).unwrap();
                assert_eq!(pem_key.n(), pkey.rsa().unwrap().n());
                assert_eq!(pem_key.e(), pkey.rsa().unwrap().e());
            }

            #[test]
            fn test_rsa_der() {
                let pkey = PKey::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();

                // Serialise the public key to DER
                let der = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::SubjectPublicKeyInfo)
                    .encode(&pkey)
                    .unwrap();

                // DER is not valid UTF-8, so we can't convert it to a string
                assert!(from_utf8(&der).is_err());

                // We should be able to load the DER back into a key
                let der_key = Rsa::public_key_from_der(&der).unwrap();
                assert_eq!(der_key.n(), pkey.rsa().unwrap().n());
                assert_eq!(der_key.e(), pkey.rsa().unwrap().e());
            }

            #[test]
            fn test_rsa_der_pkcs1() {
                let pkey = PKey::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();

                // Serialise the public key to DER
                let der = Encoder::new(Selection::PublicKey)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::PKCS1)
                    .encode(&pkey)
                    .unwrap();

                // DER is not valid UTF-8, so we can't convert it to a string
                assert!(from_utf8(&der).is_err());

                // We should be able to load the DER back into a key
                let der_key = Rsa::public_key_from_der_pkcs1(&der).unwrap();
                assert_eq!(der_key.n(), pkey.rsa().unwrap().n());
                assert_eq!(der_key.e(), pkey.rsa().unwrap().e());
            }
        }

        mod private {
            use super::*;

            #[test]
            fn test_rsa_pem() {
                let expected = include_bytes!("../test/rsa.pem");
                let pkey = PKey::private_key_from_pem(expected).unwrap();

                // Serialise private key to PEM
                let pem = Encoder::new(Selection::Keypair)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .encode(&pkey)
                    .unwrap();

                assert_eq!(
                    from_utf8(&pem).unwrap(),
                    from_utf8(expected).unwrap().replace("\r\n", "\n")
                );
            }

            #[test]
            fn test_rsa_pem_encrypted() {
                let pkey = PKey::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();

                // Serialise private to an encrypted PEM
                let passphrase = b"hunter2";
                let pem = Encoder::new(Selection::Keypair)
                    .set_format(KeyFormat::Pem)
                    .set_cipher(Cipher::aes_256_cbc())
                    .set_passphrase(passphrase)
                    .encode(&pkey)
                    .unwrap();

                // Check that we have an encrypted PEM
                let pem_str = from_utf8(&pem).unwrap();
                assert!(pem_str.contains("ENCRYPTED"), "{pem_str}");

                // Check that we can load the PEM back into a key
                let pkey2 =
                    Rsa::private_key_from_pem_passphrase(pem.as_slice(), passphrase).unwrap();
                assert_eq!(pkey2.p(), pkey.rsa().unwrap().p());
                assert_eq!(pkey2.q(), pkey.rsa().unwrap().q());
                assert_eq!(pkey2.d(), pkey.rsa().unwrap().d());
            }

            #[test]
            fn test_rsa_der() {
                let expected = include_bytes!("../test/rsa.der");
                let pkey = PKey::private_key_from_der(expected).unwrap();

                // Serialise private key to DER
                let der = Encoder::new(Selection::Keypair)
                    .set_format(KeyFormat::Der)
                    .encode(&pkey)
                    .unwrap();

                assert_eq!(der, expected);
            }
        }
    }
}
