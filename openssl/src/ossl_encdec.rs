use crate::bio::{MemBio, MemBioSlice};
use crate::error::ErrorStack;
use crate::pkey::{Id, PKey, PKeyRef};
use crate::pkey_ctx::{Selection, SelectionT};
use crate::symm::Cipher;
use crate::util::{invoke_passwd_cb, CallbackState};
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
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
    type CType = ffi::OSSL_DECODER_CTX;
    fn drop = ffi::OSSL_DECODER_CTX_free;

    /// A context object which can perform decode operations.
    pub struct OsslDecoderCtx;
    /// A reference to an `OsslDecoderCtx`.
    pub struct OsslDecoderCtxRef;
}

impl OsslDecoderCtx {
    #[corresponds(OSSL_DECODER_CTX_new_for_pkey)]
    #[inline]
    #[allow(dead_code)]
    fn new_for_key(
        pkey: *mut *mut ffi::EVP_PKEY,
        selection: Selection,
        input: Option<KeyFormat>,
        structure: Option<Structure<'_>>,
        key_type: Option<Id>,
    ) -> Result<Self, ErrorStack> {
        let input_ptr = input
            .map(|i| {
                let input: &CStr = i.into();
                input.as_ptr()
            })
            .unwrap_or_else(ptr::null);
        let structure_ptr = structure
            .map(|s| {
                let structure: &CStr = s.into();
                structure.as_ptr()
            })
            .unwrap_or_else(ptr::null);
        let key_type_ptr = key_type
            .and_then(|k| k.try_into().ok())
            .map(|k: &CStr| k.as_ptr())
            .unwrap_or_else(ptr::null);
        unsafe {
            let ptr = cvt_p(ffi::OSSL_DECODER_CTX_new_for_pkey(
                pkey,
                input_ptr,
                structure_ptr,
                key_type_ptr,
                selection.into(),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}

impl OsslDecoderCtxRef {
    /// Select which parts of the key to decode.
    #[corresponds(OSSL_DECODER_CTX_set_selection)]
    #[allow(dead_code)]
    fn set_selection(&mut self, selection: Selection) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::OSSL_DECODER_CTX_set_selection(self.as_ptr(), selection.into()) })
            .map(|_| ())
    }

    /// Set the input type for the encoded data.
    #[corresponds(OSSL_DECODER_CTX_set_input_type)]
    #[allow(dead_code)]
    fn set_input_type(&mut self, input: KeyFormat) -> Result<(), ErrorStack> {
        let input: &CStr = input.into();
        cvt(unsafe { ffi::OSSL_DECODER_CTX_set_input_type(self.as_ptr(), input.as_ptr()) })
            .map(|_| ())
    }

    /// Set the input structure for the encoded data.
    #[corresponds(OSSL_DECODER_CTX_set_input_structure)]
    #[allow(dead_code)]
    fn set_input_structure(&mut self, structure: Structure<'_>) -> Result<(), ErrorStack> {
        let structure: &CStr = structure.into();
        cvt(unsafe { ffi::OSSL_DECODER_CTX_set_input_structure(self.as_ptr(), structure.as_ptr()) })
            .map(|_| ())
    }

    /// Set the passphrase to decrypt the encoded data.
    #[corresponds(OSSL_DECODER_CTX_set_passphrase)]
    #[allow(dead_code)]
    fn set_passphrase(&mut self, passphrase: &[u8]) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::OSSL_DECODER_CTX_set_passphrase(
                self.as_ptr(),
                passphrase.as_ptr().cast(),
                passphrase.len(),
            )
        })
        .map(|_| ())
    }

    /// Set the passphrase to decrypt the encoded data.
    #[corresponds(OSSL_DECODER_CTX_set_passphrase)]
    #[allow(dead_code)]
    unsafe fn set_passphrase_callback<F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>>(
        &mut self,
        callback: *mut CallbackState<F>,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::OSSL_DECODER_CTX_set_pem_password_cb(
                self.as_ptr(),
                Some(invoke_passwd_cb::<F>),
                callback as *mut _,
            )
        })
        .map(|_| ())
    }

    /// Decode the encoded data
    #[corresponds(OSSL_DECODER_from_bio)]
    #[allow(dead_code)]
    fn decode(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        let bio = MemBioSlice::new(data)?;

        cvt(unsafe { ffi::OSSL_DECODER_from_bio(self.as_ptr(), bio.as_ptr()) }).map(|_| ())
    }
}

#[allow(dead_code)]
pub(crate) struct Decoder<'a, T: SelectionT> {
    selection: PhantomData<T>,
    key_type: Option<Id>,
    format: Option<KeyFormat>,
    structure: Option<Structure<'a>>,
    passphrase: Option<&'a [u8]>,
    #[allow(clippy::type_complexity)]
    passphrase_callback: Option<Box<dyn FnOnce(&mut [u8]) -> Result<usize, ErrorStack> + 'a>>,
}

impl<'a, T: SelectionT> Decoder<'a, T> {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            selection: PhantomData,
            key_type: None,
            format: None,
            structure: None,
            passphrase: None,
            passphrase_callback: None,
        }
    }

    #[allow(dead_code)]
    pub fn set_key_type(mut self, key_type: Id) -> Self {
        self.key_type = Some(key_type);
        self
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
    pub fn set_passphrase(mut self, passphrase: &'a [u8]) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    #[allow(dead_code)]
    pub fn set_passphrase_callback<F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack> + 'a>(
        mut self,
        callback: F,
    ) -> Self {
        self.passphrase_callback = Some(Box::new(callback));
        self
    }

    #[allow(dead_code)]
    pub fn decode(self, data: &[u8]) -> Result<PKey<T>, ErrorStack> {
        let mut pkey_ptr = ptr::null_mut();
        let mut passphrase_callback_state;
        let mut ctx = OsslDecoderCtx::new_for_key(
            &mut pkey_ptr,
            T::SELECTION,
            self.format,
            self.structure,
            self.key_type,
        )?;
        if let Some(passphrase) = self.passphrase {
            ctx.set_passphrase(passphrase)?;
        }
        if let Some(passphrase_callback) = self.passphrase_callback {
            passphrase_callback_state = CallbackState::new(passphrase_callback);
            unsafe { ctx.set_passphrase_callback(&mut passphrase_callback_state)? };
        }
        ctx.decode(data)?;
        Ok(unsafe { PKey::from_ptr(pkey_ptr) })
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

    mod decoder {
        use super::*;

        mod params {
            use super::*;
            use crate::pkey::Params;

            #[test]
            fn test_dh_pem() {
                Decoder::<Params>::new()
                    .set_key_type(Id::DH)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::TypeSpecific)
                    .decode(include_bytes!("../test/dhparams.pem"))
                    .unwrap()
                    .dh()
                    .unwrap();
            }

            #[test]
            fn test_dh_der() {
                Decoder::<Params>::new()
                    .set_key_type(Id::DH)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::TypeSpecific)
                    .decode(include_bytes!("../test/dhparams.der"))
                    .unwrap()
                    .dh()
                    .unwrap();
            }
        }
        mod public {
            use super::*;
            use crate::pkey::Public;

            #[test]
            fn test_rsa_pem() {
                Decoder::<Public>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::SubjectPublicKeyInfo)
                    .decode(include_bytes!("../test/rsa.pub.pem"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }

            #[test]
            fn test_rsa_pem_pkcs1() {
                Decoder::<Public>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .decode(include_bytes!("../test/pkcs1.pem.pub"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }

            #[test]
            fn test_rsa_der() {
                Decoder::<Public>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::SubjectPublicKeyInfo)
                    .decode(include_bytes!("../test/key.der.pub"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }

            #[test]
            fn test_rsa_der_pkcs1() {
                Decoder::<Public>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::PKCS1)
                    .decode(include_bytes!("../test/pkcs1.der.pub"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }
        }
        mod private {
            use super::*;
            use crate::pkey::Private;

            #[test]
            fn test_rsa_pem() {
                Decoder::<Private>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .decode(include_bytes!("../test/rsa.pkcs1.pem"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }

            #[test]
            fn test_rsa_pem_passphrase() {
                Decoder::<Private>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .set_passphrase(b"mypass")
                    .decode(include_bytes!("../test/rsa-encrypted.pem"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }

            #[test]
            fn test_rsa_pem_callback() {
                let mut password_queried = false;
                Decoder::<Private>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Pem)
                    .set_structure(Structure::PKCS1)
                    .set_passphrase_callback(|password| {
                        password_queried = true;
                        password[..6].copy_from_slice(b"mypass");
                        Ok(6)
                    })
                    .decode(include_bytes!("../test/rsa-encrypted.pem"))
                    .unwrap();
                assert!(password_queried);
            }

            #[test]
            fn test_rsa_der() {
                Decoder::<Private>::new()
                    .set_key_type(Id::RSA)
                    .set_format(KeyFormat::Der)
                    .set_structure(Structure::PKCS1)
                    .decode(include_bytes!("../test/key.der"))
                    .unwrap()
                    .rsa()
                    .unwrap();
            }
        }
    }

    mod encoder {
        use super::*;

        mod params {
            use super::*;
            use crate::dh::Dh;
            use crate::pkey::{Id, Params};
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
                let expected = include_bytes!("../test/rsa.pub.pem");
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
                let expected = include_bytes!("../test/rsa.pub.pem");
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
                let expected = include_bytes!("../test/rsa.pkcs1.pem");
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
