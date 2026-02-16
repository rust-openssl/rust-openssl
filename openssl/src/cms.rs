//! SMIME implementation using CMS
//!
//! CMS (PKCS#7) is an encryption standard.  It allows signing and encrypting data using
//! X.509 certificates.  The OpenSSL implementation of CMS is used in email encryption
//! generated from a `Vec` of bytes.  This `Vec` follows the smime protocol standards.
//! Data accepted by this module will be smime type `enveloped-data`.

use bitflags::bitflags;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_uint};
use std::ptr;

use crate::bio::{MemBio, MemBioSlice};
use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, PKeyRef};
use crate::stack::StackRef;
use crate::symm::Cipher;
use crate::x509::{store::X509StoreRef, X509Ref, X509};
use crate::{cvt, cvt_p};
use openssl_macros::corresponds;

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct CMSOptions : c_uint {
        const TEXT = ffi::CMS_TEXT;
        const CMS_NOCERTS = ffi::CMS_NOCERTS;
        const NO_CONTENT_VERIFY = ffi::CMS_NO_CONTENT_VERIFY;
        const NO_ATTR_VERIFY = ffi::CMS_NO_ATTR_VERIFY;
        const NOSIGS = ffi::CMS_NOSIGS;
        const NOINTERN = ffi::CMS_NOINTERN;
        const NO_SIGNER_CERT_VERIFY = ffi::CMS_NO_SIGNER_CERT_VERIFY;
        const NOVERIFY = ffi::CMS_NOVERIFY;
        const DETACHED = ffi::CMS_DETACHED;
        const BINARY = ffi::CMS_BINARY;
        const NOATTR = ffi::CMS_NOATTR;
        const NOSMIMECAP = ffi::CMS_NOSMIMECAP;
        const NOOLDMIMETYPE = ffi::CMS_NOOLDMIMETYPE;
        const CRLFEOL = ffi::CMS_CRLFEOL;
        const STREAM = ffi::CMS_STREAM;
        const NOCRL = ffi::CMS_NOCRL;
        const PARTIAL = ffi::CMS_PARTIAL;
        const REUSE_DIGEST = ffi::CMS_REUSE_DIGEST;
        const USE_KEYID = ffi::CMS_USE_KEYID;
        const DEBUG_DECRYPT = ffi::CMS_DEBUG_DECRYPT;
        const KEY_PARAM = ffi::CMS_KEY_PARAM;
        const ASCIICRLF = ffi::CMS_ASCIICRLF;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::CMS_ContentInfo;
    fn drop = ffi::CMS_ContentInfo_free;

    /// High level CMS wrapper
    ///
    /// CMS supports nesting various types of data, including signatures, certificates,
    /// encrypted data, smime messages (encrypted email), and data digest.  The ContentInfo
    /// content type is the encapsulation of all those content types.  [`RFC 5652`] describes
    /// CMS and OpenSSL follows this RFC's implementation.
    ///
    /// [`RFC 5652`]: https://tools.ietf.org/html/rfc5652#page-6
    pub struct CmsContentInfo;
    /// Reference to [`CMSContentInfo`]
    ///
    /// [`CMSContentInfo`]:struct.CmsContentInfo.html
    pub struct CmsContentInfoRef;
}

impl CmsContentInfoRef {
    /// Given the sender's private key, `pkey` and the recipient's certificate, `cert`,
    /// decrypt the data in `self`.
    #[corresponds(CMS_decrypt)]
    pub fn decrypt<T>(&self, pkey: &PKeyRef<T>, cert: &X509) -> Result<Vec<u8>, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            let pkey = pkey.as_ptr();
            let cert = cert.as_ptr();
            let out = MemBio::new()?;

            cvt(ffi::CMS_decrypt(
                self.as_ptr(),
                pkey,
                cert,
                ptr::null_mut(),
                out.as_ptr(),
                0,
            ))?;

            Ok(out.get_buf().to_owned())
        }
    }

    /// Given the sender's private key, `pkey`,
    /// decrypt the data in `self` without validating the recipient certificate.
    ///
    /// *Warning*: Not checking the recipient certificate may leave you vulnerable to Bleichenbacher's attack on PKCS#1 v1.5 RSA padding.
    #[corresponds(CMS_decrypt)]
    // FIXME merge into decrypt
    pub fn decrypt_without_cert_check<T>(&self, pkey: &PKeyRef<T>) -> Result<Vec<u8>, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            let pkey = pkey.as_ptr();
            let out = MemBio::new()?;

            cvt(ffi::CMS_decrypt(
                self.as_ptr(),
                pkey,
                ptr::null_mut(),
                ptr::null_mut(),
                out.as_ptr(),
                0,
            ))?;

            Ok(out.get_buf().to_owned())
        }
    }

    /// Decrypt detached content using the recipient's private key and certificate.
    ///
    /// This is used to decrypt content that was encrypted with [`CmsContentInfo::encrypt_detached`].
    /// The CMS structure (`self`) contains the encrypted symmetric key and algorithm parameters,
    /// while the actual encrypted content is provided separately in `encrypted_content`.
    ///
    /// [`CmsContentInfo::encrypt_detached`]: struct.CmsContentInfo.html#method.encrypt_detached
    #[corresponds(CMS_decrypt)]
    pub fn decrypt_detached<T>(
        &self,
        pkey: &PKeyRef<T>,
        cert: &X509,
        encrypted_content: &[u8],
    ) -> Result<Vec<u8>, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            let pkey = pkey.as_ptr();
            let cert = cert.as_ptr();
            let dcont = MemBioSlice::new(encrypted_content)?;
            let out = MemBio::new()?;

            cvt(ffi::CMS_decrypt(
                self.as_ptr(),
                pkey,
                cert,
                dcont.as_ptr(),
                out.as_ptr(),
                0,
            ))?;

            Ok(out.get_buf().to_owned())
        }
    }

    to_der! {
        /// Serializes this CmsContentInfo using DER.
        #[corresponds(i2d_CMS_ContentInfo)]
        to_der,
        ffi::i2d_CMS_ContentInfo
    }

    to_pem! {
        /// Serializes this CmsContentInfo using DER.
        #[corresponds(PEM_write_bio_CMS)]
        to_pem,
        ffi::PEM_write_bio_CMS
    }
}

impl CmsContentInfo {
    /// Parses a smime formatted `vec` of bytes into a `CmsContentInfo`.
    #[corresponds(SMIME_read_CMS)]
    pub fn smime_read_cms(smime: &[u8]) -> Result<CmsContentInfo, ErrorStack> {
        unsafe {
            let bio = MemBioSlice::new(smime)?;

            let cms = cvt_p(ffi::SMIME_read_CMS(bio.as_ptr(), ptr::null_mut()))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }

    from_der! {
        /// Deserializes a DER-encoded ContentInfo structure.
        #[corresponds(d2i_CMS_ContentInfo)]
        from_der,
        CmsContentInfo,
        ffi::d2i_CMS_ContentInfo
    }

    from_pem! {
        /// Deserializes a PEM-encoded ContentInfo structure.
        #[corresponds(PEM_read_bio_CMS)]
        from_pem,
        CmsContentInfo,
        ffi::PEM_read_bio_CMS
    }

    /// Given a signing cert `signcert`, private key `pkey`, a certificate stack `certs`,
    /// data `data` and flags `flags`, create a CmsContentInfo struct.
    ///
    /// All arguments are optional.
    #[corresponds(CMS_sign)]
    pub fn sign<T>(
        signcert: Option<&X509Ref>,
        pkey: Option<&PKeyRef<T>>,
        certs: Option<&StackRef<X509>>,
        data: Option<&[u8]>,
        flags: CMSOptions,
    ) -> Result<CmsContentInfo, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            let signcert = signcert.map_or(ptr::null_mut(), |p| p.as_ptr());
            let pkey = pkey.map_or(ptr::null_mut(), |p| p.as_ptr());
            let data_bio = match data {
                Some(data) => Some(MemBioSlice::new(data)?),
                None => None,
            };
            let data_bio_ptr = data_bio.as_ref().map_or(ptr::null_mut(), |p| p.as_ptr());
            let certs = certs.map_or(ptr::null_mut(), |p| p.as_ptr());

            let cms = cvt_p(ffi::CMS_sign(
                signcert,
                pkey,
                certs,
                data_bio_ptr,
                flags.bits(),
            ))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }

    /// Given a certificate stack `certs`, data `data`, cipher `cipher` and flags `flags`,
    /// create a CmsContentInfo struct.
    ///
    #[corresponds(CMS_encrypt)]
    pub fn encrypt(
        certs: &StackRef<X509>,
        data: &[u8],
        cipher: Cipher,
        flags: CMSOptions,
    ) -> Result<CmsContentInfo, ErrorStack> {
        unsafe {
            let data_bio = MemBioSlice::new(data)?;

            let cms = cvt_p(ffi::CMS_encrypt(
                certs.as_ptr(),
                data_bio.as_ptr(),
                cipher.as_ptr(),
                flags.bits(),
            ))?;

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }

    /// Encrypt data with detached content.
    ///
    /// This creates a CMS EnvelopedData structure where the encrypted content is
    /// returned separately from the CMS structure. The CMS structure contains the
    /// encrypted symmetric key and algorithm parameters needed for decryption,
    /// while the actual encrypted data is returned as a separate byte vector.
    ///
    /// This is useful when you need to handle the encrypted content separately,
    /// for example when splitting it into blocks or storing it in a different location.
    ///
    /// The `flags` parameter will have `STREAM`, `PARTIAL`, and `DETACHED` flags
    /// added automatically.
    ///
    /// # Example
    /// ```
    /// use openssl::cms::{CmsContentInfo, CMSOptions};
    /// use openssl::stack::Stack;
    /// use openssl::symm::Cipher;
    /// use openssl::x509::X509;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cert_pem = include_bytes!("../test/cms_pubkey.der");
    /// let cert = X509::from_der(cert_pem)?;
    /// let mut certs = Stack::new()?;
    /// certs.push(cert)?;
    ///
    /// let data = b"Hello, World!";
    /// let (cms, encrypted_data) = CmsContentInfo::encrypt_detached(
    ///     &certs,
    ///     data,
    ///     Cipher::aes_256_cbc(),
    ///     CMSOptions::empty(),
    /// )?;
    ///
    /// // cms contains the envelope (encrypted key, algorithm info)
    /// // encrypted_data contains the ciphertext
    /// let envelope_der = cms.to_der()?;
    /// # Ok(())
    /// # }
    /// ```
    #[corresponds(CMS_encrypt)]
    pub fn encrypt_detached(
        certs: &StackRef<X509>,
        data: &[u8],
        cipher: Cipher,
        flags: CMSOptions,
    ) -> Result<(CmsContentInfo, Vec<u8>), ErrorStack> {
        unsafe {
            // Add streaming and detached flags
            let stream_flags =
                flags | CMSOptions::STREAM | CMSOptions::PARTIAL | CMSOptions::DETACHED;

            // Create CMS structure with streaming mode (no input data yet)
            let cms = cvt_p(ffi::CMS_encrypt(
                certs.as_ptr(),
                ptr::null_mut(),
                cipher.as_ptr(),
                stream_flags.bits(),
            ))?;

            let cms = CmsContentInfo::from_ptr(cms);

            // Create output BIO for encrypted data
            let out = MemBio::new()?;

            // Initialize data streaming - returns cipher BIO chain pushed onto output
            let bio = cvt_p(ffi::CMS_dataInit(cms.as_ptr(), out.as_ptr()))?;

            // Write plaintext through the cipher BIO
            let len = data.len() as c_int;
            let written = ffi::BIO_write(bio, data.as_ptr() as *const _, len);
            if written != len {
                // Clean up the filter BIO chain
                ffi::BIO_pop(bio);
                ffi::BIO_free(bio);
                return Err(ErrorStack::get());
            }

            // Flush the BIO
            if ffi::BIO_ctrl(bio, ffi::BIO_CTRL_FLUSH, 0, ptr::null_mut()) != 1 {
                ffi::BIO_pop(bio);
                ffi::BIO_free(bio);
                return Err(ErrorStack::get());
            }

            // Finalize the CMS structure
            let final_ret = ffi::CMS_dataFinal(cms.as_ptr(), bio);

            // Pop the filter BIO off the chain so our output BIO is standalone
            ffi::BIO_pop(bio);
            // Free just the filter BIO (not the whole chain)
            ffi::BIO_free(bio);

            if final_ret != 1 {
                return Err(ErrorStack::get());
            }

            Ok((cms, out.get_buf().to_owned()))
        }
    }

    /// Verify this CmsContentInfo's signature,
    /// This will search the 'certs' list for the signing certificate.
    /// Additional certificates, needed for building the certificate chain, may be
    /// given in 'store' as well as additional CRLs.
    /// A detached signature may be passed in `detached_data`. The signed content
    /// without signature, will be copied into output_data if it is present.
    ///
    #[corresponds(CMS_verify)]
    pub fn verify(
        &mut self,
        certs: Option<&StackRef<X509>>,
        store: Option<&X509StoreRef>,
        detached_data: Option<&[u8]>,
        output_data: Option<&mut Vec<u8>>,
        flags: CMSOptions,
    ) -> Result<(), ErrorStack> {
        unsafe {
            let certs_ptr = certs.map_or(ptr::null_mut(), |p| p.as_ptr());
            let store_ptr = store.map_or(ptr::null_mut(), |p| p.as_ptr());
            let detached_data_bio = match detached_data {
                Some(data) => Some(MemBioSlice::new(data)?),
                None => None,
            };
            let detached_data_bio_ptr = detached_data_bio
                .as_ref()
                .map_or(ptr::null_mut(), |p| p.as_ptr());
            let out_bio = MemBio::new()?;

            cvt(ffi::CMS_verify(
                self.as_ptr(),
                certs_ptr,
                store_ptr,
                detached_data_bio_ptr,
                out_bio.as_ptr(),
                flags.bits(),
            ))?;

            if let Some(data) = output_data {
                data.clear();
                data.extend_from_slice(out_bio.get_buf());
            };

            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::pkcs12::Pkcs12;
    use crate::pkey::PKey;
    use crate::stack::Stack;
    use crate::x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    };

    #[test]
    fn cms_encrypt_decrypt() {
        #[cfg(ossl300)]
        let _provider = crate::provider::Provider::try_load(None, "legacy", true).unwrap();

        // load cert with public key only
        let pub_cert_bytes = include_bytes!("../test/cms_pubkey.der");
        let pub_cert = X509::from_der(pub_cert_bytes).expect("failed to load pub cert");

        // load cert with private key
        let priv_cert_bytes = include_bytes!("../test/cms.p12");
        let priv_cert = Pkcs12::from_der(priv_cert_bytes).expect("failed to load priv cert");
        let priv_cert = priv_cert
            .parse2("mypass")
            .expect("failed to parse priv cert");

        // encrypt cms message using public key cert
        let input = String::from("My Message");
        let mut cert_stack = Stack::new().expect("failed to create stack");
        cert_stack
            .push(pub_cert)
            .expect("failed to add pub cert to stack");

        let encrypt = CmsContentInfo::encrypt(
            &cert_stack,
            input.as_bytes(),
            Cipher::des_ede3_cbc(),
            CMSOptions::empty(),
        )
        .expect("failed create encrypted cms");

        // decrypt cms message using private key cert (DER)
        {
            let encrypted_der = encrypt.to_der().expect("failed to create der from cms");
            let decrypt =
                CmsContentInfo::from_der(&encrypted_der).expect("failed read cms from der");

            let decrypt_with_cert_check = decrypt
                .decrypt(
                    priv_cert.pkey.as_ref().unwrap(),
                    priv_cert.cert.as_ref().unwrap(),
                )
                .expect("failed to decrypt cms");
            let decrypt_with_cert_check = String::from_utf8(decrypt_with_cert_check)
                .expect("failed to create string from cms content");

            let decrypt_without_cert_check = decrypt
                .decrypt_without_cert_check(priv_cert.pkey.as_ref().unwrap())
                .expect("failed to decrypt cms");
            let decrypt_without_cert_check = String::from_utf8(decrypt_without_cert_check)
                .expect("failed to create string from cms content");

            assert_eq!(input, decrypt_with_cert_check);
            assert_eq!(input, decrypt_without_cert_check);
        }

        // decrypt cms message using private key cert (PEM)
        {
            let encrypted_pem = encrypt.to_pem().expect("failed to create pem from cms");
            let decrypt =
                CmsContentInfo::from_pem(&encrypted_pem).expect("failed read cms from pem");

            let decrypt_with_cert_check = decrypt
                .decrypt(
                    priv_cert.pkey.as_ref().unwrap(),
                    priv_cert.cert.as_ref().unwrap(),
                )
                .expect("failed to decrypt cms");
            let decrypt_with_cert_check = String::from_utf8(decrypt_with_cert_check)
                .expect("failed to create string from cms content");

            let decrypt_without_cert_check = decrypt
                .decrypt_without_cert_check(priv_cert.pkey.as_ref().unwrap())
                .expect("failed to decrypt cms");
            let decrypt_without_cert_check = String::from_utf8(decrypt_without_cert_check)
                .expect("failed to create string from cms content");

            assert_eq!(input, decrypt_with_cert_check);
            assert_eq!(input, decrypt_without_cert_check);
        }
    }

    #[test]
    fn cms_encrypt_decrypt_detached() {
        #[cfg(ossl300)]
        let _provider = crate::provider::Provider::try_load(None, "legacy", true).unwrap();

        // load cert with public key only
        let pub_cert_bytes = include_bytes!("../test/cms_pubkey.der");
        let pub_cert = X509::from_der(pub_cert_bytes).expect("failed to load pub cert");

        // load cert with private key
        let priv_cert_bytes = include_bytes!("../test/cms.p12");
        let priv_cert = Pkcs12::from_der(priv_cert_bytes).expect("failed to load priv cert");
        let priv_cert = priv_cert
            .parse2("mypass")
            .expect("failed to parse priv cert");

        // encrypt cms message using public key cert with detached content
        let input = b"My Message for detached encryption";
        let mut cert_stack = Stack::new().expect("failed to create stack");
        cert_stack
            .push(pub_cert)
            .expect("failed to add pub cert to stack");

        let (cms, encrypted_content) = CmsContentInfo::encrypt_detached(
            &cert_stack,
            input,
            Cipher::des_ede3_cbc(),
            CMSOptions::empty(),
        )
        .expect("failed to create encrypted cms with detached content");

        // Verify that we got both parts
        let envelope_der = cms.to_der().expect("failed to create der from cms");
        assert!(!envelope_der.is_empty());
        assert!(!encrypted_content.is_empty());

        // The encrypted content should be different from the input
        assert_ne!(input.as_slice(), encrypted_content.as_slice());

        // Decrypt using the detached method
        let cms_restored =
            CmsContentInfo::from_der(&envelope_der).expect("failed to read cms from der");
        let decrypted = cms_restored
            .decrypt_detached(
                priv_cert.pkey.as_ref().unwrap(),
                priv_cert.cert.as_ref().unwrap(),
                &encrypted_content,
            )
            .expect("failed to decrypt detached cms");

        assert_eq!(input.as_slice(), decrypted.as_slice());
    }

    fn cms_sign_verify_generic_helper(is_detached: bool) {
        // load cert with private key
        let cert_bytes = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert_bytes).expect("failed to load cert.pem");

        let key_bytes = include_bytes!("../test/key.pem");
        let key = PKey::private_key_from_pem(key_bytes).expect("failed to load key.pem");

        let root_bytes = include_bytes!("../test/root-ca.pem");
        let root = X509::from_pem(root_bytes).expect("failed to load root-ca.pem");

        // sign cms message using public key cert
        let data = b"Hello world!";

        let (opt, ext_data): (CMSOptions, Option<&[u8]>) = if is_detached {
            (CMSOptions::DETACHED | CMSOptions::BINARY, Some(data))
        } else {
            (CMSOptions::empty(), None)
        };

        let mut cms = CmsContentInfo::sign(Some(&cert), Some(&key), None, Some(data), opt)
            .expect("failed to CMS sign a message");

        // check CMS signature length
        let pem_cms = cms
            .to_pem()
            .expect("failed to pack CmsContentInfo into PEM");
        assert!(!pem_cms.is_empty());

        // verify CMS signature
        let mut builder = X509StoreBuilder::new().expect("failed to create X509StoreBuilder");
        builder
            .add_cert(root)
            .expect("failed to add root-ca into X509StoreBuilder");
        let store: X509Store = builder.build();
        let mut out_data: Vec<u8> = Vec::new();
        let res = cms.verify(
            None,
            Some(&store),
            ext_data,
            Some(&mut out_data),
            CMSOptions::empty(),
        );

        // check verification result -  valid signature
        res.unwrap();
        assert_eq!(data.to_vec(), out_data);
    }

    #[test]
    fn cms_sign_verify_ok() {
        cms_sign_verify_generic_helper(false);
    }

    #[test]
    fn cms_sign_verify_detached_ok() {
        cms_sign_verify_generic_helper(true);
    }

    #[test]
    fn cms_sign_verify_error() {
        #[cfg(ossl300)]
        let _provider = crate::provider::Provider::try_load(None, "legacy", true).unwrap();

        // load cert with private key
        let priv_cert_bytes = include_bytes!("../test/cms.p12");
        let priv_cert = Pkcs12::from_der(priv_cert_bytes).expect("failed to load priv cert");
        let priv_cert = priv_cert
            .parse2("mypass")
            .expect("failed to parse priv cert");

        // sign cms message using public key cert
        let data = b"Hello world!";
        let mut cms = CmsContentInfo::sign(
            Some(&priv_cert.cert.unwrap()),
            Some(&priv_cert.pkey.unwrap()),
            None,
            Some(data),
            CMSOptions::empty(),
        )
        .expect("failed to CMS sign a message");

        // check CMS signature length
        let pem_cms = cms
            .to_pem()
            .expect("failed to pack CmsContentInfo into PEM");
        assert!(!pem_cms.is_empty());

        let empty_store = X509StoreBuilder::new()
            .expect("failed to create X509StoreBuilder")
            .build();

        // verify CMS signature
        let res = cms.verify(
            None,
            Some(&empty_store),
            Some(data),
            None,
            CMSOptions::empty(),
        );

        // check verification result - this is an invalid signature
        // defined in openssl crypto/cms/cms.h
        const CMS_R_CERTIFICATE_VERIFY_ERROR: i32 = 100;
        let es = res.unwrap_err();
        let error_array = es.errors();
        assert_eq!(1, error_array.len());
        let code = error_array[0].reason_code();
        assert_eq!(code, CMS_R_CERTIFICATE_VERIFY_ERROR);
    }
}
