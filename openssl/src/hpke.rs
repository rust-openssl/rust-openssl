use std::{ffi::CString, ptr};

use ffi::{
    c_int, OSSL_HPKE_CTX_free, OSSL_HPKE_CTX_get_seq, OSSL_HPKE_CTX_new,
    OSSL_HPKE_CTX_set1_authpriv, OSSL_HPKE_CTX_set1_authpub, OSSL_HPKE_CTX_set1_ikme,
    OSSL_HPKE_CTX_set1_psk, OSSL_HPKE_CTX_set_seq, OSSL_HPKE_decap, OSSL_HPKE_encap,
    OSSL_HPKE_export, OSSL_HPKE_get_grease_value, OSSL_HPKE_get_public_encap_size,
    OSSL_HPKE_keygen, OSSL_HPKE_open, OSSL_HPKE_seal, OSSL_HPKE_str2suite, OSSL_HPKE_suite_check,
    OSSL_HPKE_SUITE, OSSL_HPKE_SUITE_DEFAULT,
};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use crate::{
    cvt, cvt_p,
    error::ErrorStack,
    pkey::{self, PKey, PKeyRef, Private},
};

/// HPKE authentication modes.
///
/// OpenSSL documentation at [`hpke-modes`].
///
/// [`hpke-modes`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#hpke-modes
pub struct Mode(c_int);

impl Mode {
    /// Authentication is not used.
    pub const BASE: Self = Mode(ffi::OSSL_HPKE_MODE_BASE);
    /// Authenticates possession of a pre-shared key (PSK).
    pub const PSK: Self = Mode(ffi::OSSL_HPKE_MODE_PSK);
    /// Authenticates possession of a KEM-based sender private key.
    pub const AUTH: Self = Mode(ffi::OSSL_HPKE_MODE_AUTH);
    /// A combination of OSSL_HPKE_MODE_PSK and OSSL_HPKE_MODE_AUTH.
    /// Both the PSK and the senders authentication public/private must be supplied before the encapsulation/decapsulation operation will work.
    pub const PSKAUTH: Self = Mode(ffi::OSSL_HPKE_MODE_PSKAUTH);
}

/// HPKE Key Encapsulation Method identifier.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Kem(u16);

/// HPKE Key Derivation Function identifier.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Kdf(u16);

/// HPKE authenticated encryption with additional data algorithm identifier.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Aead(u16);

impl Kem {
    /// The NIST P-256 curve.
    pub const P256: Self = Kem(ffi::OSSL_HPKE_KEM_ID_P256);
    /// The NIST P-384 curve.
    pub const P384: Self = Kem(ffi::OSSL_HPKE_KEM_ID_P384);
    /// The NIST P-521 curve.
    pub const P521: Self = Kem(ffi::OSSL_HPKE_KEM_ID_P521);
    /// The X25519 curve.
    pub const X25519: Self = Kem(ffi::OSSL_HPKE_KEM_ID_X25519);
    /// The X448 curve.
    pub const X448: Self = Kem(ffi::OSSL_HPKE_KEM_ID_X448);
}

impl Kdf {
    /// HKDF with SHA-256.
    pub const HKDF_SHA256: Self = Kdf(ffi::OSSL_HPKE_KDF_ID_HKDF_SHA256);
    /// HKDF with SHA-384.
    pub const HKDF_SHA384: Self = Kdf(ffi::OSSL_HPKE_KDF_ID_HKDF_SHA384);
    /// HKDF with SHA-512.
    pub const HKDF_SHA512: Self = Kdf(ffi::OSSL_HPKE_KDF_ID_HKDF_SHA512);
}

impl Aead {
    /// AES-GCM with 128-bit key.
    pub const AES_GCM_128: Self = Aead(ffi::OSSL_HPKE_AEAD_ID_AES_GCM_128);
    /// AES-GCM with 256-bit key.
    pub const AES_GCM_256: Self = Aead(ffi::OSSL_HPKE_AEAD_ID_AES_GCM_256);
    /// ChaCha20-Poly1305.
    pub const CHACHA_POLY1305: Self = Aead(ffi::OSSL_HPKE_AEAD_ID_CHACHA_POLY1305);
    /// Indicates that AEAD operations are not needed.
    /// [SenderCtxRef::export] or [ReceiverCtxRef::export] can be used, but
    /// [SenderCtxRef::seal] and [ReceiverCtxRef::open] will return an error
    /// if called with a context using this AEAD identifier.
    pub const EXPORTONLY: Self = Aead(ffi::OSSL_HPKE_AEAD_ID_EXPORTONLY);
}

/// A HPKE suite.
///
/// OpenSSL documentation at [`hpke-suite-identifiers`].
///
/// [`hpke-suite-identifiers`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#ossl_hpke_suite-identifiers
#[derive(Debug, Copy, Clone)]
pub struct Suite {
    pub kem_id: Kem,
    pub kdf_id: Kdf,
    pub aead_id: Aead,
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_HPKE_CTX;
    fn drop = OSSL_HPKE_CTX_free;

    /// A HPKE context for sending messages.
    ///
    /// OpenSSL documentation at [`sender-apis`].
    ///
    /// [`sender-apis`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#sender-apis
    pub struct SenderCtx;
    /// A reference to an [`SenderCtx`].
    pub struct SenderCtxRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_HPKE_CTX;
    fn drop = OSSL_HPKE_CTX_free;

    /// A HPKE context for receiving messages.
    ///
    /// OpenSSL documentation at [`recipient-apis`].
    ///
    /// [`recipient-apis`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#recipient-apis
    pub struct ReceiverCtx;
    /// A reference to an [`ReceiverCtx`].
    pub struct ReceiverCtxRef;
}

impl SenderCtxRef {
    /// Encapsulates a public key.
    ///
    /// The encapsulation will be written to the input `enc` buffer, and the number of bytes written will be returned.
    /// Calling this function more than once on the same context will result in an error.
    /// If `enc` is smaller than the value returned by [`Suite::public_encap_size`], an error will be returned.
    #[corresponds(OSSL_HPKE_encap)]
    #[inline]
    pub fn encap(&self, enc: &mut [u8], pub_key: &[u8], info: &[u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut enclen = enc.len();
            cvt(OSSL_HPKE_encap(
                self.as_ptr(),
                enc.as_mut_ptr(),
                &mut enclen,
                pub_key.as_ptr(),
                pub_key.len(),
                info.as_ptr(),
                info.len(),
            ))
            .map(|_| enclen)
        }
    }

    /// Seals a plaintext message.
    ///
    /// The ciphertext will be written to the input `ct` buffer, and the number of bytes written will be returned.
    /// If `ct` is smaller than the value returned by [`Suite::ciphertext_size`], an error will be returned.
    ///
    /// This function can be called multiple times on the same context.
    #[corresponds(OSSL_HPKE_seal)]
    #[inline]
    pub fn seal(&self, ct: &mut [u8], aad: &[u8], pt: &[u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut ctlen = ct.len();
            cvt(OSSL_HPKE_seal(
                self.as_ptr(),
                ct.as_mut_ptr(),
                &mut ctlen,
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
            ))
            .map(|_| ctlen)
        }
    }

    /// Set the input key material for the context.
    ///
    /// This enables deterministic key generation.
    /// OpenSSL documentation at [`deterministic-key-generation`].
    ///
    /// [`deterministic-key-generation`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#deterministic-key-generation-for-senders
    #[corresponds(OSSL_HPKE_CTX_set1_ikme)]
    #[inline]
    pub fn set1_ikme(&self, ikm: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_ikme(
                self.as_ptr(),
                ikm.as_ptr(),
                ikm.len(),
            ))?;
            Ok(())
        }
    }

    /// Bind the sender's private key to the context.
    ///
    /// This is for use with the [`Mode::AUTH`] and [`Mode::PSKAUTH`] modes. An error will be
    /// returned if the input key was not generated with the same KEM as the context's suite.
    #[corresponds(OSSL_HPKE_CTX_set1_authpriv)]
    #[inline]
    pub fn set1_authpriv(
        &self,
        pkey_key: &mut pkey::PKeyRef<pkey::Private>,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_authpriv(
                self.as_ptr(),
                pkey_key.as_ptr(),
            ))?;
            Ok(())
        }
    }
}

impl ReceiverCtxRef {
    /// Decapsulates a sender's encapsulated public value.
    ///
    /// An optional info parameter allows binding that derived secret to other application/protocol artefacts.
    /// Calling this function more than once on the same context will result in an error.
    #[corresponds(OSSL_HPKE_decap)]
    #[inline]
    pub fn decap(
        &self,
        enc: &[u8],
        private_key: &PKeyRef<Private>,
        info: &[u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_decap(
                self.as_ptr(),
                enc.as_ptr(),
                enc.len(),
                private_key.as_ptr(),
                info.as_ptr(),
                info.len(),
            ))?;
            Ok(())
        }
    }

    /// Opens a encrypted message.
    ///
    /// The plaintext will be written to the input `pt` buffer, and the number of bytes written will be returned.
    /// If `pt` is too small then an error will be returned. The plaintext length will be a little smaller than the ciphertext length.
    ///
    /// This function can be called multiple times on the same context.
    #[corresponds(OSSL_HPKE_open)]
    #[inline]
    pub fn open(&self, pt: &mut [u8], aad: &[u8], ct: &[u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut ptlen = pt.len();
            cvt(OSSL_HPKE_open(
                self.as_ptr(),
                pt.as_mut_ptr(),
                &mut ptlen,
                aad.as_ptr(),
                aad.len(),
                ct.as_ptr(),
                ct.len(),
            ))
            .map(|_| ptlen)
        }
    }

    /// Bind the sender's public key to the context.
    ///
    /// This is for use with the [`Mode::AUTH`] and [`Mode::PSKAUTH`] modes. An error will be
    /// returned if the input key was not generated with the same KEM as the context's suite.
    #[corresponds(OSSL_HPKE_CTX_set1_authpub)]
    #[inline]
    pub fn set1_authpub(&self, public_key: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set1_authpub(
                self.as_ptr(),
                public_key.as_ptr(),
                public_key.len(),
            ))?;
            Ok(())
        }
    }

    /// Set the sequence number for the context.
    ///
    /// Use of this can be dangerous, as it can lead to nonce reuse with GCM-based AEADs.
    /// OpenSSL documentation at [`re-sequencing`].
    ///
    /// [`re-sequencing`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#re-sequencing
    #[corresponds(OSSL_HPKE_CTX_set_seq)]
    #[inline]
    pub fn set_seq(&self, seq: u64) -> Result<(), ErrorStack> {
        unsafe {
            cvt(OSSL_HPKE_CTX_set_seq(self.as_ptr(), seq))?;
            Ok(())
        }
    }
}

macro_rules! common {
    ($t:ident) => {
        impl $t {
            /// Export a secret.
            ///
            /// OpenSSL documentation at [`exporting-secrets`].
            /// [`exporting-secrets`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#exporting-secrets
            #[corresponds(OSSL_HPKE_export)]
            #[inline]
            pub fn export(&self, secret: &mut [u8], label: &[u8]) -> Result<(), ErrorStack> {
                unsafe {
                    cvt(OSSL_HPKE_export(
                        self.as_ptr(),
                        secret.as_mut_ptr(),
                        secret.len(),
                        label.as_ptr(),
                        label.len(),
                    ))?;
                    Ok(())
                }
            }

            /// Bind the pre shared key to the context.
            ///
            /// This is for use with the [`Mode::PSK`] and [`Mode::PSKAUTH`] modes.
            #[corresponds(OSSL_HPKE_CTX_set1_psk)]
            #[inline]
            pub fn set1_psk(&self, psk_id: &str, psk: &[u8]) -> Result<(), ErrorStack> {
                unsafe {
                    cvt(OSSL_HPKE_CTX_set1_psk(
                        self.as_ptr(),
                        psk_id.as_ptr() as *const _,
                        psk.as_ptr(),
                        psk.len(),
                    ))?;
                    Ok(())
                }
            }

            /// Get the sequence number for the context
            ///
            /// OpenSSL documentation at [`re-sequencing`].
            ///
            /// [`re-sequencing`]: https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#re-sequencing
            #[corresponds(OSSL_HPKE_CTX_get_seq)]
            #[inline]
            pub fn get_seq(&self) -> Result<u64, ErrorStack> {
                let mut seq = 0;
                unsafe {
                    cvt(OSSL_HPKE_CTX_get_seq(self.as_ptr(), &mut seq))?;
                }
                Ok(seq)
            }
        }
    };
}

common!(SenderCtxRef);
common!(ReceiverCtxRef);

impl Suite {
    /// Creates a new sender context.
    #[corresponds(OSSL_HPKE_CTX_new)]
    #[inline]
    pub fn new_sender(&self, mode: Mode) -> Result<SenderCtx, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                self.ffi(),
                ffi::OSSL_HPKE_ROLE_SENDER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(SenderCtx::from_ptr(ptr))
        }
    }

    /// Creates a new receiver context.
    #[corresponds(OSSL_HPKE_CTX_new)]
    #[inline]
    pub fn new_receiver(&self, mode: Mode) -> Result<ReceiverCtx, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(OSSL_HPKE_CTX_new(
                mode.0,
                self.ffi(),
                ffi::OSSL_HPKE_ROLE_RECEIVER,
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok(ReceiverCtx::from_ptr(ptr))
        }
    }

    fn ffi(&self) -> OSSL_HPKE_SUITE {
        OSSL_HPKE_SUITE {
            kem_id: self.kem_id.0,
            kdf_id: self.kdf_id.0,
            aead_id: self.aead_id.0,
        }
    }

    /// Check that the suite is supported locally.
    #[corresponds(OSSL_HPKE_suite_check)]
    #[inline]
    pub fn check(&self) -> Result<(), ErrorStack> {
        ffi::init();
        unsafe {
            cvt(OSSL_HPKE_suite_check(self.ffi()))?;
            Ok(())
        }
    }

    /// Generate a new key pair.
    ///
    /// Returns the private key and the public key, which can be used by a receiver and sender respectively.
    #[corresponds(OSSL_HPKE_keygen)]
    #[inline]
    pub fn keygen(&self, ikm: Option<&[u8]>) -> Result<(PKey<Private>, Vec<u8>), ErrorStack> {
        ffi::init();
        let mut public_key = vec![0; self.public_encap_size()];
        let mut private_key = ptr::null_mut();

        unsafe {
            cvt(OSSL_HPKE_keygen(
                self.ffi(),
                public_key.as_mut_ptr(),
                &mut public_key.len(),
                &mut private_key,
                ikm.map(|ikm| ikm.as_ptr()).unwrap_or(ptr::null()),
                ikm.map(|ikm| ikm.len()).unwrap_or(0),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok((PKey::from_ptr(private_key), public_key))
        }
    }

    /// Get the size of the public encapsulation.
    ///
    /// This is a helper function to determine the size of the buffer needed for the encapsulation.
    #[corresponds(OSSL_HPKE_get_public_encap_size)]
    #[inline]
    pub fn public_encap_size(&self) -> usize {
        ffi::init();
        unsafe {
            OSSL_HPKE_get_public_encap_size(ffi::OSSL_HPKE_SUITE {
                kem_id: self.kem_id.0,
                kdf_id: self.kdf_id.0,
                aead_id: self.aead_id.0,
            })
        }
    }

    /// Get the size of the ciphertext for a given plaintext length.
    #[corresponds(OSSL_HPKE_get_ciphertext_size)]
    #[inline]
    pub fn ciphertext_size(&self, clear_len: usize) -> usize {
        ffi::init();
        unsafe {
            ffi::OSSL_HPKE_get_ciphertext_size(
                ffi::OSSL_HPKE_SUITE {
                    kem_id: self.kem_id.0,
                    kdf_id: self.kdf_id.0,
                    aead_id: self.aead_id.0,
                },
                clear_len,
            )
        }
    }

    /// Get the recommended length for the initial key material.
    #[corresponds(OSSL_HPKE_get_recommended_ikmelen)]
    #[inline]
    pub fn recommended_ikmelen(&self) -> usize {
        ffi::init();
        unsafe {
            ffi::OSSL_HPKE_get_recommended_ikmelen(ffi::OSSL_HPKE_SUITE {
                kem_id: self.kem_id.0,
                kdf_id: self.kdf_id.0,
                aead_id: self.aead_id.0,
            })
        }
    }

    /// Creates a grease value.
    ///
    /// This value is of the appropriate length for a given suite_in value (or a random value if suite_in is not provided)
    /// so that a protocol using HPKE can send so-called GREASE (see RFC8701) values that are harder to distinguish
    /// from a real use of HPKE.
    /// Returns a tuple of `enc` and `ct`. The output `enc` value will have an appropriate length for the suite and a random value,
    /// and the ct output will be a random value.
    #[corresponds(OSSL_HPKE_get_grease_value)]
    #[inline]
    pub fn get_grease_value(
        &self,
        suite_in: Option<Suite>,
        clear_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        ffi::init();
        let mut enc = vec![0; self.public_encap_size()];
        let mut ct = vec![0; self.ciphertext_size(clear_len)];

        unsafe {
            let mut enclen = enc.len();
            cvt(OSSL_HPKE_get_grease_value(
                suite_in.as_ref().map_or(ptr::null_mut(), |s| {
                    &s.ffi() as *const OSSL_HPKE_SUITE as *mut OSSL_HPKE_SUITE
                }),
                &self.ffi() as *const OSSL_HPKE_SUITE as *mut OSSL_HPKE_SUITE,
                enc.as_mut_ptr(),
                &mut enclen,
                ct.as_mut_ptr(),
                ct.len(),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            Ok((enc, ct))
        }
    }
}

impl TryFrom<&str> for Suite {
    type Error = ErrorStack;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ffi::init();
        unsafe {
            let s = CString::new(s).unwrap();
            let mut suite = OSSL_HPKE_SUITE_DEFAULT;
            cvt(OSSL_HPKE_str2suite(s.as_ptr(), &mut suite as *mut _))?;
            Ok(Suite {
                kem_id: Kem(suite.kem_id),
                kdf_id: Kdf(suite.kdf_id),
                aead_id: Aead(suite.aead_id),
            })
        }
    }
}

impl Default for Suite {
    /// The default suite is X25519, HKDF-SHA256, and AES-GCM-128.
    ///
    /// If compiled without ECX support, the default suite is P-256, HKDF-SHA256, and AES-GCM-128.
    fn default() -> Self {
        let suite = OSSL_HPKE_SUITE_DEFAULT;
        Suite {
            kem_id: Kem(suite.kem_id),
            kdf_id: Kdf(suite.kdf_id),
            aead_id: Aead(suite.aead_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mode, Suite};

    // https://docs.openssl.org/master/man3/OSSL_HPKE_CTX_new/#examples
    #[test]
    fn roundtrip() {
        let suite = Suite::default();
        let pt = b"a message not in a bottle";
        let info = b"Some info";
        let aad: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut enc = vec![0; suite.public_encap_size()];
        let mut ct = vec![0; suite.ciphertext_size(pt.len())];

        // Generate receiver's key pair.
        let (private_key, public_key) = suite.keygen(None).unwrap();

        // Sender - encrypt the message with the receiver's public key.
        let sender = suite.new_sender(Mode::BASE).unwrap();
        sender.encap(&mut enc, &public_key, info).unwrap();
        sender.seal(&mut ct, &aad, pt).unwrap();

        // Receiver - decrypt the message with the private key.
        let receiver = suite.new_receiver(Mode::BASE).unwrap();
        receiver.decap(&enc, &private_key, info).unwrap();
        let mut pt2 = vec![0; ct.len()];
        let pt_len = receiver.open(&mut pt2, &aad, &ct).unwrap();
        assert_eq!(pt, &pt2[..pt_len]);
    }

    #[test]
    fn try_from() {
        let suite = Suite::try_from("p-256,hkdf-sha256,aes-128-gcm").unwrap();
        assert_eq!(suite.kem_id, super::Kem::P256);
    }
}
