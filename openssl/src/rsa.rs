//! Rivest–Shamir–Adleman cryptosystem
//!
//! RSA is one of the earliest asymmetric public key encryption schemes.
//! Like many other cryptosystems, RSA relies on the presumed difficulty of a hard
//! mathematical problem, namely factorization of the product of two large prime
//! numbers. At the moment there does not exist an algorithm that can factor such
//! large numbers in reasonable time. RSA is used in a wide variety of
//! applications including digital signatures and key exchanges such as
//! establishing a TLS/SSL connection.
//!
//! The RSA acronym is derived from the first letters of the surnames of the
//! algorithm's founding trio.
//!
//! # Example
//!
//! Generate a 2048-bit RSA key pair and use the public key to encrypt some data.
//!
//! ```rust
//! use openssl::rsa::{Rsa, Padding};
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let data = b"foobar";
//! let mut buf = vec![0; rsa.size() as usize];
//! let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
//! ```
use cfg_if::cfg_if;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::fmt;
use std::mem;
use std::ptr;

use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic, Private, Public};
use crate::util::ForeignTypeRefExt;
use crate::{cvt, cvt_n, cvt_p, LenType};
use openssl_macros::corresponds;

/// Type of encryption padding to use.
///
/// Random length padding is primarily used to prevent attackers from
/// predicting or knowing the exact length of a plaintext message that
/// can possibly lead to breaking encryption.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Padding(c_int);

impl Padding {
    pub const NONE: Padding = Padding(ffi::RSA_NO_PADDING);
    pub const PKCS1: Padding = Padding(ffi::RSA_PKCS1_PADDING);
    pub const PKCS1_OAEP: Padding = Padding(ffi::RSA_PKCS1_OAEP_PADDING);
    pub const PKCS1_PSS: Padding = Padding(ffi::RSA_PKCS1_PSS_PADDING);

    /// Creates a `Padding` from an integer representation.
    pub fn from_raw(value: c_int) -> Padding {
        Padding(value)
    }

    /// Returns the integer representation of `Padding`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::RSA;
    fn drop = ffi::RSA_free;

    /// An RSA key.
    pub struct Rsa<T>;

    /// Reference to `RSA`
    pub struct RsaRef<T>;
}

impl<T> Clone for Rsa<T> {
    fn clone(&self) -> Rsa<T> {
        (**self).to_owned()
    }
}

impl<T> ToOwned for RsaRef<T> {
    type Owned = Rsa<T>;

    fn to_owned(&self) -> Rsa<T> {
        unsafe {
            ffi::RSA_up_ref(self.as_ptr());
            Rsa::from_ptr(self.as_ptr())
        }
    }
}

impl<T> RsaRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_RSAPrivateKey)]
        private_key_to_pem,
        /// Serializes the private key to a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_RSAPrivateKey)]
        private_key_to_pem_passphrase,
        ffi::PEM_write_bio_RSAPrivateKey
    }

    to_der! {
        /// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.
        #[corresponds(i2d_RSAPrivateKey)]
        private_key_to_der,
        ffi::i2d_RSAPrivateKey
    }

    /// Decrypts data using the private key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    #[corresponds(RSA_private_decrypt)]
    pub fn private_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_private_decrypt(
                from.len() as LenType,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Encrypts data using the private key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    #[corresponds(RSA_private_encrypt)]
    pub fn private_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_private_encrypt(
                from.len() as LenType,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Returns a reference to the private exponent of the key.
    #[corresponds(RSA_get0_key)]
    pub fn d(&self) -> &BigNumRef {
        unsafe {
            let mut d = ptr::null();
            RSA_get0_key(self.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut d);
            BigNumRef::from_const_ptr(d)
        }
    }

    /// Returns a reference to the first factor of the exponent of the key.
    #[corresponds(RSA_get0_factors)]
    pub fn p(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut p = ptr::null();
            RSA_get0_factors(self.as_ptr(), &mut p, ptr::null_mut());
            BigNumRef::from_const_ptr_opt(p)
        }
    }

    /// Returns a reference to the second factor of the exponent of the key.
    #[corresponds(RSA_get0_factors)]
    pub fn q(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut q = ptr::null();
            RSA_get0_factors(self.as_ptr(), ptr::null_mut(), &mut q);
            BigNumRef::from_const_ptr_opt(q)
        }
    }

    /// Returns a reference to the first exponent used for CRT calculations.
    #[corresponds(RSA_get0_crt_params)]
    pub fn dmp1(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut dp = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), &mut dp, ptr::null_mut(), ptr::null_mut());
            BigNumRef::from_const_ptr_opt(dp)
        }
    }

    /// Returns a reference to the second exponent used for CRT calculations.
    #[corresponds(RSA_get0_crt_params)]
    pub fn dmq1(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut dq = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), ptr::null_mut(), &mut dq, ptr::null_mut());
            BigNumRef::from_const_ptr_opt(dq)
        }
    }

    /// Returns a reference to the coefficient used for CRT calculations.
    #[corresponds(RSA_get0_crt_params)]
    pub fn iqmp(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut qi = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut qi);
            BigNumRef::from_const_ptr_opt(qi)
        }
    }

    /// Validates RSA parameters for correctness
    #[corresponds(RSA_check_key)]
    pub fn check_key(&self) -> Result<bool, ErrorStack> {
        unsafe {
            let result = ffi::RSA_check_key(self.as_ptr());
            if result != 1 {
                let errors = ErrorStack::get();
                if errors.errors().is_empty() {
                    Ok(false)
                } else {
                    Err(errors)
                }
            } else {
                Ok(true)
            }
        }
    }
}

impl<T> RsaRef<T>
where
    T: HasPublic,
{
    to_pem! {
        /// Serializes the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_write_bio_RSA_PUBKEY)]
        public_key_to_pem,
        ffi::PEM_write_bio_RSA_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        #[corresponds(i2d_RSA_PUBKEY)]
        public_key_to_der,
        ffi::i2d_RSA_PUBKEY
    }

    to_pem! {
        /// Serializes the public key into a PEM-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PUBLIC KEY-----`.
        #[corresponds(PEM_write_bio_RSAPublicKey)]
        public_key_to_pem_pkcs1,
        ffi::PEM_write_bio_RSAPublicKey
    }

    to_der! {
        /// Serializes the public key into a DER-encoded PKCS#1 RSAPublicKey structure.
        #[corresponds(i2d_RSAPublicKey)]
        public_key_to_der_pkcs1,
        ffi::i2d_RSAPublicKey
    }

    /// Returns the size of the modulus in bytes.
    #[corresponds(RSA_size)]
    pub fn size(&self) -> u32 {
        unsafe { ffi::RSA_size(self.as_ptr()) as u32 }
    }

    /// Decrypts data using the public key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    #[corresponds(RSA_public_decrypt)]
    pub fn public_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_public_decrypt(
                from.len() as LenType,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Encrypts data using the public key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    #[corresponds(RSA_public_encrypt)]
    pub fn public_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_public_encrypt(
                from.len() as LenType,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Returns a reference to the modulus of the key.
    #[corresponds(RSA_get0_key)]
    pub fn n(&self) -> &BigNumRef {
        unsafe {
            let mut n = ptr::null();
            RSA_get0_key(self.as_ptr(), &mut n, ptr::null_mut(), ptr::null_mut());
            BigNumRef::from_const_ptr(n)
        }
    }

    /// Returns a reference to the public exponent of the key.
    #[corresponds(RSA_get0_key)]
    pub fn e(&self) -> &BigNumRef {
        unsafe {
            let mut e = ptr::null();
            RSA_get0_key(self.as_ptr(), ptr::null_mut(), &mut e, ptr::null_mut());
            BigNumRef::from_const_ptr(e)
        }
    }
}

impl Rsa<Public> {
    /// Creates a new RSA key with only public components.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent.
    ///
    /// This corresponds to [`RSA_new`] and uses [`RSA_set0_key`].
    ///
    /// [`RSA_new`]: https://docs.openssl.org/master/man3/RSA_new/
    /// [`RSA_set0_key`]: https://docs.openssl.org/master/man3/RSA_set0_key/
    pub fn from_public_components(n: BigNum, e: BigNum) -> Result<Rsa<Public>, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::RSA_new())?;
            RSA_set0_key(rsa, n.as_ptr(), e.as_ptr(), ptr::null_mut());
            mem::forget((n, e));
            Ok(Rsa::from_ptr(rsa))
        }
    }

    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure containing an RSA key.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_read_bio_RSA_PUBKEY)]
        public_key_from_pem,
        Rsa<Public>,
        ffi::PEM_read_bio_RSA_PUBKEY
    }

    from_pem! {
        /// Decodes a PEM-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// The input should have a header of `-----BEGIN RSA PUBLIC KEY-----`.
        #[corresponds(PEM_read_bio_RSAPublicKey)]
        public_key_from_pem_pkcs1,
        Rsa<Public>,
        ffi::PEM_read_bio_RSAPublicKey
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing an RSA key.
        #[corresponds(d2i_RSA_PUBKEY)]
        public_key_from_der,
        Rsa<Public>,
        ffi::d2i_RSA_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded PKCS#1 RSAPublicKey structure.
        #[corresponds(d2i_RSAPublicKey)]
        public_key_from_der_pkcs1,
        Rsa<Public>,
        ffi::d2i_RSAPublicKey
    }
}

pub struct RsaPrivateKeyBuilder {
    rsa: Rsa<Private>,
}

impl RsaPrivateKeyBuilder {
    /// Creates a new `RsaPrivateKeyBuilder`.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent and `d` is the private exponent.
    ///
    /// This corresponds to [`RSA_new`] and uses [`RSA_set0_key`].
    ///
    /// [`RSA_new`]: https://docs.openssl.org/master/man3/RSA_new/
    /// [`RSA_set0_key`]: https://docs.openssl.org/master/man3/RSA_set0_key/
    pub fn new(n: BigNum, e: BigNum, d: BigNum) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::RSA_new())?;
            RSA_set0_key(rsa, n.as_ptr(), e.as_ptr(), d.as_ptr());
            mem::forget((n, e, d));
            Ok(RsaPrivateKeyBuilder {
                rsa: Rsa::from_ptr(rsa),
            })
        }
    }

    /// Sets the factors of the Rsa key.
    ///
    /// `p` and `q` are the first and second factors of `n`.
    #[corresponds(RSA_set0_factors)]
    // FIXME should be infallible
    pub fn set_factors(self, p: BigNum, q: BigNum) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            RSA_set0_factors(self.rsa.as_ptr(), p.as_ptr(), q.as_ptr());
            mem::forget((p, q));
        }
        Ok(self)
    }

    /// Sets the Chinese Remainder Theorem params of the Rsa key.
    ///
    /// `dmp1`, `dmq1`, and `iqmp` are the exponents and coefficient for
    /// CRT calculations which is used to speed up RSA operations.
    #[corresponds(RSA_set0_crt_params)]
    // FIXME should be infallible
    pub fn set_crt_params(
        self,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            RSA_set0_crt_params(
                self.rsa.as_ptr(),
                dmp1.as_ptr(),
                dmq1.as_ptr(),
                iqmp.as_ptr(),
            );
            mem::forget((dmp1, dmq1, iqmp));
        }
        Ok(self)
    }

    /// Returns the Rsa key.
    pub fn build(self) -> Rsa<Private> {
        self.rsa
    }
}

impl Rsa<Private> {
    /// Creates a new RSA key with private components (public components are assumed).
    ///
    /// This a convenience method over:
    /// ```
    /// # use openssl::rsa::RsaPrivateKeyBuilder;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let bn = || openssl::bn::BigNum::new().unwrap();
    /// # let (n, e, d, p, q, dmp1, dmq1, iqmp) = (bn(), bn(), bn(), bn(), bn(), bn(), bn(), bn());
    /// RsaPrivateKeyBuilder::new(n, e, d)?
    ///     .set_factors(p, q)?
    ///     .set_crt_params(dmp1, dmq1, iqmp)?
    ///     .build();
    /// # Ok(()) }
    /// ```
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    pub fn from_private_components(
        n: BigNum,
        e: BigNum,
        d: BigNum,
        p: BigNum,
        q: BigNum,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> Result<Rsa<Private>, ErrorStack> {
        Ok(RsaPrivateKeyBuilder::new(n, e, d)?
            .set_factors(p, q)?
            .set_crt_params(dmp1, dmq1, iqmp)?
            .build())
    }

    /// Generates a public/private key pair with the specified size.
    ///
    /// The public exponent will be 65537.
    #[corresponds(RSA_generate_key_ex)]
    pub fn generate(bits: u32) -> Result<Rsa<Private>, ErrorStack> {
        let e = BigNum::from_u32(ffi::RSA_F4 as u32)?;
        Rsa::generate_with_e(bits, &e)
    }

    /// Generates a public/private key pair with the specified size and a custom exponent.
    ///
    /// Unless you have specific needs and know what you're doing, use `Rsa::generate` instead.
    #[corresponds(RSA_generate_key_ex)]
    pub fn generate_with_e(bits: u32, e: &BigNumRef) -> Result<Rsa<Private>, ErrorStack> {
        unsafe {
            let rsa = Rsa::from_ptr(cvt_p(ffi::RSA_new())?);
            cvt(ffi::RSA_generate_key_ex(
                rsa.0,
                bits as c_int,
                e.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(rsa)
        }
    }

    // FIXME these need to identify input formats
    private_key_from_pem! {
        /// Deserializes a private key from a PEM-encoded PKCS#1 RSAPrivateKey structure.
        #[corresponds(PEM_read_bio_RSAPrivateKey)]
        private_key_from_pem,

        /// Deserializes a private key from a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        #[corresponds(PEM_read_bio_RSAPrivateKey)]
        private_key_from_pem_passphrase,

        /// Deserializes a private key from a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// The callback should fill the password into the provided buffer and return its length.
        #[corresponds(PEM_read_bio_RSAPrivateKey)]
        private_key_from_pem_callback,
        Rsa<Private>,
        ffi::PEM_read_bio_RSAPrivateKey
    }

    from_der! {
        /// Decodes a DER-encoded PKCS#1 RSAPrivateKey structure.
        #[corresponds(d2i_RSAPrivateKey)]
        private_key_from_der,
        Rsa<Private>,
        ffi::d2i_RSAPrivateKey
    }
}

impl<T> fmt::Debug for Rsa<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rsa")
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl, boringssl, awslc))] {
        use ffi::{
            RSA_get0_key, RSA_get0_factors, RSA_get0_crt_params, RSA_set0_key, RSA_set0_factors,
            RSA_set0_crt_params,
        };
    } else {
        #[allow(bad_style)]
        unsafe fn RSA_get0_key(
            r: *const ffi::RSA,
            n: *mut *const ffi::BIGNUM,
            e: *mut *const ffi::BIGNUM,
            d: *mut *const ffi::BIGNUM,
        ) {
            if !n.is_null() {
                *n = (*r).n;
            }
            if !e.is_null() {
                *e = (*r).e;
            }
            if !d.is_null() {
                *d = (*r).d;
            }
        }

        #[allow(bad_style)]
        unsafe fn RSA_get0_factors(
            r: *const ffi::RSA,
            p: *mut *const ffi::BIGNUM,
            q: *mut *const ffi::BIGNUM,
        ) {
            if !p.is_null() {
                *p = (*r).p;
            }
            if !q.is_null() {
                *q = (*r).q;
            }
        }

        #[allow(bad_style)]
        unsafe fn RSA_get0_crt_params(
            r: *const ffi::RSA,
            dmp1: *mut *const ffi::BIGNUM,
            dmq1: *mut *const ffi::BIGNUM,
            iqmp: *mut *const ffi::BIGNUM,
        ) {
            if !dmp1.is_null() {
                *dmp1 = (*r).dmp1;
            }
            if !dmq1.is_null() {
                *dmq1 = (*r).dmq1;
            }
            if !iqmp.is_null() {
                *iqmp = (*r).iqmp;
            }
        }

        #[allow(bad_style)]
        unsafe fn RSA_set0_key(
            r: *mut ffi::RSA,
            n: *mut ffi::BIGNUM,
            e: *mut ffi::BIGNUM,
            d: *mut ffi::BIGNUM,
        ) -> c_int {
            (*r).n = n;
            (*r).e = e;
            (*r).d = d;
            1
        }

        #[allow(bad_style)]
        unsafe fn RSA_set0_factors(
            r: *mut ffi::RSA,
            p: *mut ffi::BIGNUM,
            q: *mut ffi::BIGNUM,
        ) -> c_int {
            (*r).p = p;
            (*r).q = q;
            1
        }

        #[allow(bad_style)]
        unsafe fn RSA_set0_crt_params(
            r: *mut ffi::RSA,
            dmp1: *mut ffi::BIGNUM,
            dmq1: *mut ffi::BIGNUM,
            iqmp: *mut ffi::BIGNUM,
        ) -> c_int {
            (*r).dmp1 = dmp1;
            (*r).dmq1 = dmq1;
            (*r).iqmp = iqmp;
            1
        }
    }
}

#[cfg(test)]
mod test {
    use crate::symm::Cipher;
    use std::str::from_utf8;

    use super::*;

    #[test]
    fn test_accessors() {
        let key = include_bytes!("../test/rsa.pem");
        let rsa = Rsa::private_key_from_pem_passphrase(key, b"mypass").unwrap();

        assert_eq!(
            rsa.n().to_string(),
            BigNum::from_hex_str("A1F8160AE2E3C9B465CE8D2D656263362B927DBE29E1F02477FC1625CC90A136E38BD93497C5B6EA63DD7711E67C7429F956B0FB8A8F089ADC4B69893CC1333F53EDD019B87784252FEC914FE4857769594BEA4280D32C0F55BF62944F130396BC6E9BDF6EBDD2BDA3678EECA0C668F701B38DBFFB38C8342CE2FE6D27FADE4A5A4874979DD4B9CF9ADEC4C75B05852C2C0F5EF8A5C1750392F944E8ED64C110C6B647609AA4783AEB9C6C9AD755313050638B83665C6F6F7A82A396702A1F641B82D3EBF2392219491FB686872C5716F50AF8358D9A8B9D17C340728F7F87D89A18D8FCAB67AD84590C2ECF759339363C07034D6F606F9E21E05456CAE5E9A1").unwrap().to_string(),
        );
        assert_eq!(
            rsa.e().to_string(),
            BigNum::from_dec_str("65537").unwrap().to_string(),
        );
        assert_eq!(
            rsa.d().to_string(),
            BigNum::from_hex_str("12AE71A469CD0A2BC37E526C4500571F1D61751D64E949707B62590F9D0BA57C963C401E3FCF2F2CD3BDEC88E503BFC6439B0B28C82F7D3797671F5213EED8C15A25D8D5CEA0025EE3AB2E8B7F79216FC63BEA562753B40644C6A15127D9B2954540A0BBE1A30556982D4E9FDE5F6425F14D4B713441B55DC73B9B4AEDCC92ACE3927E37F57D0CFD5E7581FA512C8F4961A9EB0B80F8A80746728A55FF46471F3425063B9D53642F5EDE1E84D613081AFA5C22D051285BD63B943B565D898A05685413E53C3C6C6525FF1FE34E3DDC70F0D56450FDA48BA12E104E9DEB9FB81881E1C4BDF25D9247F450C865927968E77334F4414F75A750E139546E3A8A739D").unwrap().to_string(),
        );

        assert_eq!(
            rsa.p().unwrap().to_string(),
            BigNum::from_hex_str("E01CC410EB48A6655D54464D0AA4BB6DA0B872B774A6A9D11FFE480778F0DDB7311A7E902EF9C4B5F75476262BA8176CB35979F014372A1A2829E4136BD001D07C3F3F2E4F25D4C934F63C7109FBA2E67628A0DC9A73C6058E6DEF22DCD50950E711DDC16D5586F2A7FA75EA8494C18083E0B65742F8A0D5E73FB2D970F01947").unwrap().to_string(),
        );
        assert_eq!(
            rsa.q().unwrap().to_string(),
            BigNum::from_hex_str("B903C47E0995B632F4532CB1F3C199145D5F3AE9C7DFEEDC7A92A6B47E29C61B42A07AA95A64FC600999C5A7B01E01C08CB62CA756527BBCC56078FB0BABA5ED38DE2D07990FF6300FAEADEB6C039A97BF1E507E4E7040FA78DB8257C8B112ED5E59C3CD092FE5D4E5B51275D41281072A5E785EBAF3DAE3709203133F5159D7").unwrap().to_string(),
        );

        assert_eq!(
            rsa.dmp1().unwrap().to_string(),
            BigNum::from_hex_str("07029F577024AB9FCC1590C56429D6FB0CE5F820A8F375A866F9CB430093783BFCBB396E4529E6EF52374022DD86BA84D9EF58931BEEC5D05FA53FCF23B633F8538A9EED51E87B097830A39F5D92937BE6024B55DB36F7E0C09DCBB72975387F615AFBB6CB36BBABE7793C2B03CEAB66DBB931BAF50B55EC9AF9311D001D628D").unwrap().to_string(),
        );
        assert_eq!(
            rsa.dmq1().unwrap().to_string(),
            BigNum::from_hex_str("87FF7AFA62B547FEE0961B2E9BCD5D6718D39D8CA73DB6691F38998DE78771762C5DA68CC243A5383B166BB23DC570E84706CA801EF5F6BAE6236A0AAFA3770E8F54D1A8DA1C5F8D2899F082331DDB0F5C8F3DFFFA4C8D97102BDAFE082A118DA6633988880E4B55599CE67AF26EBFA5B2C14A9DE7B2C4DD96ABDDD2D2224C75").unwrap().to_string(),
        );
        assert_eq!(
            rsa.iqmp().unwrap().to_string(),
            BigNum::from_hex_str("21877B0C73A1AD6BF19303D0B11336B4E82B8DB72B7EFB50262A5DF8395CC7256EB8CF6C40B7608D5936A32DBA174126A527062EAD8CA305FB7E177F409437C9DCB9718ED82018BCEF0F7720A2C475F9DB26DA0E3CB516D084EB25178E828D5CABD49BB3161AC0181FA7F821E80E7AD37936F9943054AD092921EE2C592E4375").unwrap().to_string(),
        );
    }

    #[test]
    fn test_private_key_from_pem() {
        Rsa::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();
    }

    #[test]
    fn test_private_key_from_pem_pkcs1() {
        Rsa::private_key_from_pem(include_bytes!("../test/rsa.pkcs1.pem")).unwrap();
    }
    #[test]
    fn test_private_key_from_der() {
        Rsa::private_key_from_der(include_bytes!("../test/rsa.der")).unwrap();
    }

    #[test]
    fn test_private_key_from_der_pkcs1() {
        Rsa::private_key_from_der(include_bytes!("../test/rsa.pkcs1.der")).unwrap();
    }

    #[test]
    fn test_private_key_from_pem_password() {
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_passphrase(key, b"mypass").unwrap();
    }

    #[test]
    fn test_private_key_from_pem_callback() {
        let mut password_queried = false;
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_callback(key, |password| {
            password_queried = true;
            password[..6].copy_from_slice(b"mypass");
            Ok(6)
        })
        .unwrap();

        assert!(password_queried);
    }

    #[test]
    fn test_private_key_to_pem() {
        let key = Rsa::private_key_from_der(include_bytes!("../test/rsa.der")).unwrap();
        let pem = key.private_key_to_pem().unwrap();
        assert_eq!(
            from_utf8(&pem).unwrap(),
            include_str!("../test/rsa.pkcs1.pem").replace("\r\n", "\n")
        );
    }

    #[test]
    fn test_private_key_to_pem_password() {
        let key = Rsa::private_key_from_der(include_bytes!("../test/rsa.der")).unwrap();
        let pem = key
            .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"foobar")
            .unwrap();
        Rsa::private_key_from_pem_passphrase(&pem, b"foobar").unwrap();
        assert!(Rsa::private_key_from_pem_passphrase(&pem, b"fizzbuzz").is_err());
    }

    #[test]
    fn test_private_key_to_der_pkcs1() {
        let key = super::Rsa::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();
        let der = key.private_key_to_der().unwrap();
        assert_eq!(der, include_bytes!("../test/rsa.pkcs1.der"));
    }

    #[test]
    fn test_public_encrypt_private_decrypt_with_padding() {
        let key = include_bytes!("../test/rsa.pub.pem");
        let public_key = Rsa::public_key_from_pem(key).unwrap();

        let mut result = vec![0; public_key.size() as usize];
        let original_data = b"This is test";
        let len = public_key
            .public_encrypt(original_data, &mut result, Padding::PKCS1)
            .unwrap();
        assert_eq!(len, 256);

        let pkey = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(pkey).unwrap();
        let mut dec_result = vec![0; private_key.size() as usize];
        let len = private_key
            .private_decrypt(&result, &mut dec_result, Padding::PKCS1)
            .unwrap();

        assert_eq!(&dec_result[..len], original_data);
    }

    #[test]
    fn test_private_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.public_key_to_pem().unwrap();
        let k1 = super::Rsa::public_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size() as usize];
        k0.private_encrypt(&msg, &mut emesg, Padding::PKCS1)
            .unwrap();
        let mut dmesg = vec![0; k1.size() as usize];
        let len = k1
            .public_decrypt(&emesg, &mut dmesg, Padding::PKCS1)
            .unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.private_key_to_pem().unwrap();
        let k1 = super::Rsa::private_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size() as usize];
        k0.public_encrypt(&msg, &mut emesg, Padding::PKCS1).unwrap();
        let mut dmesg = vec![0; k1.size() as usize];
        let len = k1
            .private_decrypt(&emesg, &mut dmesg, Padding::PKCS1)
            .unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_key_from_pem_pkcs1() {
        let key = include_bytes!("../test/pkcs1.pem.pub");
        Rsa::public_key_from_pem_pkcs1(key).unwrap();
    }

    #[test]
    fn test_public_key_from_pem_pkcs1_file_panic() {
        let key = include_bytes!("../test/key.pem.pub");
        assert!(Rsa::public_key_from_pem_pkcs1(key).is_err());
    }

    #[test]
    fn test_public_key_to_pem_pkcs1() {
        let keypair = super::Rsa::private_key_from_der(include_bytes!("../test/rsa.der")).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        assert_eq!(
            from_utf8(&pubkey_pem).unwrap(),
            include_str!("../test/rsa.pub.pkcs1.pem").replace("\r\n", "\n")
        );
    }

    #[test]
    fn test_public_key_to_pem() {
        let keypair = super::Rsa::private_key_from_der(include_bytes!("../test/rsa.der")).unwrap();
        let pubkey_pem = keypair.public_key_to_pem().unwrap();
        assert_eq!(
            from_utf8(&pubkey_pem).unwrap(),
            include_str!("../test/rsa.pub.pem").replace("\r\n", "\n")
        );
    }

    #[test]
    fn test_public_key_to_der() {
        let keypair = super::Rsa::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();
        let pubkey_der = keypair.public_key_to_der().unwrap();
        assert_eq!(pubkey_der, include_bytes!("../test/rsa.pub.der"));
    }

    #[test]
    fn test_public_key_to_der_pkcs1() {
        let keypair = super::Rsa::private_key_from_pem(include_bytes!("../test/rsa.pem")).unwrap();
        let pubkey_der = keypair.public_key_to_der_pkcs1().unwrap();
        assert_eq!(pubkey_der, include_bytes!("../test/rsa.pub.pkcs1.der"));
    }

    #[test]
    fn test_public_key_from_pem_pkcs1_generate_panic() {
        assert!(Rsa::public_key_from_der_pkcs1(include_bytes!("../test/rsa.pub.der")).is_err());
    }

    #[test]
    fn test_pem_pkcs1_encrypt() {
        let keypair = super::Rsa::generate(2048).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        let pubkey = super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
        let msg = b"Hello, world!";

        let mut encrypted = vec![0; pubkey.size() as usize];
        let len = pubkey
            .public_encrypt(msg, &mut encrypted, Padding::PKCS1)
            .unwrap();
        assert!(len > msg.len());
        let mut decrypted = vec![0; keypair.size() as usize];
        let len = keypair
            .private_decrypt(&encrypted, &mut decrypted, Padding::PKCS1)
            .unwrap();
        assert_eq!(len, msg.len());
        assert_eq!(&decrypted[..len], msg);
    }

    #[test]
    fn test_pem_pkcs1_padding() {
        let keypair = super::Rsa::generate(2048).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        let pubkey = super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
        let msg = b"foo";

        let mut encrypted1 = vec![0; pubkey.size() as usize];
        let mut encrypted2 = vec![0; pubkey.size() as usize];
        let len1 = pubkey
            .public_encrypt(msg, &mut encrypted1, Padding::PKCS1)
            .unwrap();
        let len2 = pubkey
            .public_encrypt(msg, &mut encrypted2, Padding::PKCS1)
            .unwrap();
        assert!(len1 > (msg.len() + 1));
        assert_eq!(len1, len2);
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn clone() {
        let key = Rsa::generate(2048).unwrap();
        drop(key.clone());
    }

    #[test]
    fn test_private_key_builder() {
        let key = include_bytes!("../test/rsa.pem");
        let rsa = Rsa::private_key_from_pem_passphrase(key, b"mypass").unwrap();

        let rsa2 = Rsa::from_private_components(
            rsa.n().to_owned().unwrap(),
            rsa.e().to_owned().unwrap(),
            rsa.d().to_owned().unwrap(),
            rsa.p().unwrap().to_owned().unwrap(),
            rsa.q().unwrap().to_owned().unwrap(),
            rsa.dmp1().unwrap().to_owned().unwrap(),
            rsa.dmq1().unwrap().to_owned().unwrap(),
            rsa.iqmp().unwrap().to_owned().unwrap(),
        )
        .unwrap();
        assert_eq!(rsa.n(), rsa2.n(), "n");
        assert_eq!(rsa.e(), rsa2.e(), "e");
        assert_eq!(rsa.d(), rsa2.d(), "d");
        assert_eq!(rsa.p(), rsa2.p(), "p");
        assert_eq!(rsa.q(), rsa2.q(), "q");
        assert_eq!(rsa.dmp1(), rsa2.dmp1(), "dmp1");
        assert_eq!(rsa.dmq1(), rsa2.dmq1(), "dmq1");
        assert_eq!(rsa.iqmp(), rsa2.iqmp(), "iqmp");
    }

    #[test]
    fn generate_with_e() {
        let e = BigNum::from_u32(0x10001).unwrap();
        Rsa::generate_with_e(2048, &e).unwrap();
    }

    #[test]
    fn test_check_key() {
        let k = Rsa::private_key_from_pem_passphrase(
            include_bytes!("../test/rsa-encrypted.pem"),
            b"mypass",
        )
        .unwrap();
        assert!(matches!(k.check_key(), Ok(true)));
        assert!(ErrorStack::get().errors().is_empty());

        // BoringSSL simply rejects this key, because its corrupted!
        if let Ok(k) = Rsa::private_key_from_pem(include_bytes!("../test/corrupted-rsa.pem")) {
            assert!(matches!(k.check_key(), Ok(false) | Err(_)));
            assert!(ErrorStack::get().errors().is_empty());
        }
    }
}
