//! Add extensions to an `X509` certificate or certificate request.
//!
//! The extensions defined for X.509 v3 certificates provide methods for
//! associating additional attributes with users or public keys and for
//! managing relationships between CAs. The extensions created using this
//! module can be used with `X509v3Context` objects.
//!
//! # Example
//!
//! ```rust
//! use openssl::x509::extension::BasicConstraints;
//! use openssl::x509::X509Extension;
//!
//! let mut bc = BasicConstraints::new();
//! let bc = bc.critical().ca().pathlen(1);
//!
//! let extension: X509Extension = bc.build().unwrap();
//! ```
use std::fmt::Write;

use crate::asn1::Asn1Object;
use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::x509::{GeneralName, Stack, X509Extension, X509Name, X509v3Context};
use foreign_types::ForeignType;

/// An extension which indicates whether a certificate is a CA certificate.
pub struct BasicConstraints {
    critical: bool,
    ca: bool,
    pathlen: Option<u32>,
}

impl Default for BasicConstraints {
    fn default() -> BasicConstraints {
        BasicConstraints::new()
    }
}

impl BasicConstraints {
    /// Construct a new `BasicConstraints` extension.
    pub fn new() -> BasicConstraints {
        BasicConstraints {
            critical: false,
            ca: false,
            pathlen: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut BasicConstraints {
        self.critical = true;
        self
    }

    /// Sets the `ca` flag to `true`.
    pub fn ca(&mut self) -> &mut BasicConstraints {
        self.ca = true;
        self
    }

    /// Sets the `pathlen` to an optional non-negative value. The `pathlen` is the
    /// maximum number of CAs that can appear below this one in a chain.
    pub fn pathlen(&mut self, pathlen: u32) -> &mut BasicConstraints {
        self.pathlen = Some(pathlen);
        self
    }

    /// Return the `BasicConstraints` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        if self.critical {
            value.push_str("critical,");
        }
        value.push_str("CA:");
        if self.ca {
            value.push_str("TRUE");
        } else {
            value.push_str("FALSE");
        }
        if let Some(pathlen) = self.pathlen {
            write!(value, ",pathlen:{}", pathlen).unwrap();
        }
        X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, &value)
    }
}

/// An extension consisting of a list of names of the permitted key usages.
pub struct KeyUsage {
    critical: bool,
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
    decipher_only: bool,
}

impl Default for KeyUsage {
    fn default() -> KeyUsage {
        KeyUsage::new()
    }
}

impl KeyUsage {
    /// Construct a new `KeyUsage` extension.
    pub fn new() -> KeyUsage {
        KeyUsage {
            critical: false,
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut KeyUsage {
        self.critical = true;
        self
    }

    /// Sets the `digitalSignature` flag to `true`.
    pub fn digital_signature(&mut self) -> &mut KeyUsage {
        self.digital_signature = true;
        self
    }

    /// Sets the `nonRepudiation` flag to `true`.
    pub fn non_repudiation(&mut self) -> &mut KeyUsage {
        self.non_repudiation = true;
        self
    }

    /// Sets the `keyEncipherment` flag to `true`.
    pub fn key_encipherment(&mut self) -> &mut KeyUsage {
        self.key_encipherment = true;
        self
    }

    /// Sets the `dataEncipherment` flag to `true`.
    pub fn data_encipherment(&mut self) -> &mut KeyUsage {
        self.data_encipherment = true;
        self
    }

    /// Sets the `keyAgreement` flag to `true`.
    pub fn key_agreement(&mut self) -> &mut KeyUsage {
        self.key_agreement = true;
        self
    }

    /// Sets the `keyCertSign` flag to `true`.
    pub fn key_cert_sign(&mut self) -> &mut KeyUsage {
        self.key_cert_sign = true;
        self
    }

    /// Sets the `cRLSign` flag to `true`.
    pub fn crl_sign(&mut self) -> &mut KeyUsage {
        self.crl_sign = true;
        self
    }

    /// Sets the `encipherOnly` flag to `true`.
    pub fn encipher_only(&mut self) -> &mut KeyUsage {
        self.encipher_only = true;
        self
    }

    /// Sets the `decipherOnly` flag to `true`.
    pub fn decipher_only(&mut self) -> &mut KeyUsage {
        self.decipher_only = true;
        self
    }

    /// Return the `KeyUsage` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(
            &mut value,
            &mut first,
            self.digital_signature,
            "digitalSignature",
        );
        append(
            &mut value,
            &mut first,
            self.non_repudiation,
            "nonRepudiation",
        );
        append(
            &mut value,
            &mut first,
            self.key_encipherment,
            "keyEncipherment",
        );
        append(
            &mut value,
            &mut first,
            self.data_encipherment,
            "dataEncipherment",
        );
        append(&mut value, &mut first, self.key_agreement, "keyAgreement");
        append(&mut value, &mut first, self.key_cert_sign, "keyCertSign");
        append(&mut value, &mut first, self.crl_sign, "cRLSign");
        append(&mut value, &mut first, self.encipher_only, "encipherOnly");
        append(&mut value, &mut first, self.decipher_only, "decipherOnly");
        X509Extension::new_nid(None, None, Nid::KEY_USAGE, &value)
    }
}

/// An extension consisting of a list of usages indicating purposes
/// for which the certificate public key can be used for.
pub struct ExtendedKeyUsage {
    critical: bool,
    items: Vec<String>,
}

impl Default for ExtendedKeyUsage {
    fn default() -> ExtendedKeyUsage {
        ExtendedKeyUsage::new()
    }
}

impl ExtendedKeyUsage {
    /// Construct a new `ExtendedKeyUsage` extension.
    pub fn new() -> ExtendedKeyUsage {
        ExtendedKeyUsage {
            critical: false,
            items: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut ExtendedKeyUsage {
        self.critical = true;
        self
    }

    /// Sets the `serverAuth` flag to `true`.
    pub fn server_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.other("serverAuth")
    }

    /// Sets the `clientAuth` flag to `true`.
    pub fn client_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.other("clientAuth")
    }

    /// Sets the `codeSigning` flag to `true`.
    pub fn code_signing(&mut self) -> &mut ExtendedKeyUsage {
        self.other("codeSigning")
    }

    /// Sets the `emailProtection` flag to `true`.
    pub fn email_protection(&mut self) -> &mut ExtendedKeyUsage {
        self.other("emailProtection")
    }

    /// Sets the `timeStamping` flag to `true`.
    pub fn time_stamping(&mut self) -> &mut ExtendedKeyUsage {
        self.other("timeStamping")
    }

    /// Sets the `msCodeInd` flag to `true`.
    pub fn ms_code_ind(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msCodeInd")
    }

    /// Sets the `msCodeCom` flag to `true`.
    pub fn ms_code_com(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msCodeCom")
    }

    /// Sets the `msCTLSign` flag to `true`.
    pub fn ms_ctl_sign(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msCTLSign")
    }

    /// Sets the `msSGC` flag to `true`.
    pub fn ms_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msSGC")
    }

    /// Sets the `msEFS` flag to `true`.
    pub fn ms_efs(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msEFS")
    }

    /// Sets the `nsSGC` flag to `true`.
    pub fn ns_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.other("nsSGC")
    }

    /// Sets a flag not already defined.
    pub fn other(&mut self, other: &str) -> &mut ExtendedKeyUsage {
        self.items.push(other.to_string());
        self
    }

    /// Return the `ExtendedKeyUsage` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut stack = Stack::new()?;
        for item in &self.items {
            stack.push(Asn1Object::from_str(item)?)?;
        }
        unsafe {
            X509Extension::new_internal(Nid::EXT_KEY_USAGE, self.critical, stack.as_ptr().cast())
        }
    }
}

/// An extension that provides a means of identifying certificates that contain a
/// particular public key.
pub struct SubjectKeyIdentifier {
    critical: bool,
}

impl Default for SubjectKeyIdentifier {
    fn default() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier::new()
    }
}

impl SubjectKeyIdentifier {
    /// Construct a new `SubjectKeyIdentifier` extension.
    pub fn new() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier { critical: false }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut SubjectKeyIdentifier {
        self.critical = true;
        self
    }

    /// Return a `SubjectKeyIdentifier` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self, ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, true, "hash");
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_KEY_IDENTIFIER, &value)
    }
}

/// An extension that provides a means of identifying the public key corresponding
/// to the private key used to sign a CRL.
pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<bool>,
    issuer: Option<bool>,
}

impl Default for AuthorityKeyIdentifier {
    fn default() -> AuthorityKeyIdentifier {
        AuthorityKeyIdentifier::new()
    }
}

impl AuthorityKeyIdentifier {
    /// Construct a new `AuthorityKeyIdentifier` extension.
    pub fn new() -> AuthorityKeyIdentifier {
        AuthorityKeyIdentifier {
            critical: false,
            keyid: None,
            issuer: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut AuthorityKeyIdentifier {
        self.critical = true;
        self
    }

    /// Sets the `keyid` flag.
    pub fn keyid(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.keyid = Some(always);
        self
    }

    /// Sets the `issuer` flag.
    pub fn issuer(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.issuer = Some(always);
        self
    }

    /// Return a `AuthorityKeyIdentifier` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self, ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        match self.keyid {
            Some(true) => append(&mut value, &mut first, true, "keyid:always"),
            Some(false) => append(&mut value, &mut first, true, "keyid"),
            None => {}
        }
        match self.issuer {
            Some(true) => append(&mut value, &mut first, true, "issuer:always"),
            Some(false) => append(&mut value, &mut first, true, "issuer"),
            None => {}
        }
        X509Extension::new_nid(None, Some(ctx), Nid::AUTHORITY_KEY_IDENTIFIER, &value)
    }
}

enum RustGeneralName {
    Dns(String),
    Email(String),
    Uri(String),
    Ip(String),
    Rid(String),
    OtherName(Asn1Object, Vec<u8>),
    DirName(X509Name),
}

/// An extension that allows additional identities to be bound to the subject
/// of the certificate.
pub struct SubjectAlternativeName {
    critical: bool,
    items: Vec<RustGeneralName>,
}

impl Default for SubjectAlternativeName {
    fn default() -> SubjectAlternativeName {
        SubjectAlternativeName::new()
    }
}

impl SubjectAlternativeName {
    /// Construct a new `SubjectAlternativeName` extension.
    pub fn new() -> SubjectAlternativeName {
        SubjectAlternativeName {
            critical: false,
            items: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut SubjectAlternativeName {
        self.critical = true;
        self
    }

    /// Sets the `email` flag.
    pub fn email(&mut self, email: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Email(email.to_string()));
        self
    }

    /// Sets the `uri` flag.
    pub fn uri(&mut self, uri: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Uri(uri.to_string()));
        self
    }

    /// Sets the `dns` flag.
    pub fn dns(&mut self, dns: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Dns(dns.to_string()));
        self
    }

    /// Sets the `rid` flag.
    pub fn rid(&mut self, rid: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Rid(rid.to_string()));
        self
    }

    /// Sets the `ip` flag.
    pub fn ip(&mut self, ip: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Ip(ip.to_string()));
        self
    }

    /// Sets the `dirName` flag.
    ///
    /// Not currently actually supported, always panics. Please use dir_name2
    #[deprecated = "dir_name is deprecated and always panics. Please use dir_name2."]
    pub fn dir_name(&mut self, _dir_name: &str) -> &mut SubjectAlternativeName {
        unimplemented!("This has not yet been adapted for the new internals. Use dir_name2.");
    }

    /// Sets the `dirName` flag.
    pub fn dir_name2(&mut self, dir_name: X509Name) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::DirName(dir_name));
        self
    }

    /// Sets the `otherName` flag.
    ///
    /// Not currently actually supported, always panics. Please use other_name2
    #[deprecated = "other_name is deprecated and always panics. Please use other_name2."]
    pub fn other_name(&mut self, _other_name: &str) -> &mut SubjectAlternativeName {
        unimplemented!("This has not yet been adapted for the new internals. Use other_name2.");
    }

    /// Sets the `otherName` flag.
    ///
    /// `content` must be a valid der encoded ASN1_TYPE
    ///
    /// If you want to add just a ia5string use `other_name_ia5string`
    pub fn other_name2(&mut self, oid: Asn1Object, content: &[u8]) -> &mut SubjectAlternativeName {
        self.items
            .push(RustGeneralName::OtherName(oid, content.into()));
        self
    }

    /// Return a `SubjectAlternativeName` extension as an `X509Extension`.
    pub fn build(&self, _ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut stack = Stack::new()?;
        for item in &self.items {
            let gn = match item {
                RustGeneralName::Dns(s) => GeneralName::new_dns(s.as_bytes())?,
                RustGeneralName::Email(s) => GeneralName::new_email(s.as_bytes())?,
                RustGeneralName::Uri(s) => GeneralName::new_uri(s.as_bytes())?,
                RustGeneralName::Ip(s) => {
                    GeneralName::new_ip(s.parse().map_err(|_| ErrorStack::get())?)?
                }
                RustGeneralName::Rid(s) => GeneralName::new_rid(Asn1Object::from_str(s)?)?,
                RustGeneralName::OtherName(oid, content) => {
                    GeneralName::new_other_name(oid.clone(), content)?
                }
                RustGeneralName::DirName(name) => GeneralName::new_dir_name(name.as_ref())?,
            };
            stack.push(gn)?;
        }

        unsafe {
            X509Extension::new_internal(Nid::SUBJECT_ALT_NAME, self.critical, stack.as_ptr().cast())
        }
    }
}

pub struct CrlNumber(i64);

impl CrlNumber {
    pub fn new(number: i64) -> Self {
        Self(number)
    }

    pub fn build(self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            ffi::init();

            let int_ptr = cvt_p(ffi::ASN1_INTEGER_new())?;

            if let Err(e) = cvt(ffi::ASN1_INTEGER_set(int_ptr, self.0)) {
                ffi::ASN1_INTEGER_free(int_ptr);
                return Err(e);
            }

            let r = cvt_p(ffi::X509V3_EXT_i2d(
                Nid::CRL_NUMBER.as_raw(),
                0,
                int_ptr.cast(),
            ))
            .map(|p| X509Extension::from_ptr(p));
            ffi::ASN1_INTEGER_free(int_ptr);
            r
        }
    }
}

unsafe impl ExtensionType for CrlNumber {
    const NID: Nid = Nid::CRL_NUMBER;
    type Output = Asn1Integer;
}

pub struct CrlIssuerAlternativeName(Stack<GeneralName>);

impl CrlIssuerAlternativeName {
    pub fn new(ian: Stack<GeneralName>) -> Self {
        Self(ian)
    }

    pub fn build(self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            ffi::init();

            let gns: *mut ffi::OPENSSL_STACK = self.0.as_ptr().cast();

            cvt_p(ffi::X509V3_EXT_i2d(
                Nid::ISSUER_ALT_NAME.as_raw(),
                0,
                gns.cast(),
            ))
            .map(|p| X509Extension::from_ptr(p))
        }
    }
}

pub struct AuthorityInfoAccess(Stack<AccessDescription>);

impl AuthorityInfoAccess {
    pub fn new(ai: Stack<AccessDescription>) -> Self {
        Self(ai)
    }

    pub fn build(self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            ffi::init();

            let ads = self.0.as_ptr();
            cvt_p(ffi::X509V3_EXT_i2d(
                Nid::INFO_ACCESS.as_raw(),
                0,
                ads.cast(),
            ))
            .map(|p| X509Extension::from_ptr(p))
        }
    }
}

pub struct DeltaCrlIndicator(i64);

impl DeltaCrlIndicator {
    pub fn new(base_crl_number: i64) -> Self {
        Self(base_crl_number)
    }

    pub fn build(self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            ffi::init();

            let int_ptr = cvt_p(ffi::ASN1_INTEGER_new())?;

            if let Err(e) = cvt(ffi::ASN1_INTEGER_set(int_ptr, self.0)) {
                ffi::ASN1_INTEGER_free(int_ptr);
                return Err(e);
            }

            let r = cvt_p(ffi::X509V3_EXT_i2d(
                openssl::nid::Nid::DELTA_CRL.as_raw(),
                1,
                int_ptr.cast(),
            ))
            .map(|p| X509Extension::from_ptr(p));

            ffi::ASN1_INTEGER_free(int_ptr);
            r
        }
    }
}

pub struct IssuingDistributionPoint {
    dp: Option<DistPointName>,
    only_user: bool,
    only_ca: bool,
    only_some_reasons: Option<Vec<CrlReason>>,
    indirect: bool,
    only_attr: bool,
}

impl IssuingDistributionPoint {
    pub fn new() -> Self {
        Self {
            dp: None,
            only_user: false,
            only_ca: false,
            only_some_reasons: None,
            indirect: false,
            only_attr: false,
        }
    }

    pub fn distribution_point(mut self, dp: DistPointName) -> Self {
        self.dp = Some(dp);
        self
    }

    pub fn only_contains_user_certs(mut self, v: bool) -> Self {
        self.only_user = v;
        self
    }

    pub fn only_contains_ca_certs(mut self, v: bool) -> Self {
        self.only_ca = v;
        self
    }

    pub fn indirect_crl(mut self, v: bool) -> Self {
        self.indirect = v;
        self
    }

    pub fn only_contains_attribute_certs(mut self, v: bool) -> Self {
        self.only_attr = v;
        self
    }

    pub fn only_some_reasons(mut self, reasons: Vec<CrlReason>) -> Self {
        self.only_some_reasons = Some(reasons);
        self
    }

    pub fn build(self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            ffi::init();

            let idp = cvt_p(ffi::ISSUING_DIST_POINT_new())?;

            if let Some(dp) = self.dp {
                (*idp).distpoint = dp.as_ptr();
                std::mem::forget(dp);
            }

            (*idp).onlyuser = self.only_user as i32;
            (*idp).onlyCA = self.only_ca as i32;
            (*idp).indirectCRL = self.indirect as i32;
            (*idp).onlyattr = self.only_attr as i32;

            if let Some(reasons) = self.only_some_reasons {
                let bitstr = match cvt_p(ffi::ASN1_BIT_STRING_new()) {
                    Ok(p) => p,
                    Err(e) => {
                        ffi::ISSUING_DIST_POINT_free(idp);
                        return Err(e);
                    }
                };

                for r in reasons {
                    if let Err(e) = cvt(ffi::ASN1_BIT_STRING_set_bit(bitstr, r.as_raw(), 1)) {
                        ffi::ASN1_BIT_STRING_free(bitstr);
                        ffi::ISSUING_DIST_POINT_free(idp);
                        return Err(e);
                    }
                }

                (*idp).onlysomereasons = bitstr;
            }

            let r = cvt_p(ffi::X509V3_EXT_i2d(
                openssl::nid::Nid::ISSUING_DISTRIBUTION_POINT.as_raw(),
                0,
                idp.cast(),
            ))
            .map(|p| X509Extension::from_ptr(p));

            ffi::ISSUING_DIST_POINT_free(idp);

            r
        }
    }
}

pub struct FreshestCrl(Stack<DistPoint>);

impl FreshestCrl {
    pub fn new() -> Result<Self, ErrorStack> {
        Ok(Self(Stack::new()?))
    }

    pub fn add_point(mut self, dp: DistPoint) -> Result<Self, ErrorStack> {
        self.0.push(dp)?;
        Ok(self)
    }

    pub fn build(self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::X509V3_EXT_i2d(
                openssl::nid::Nid::FRESHEST_CRL.as_raw(),
                0,
                self.0.as_ptr().cast(),
            ))
            .map(|p| X509Extension::from_ptr(p))
        }
    }
}


fn append(value: &mut String, first: &mut bool, should: bool, element: &str) {
    if !should {
        return;
    }

    if !*first {
        value.push(',');
    }
    *first = false;
    value.push_str(element);
}
