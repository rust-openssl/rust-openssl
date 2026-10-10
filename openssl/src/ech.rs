//! Encrypted Client Hello (ECH).
//!
//! ECH (RFC 9849) encrypts the sensitive parts of the TLS ClientHello -
//! above all the real server name - inside an outer ClientHello carrying
//! a cover name. A server publishes an ECHConfig (via the `ech` SvcParam
//! of a DNS HTTPS record) describing an HPKE key pair and the cover name;
//! clients encrypt to it, and the server either decrypts and proceeds
//! with the inner handshake or falls back to the outer one.
//!
//! This module wraps OpenSSL's ECH store, the `OSSL_ECHSTORE` object
//! holding ECHConfigs and their private keys: create a store, generate or
//! load key material, serialize entries as ECH PEM files, and attach the
//! store to an [`SslContextBuilder`](crate::ssl::SslContextBuilder) to
//! accept ECH on a listener. Per-connection outcomes are available via
//! [`SslRef::ech_status`](crate::ssl::SslRef::ech_status).
//!
//! Requires OpenSSL 4.0 or newer; ECH does not exist in OpenSSL 3.x.

use crate::bio::{MemBio, MemBioSlice};
use crate::error::ErrorStack;
use crate::pkey::{PKeyRef, Private};
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::time_t;
use openssl_macros::corresponds;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::time::Duration;

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_ECHSTORE;
    fn drop = ffi::OSSL_ECHSTORE_free;

    /// A store of ECHConfigs and their private keys.
    ///
    /// A store is attached to an `SslContext` (or an individual `Ssl`) to
    /// enable ECH; OpenSSL copies the store on attachment, so the store
    /// itself stays valid and usable afterwards.
    pub struct EchStore;
    /// A reference to an [`EchStore`].
    pub struct EchStoreRef;
}

impl EchStore {
    /// Creates a new, empty store in the default library context.
    #[corresponds(OSSL_ECHSTORE_new)]
    pub fn new() -> Result<Self, ErrorStack> {
        unsafe {
            let p = cvt_p(ffi::OSSL_ECHSTORE_new(ptr::null_mut(), ptr::null()))?;
            Ok(EchStore::from_ptr(p))
        }
    }
}

impl EchStoreRef {
    /// Generates a fresh ECH key pair and an ECHConfig for `public_name`,
    /// appending the entry to the store.
    ///
    /// `version` is the ECHConfig version, normally
    /// `ffi::OSSL_ECH_RFC9849_VERSION`. `max_name_length` is the longest
    /// inner server name clients will use, for ECH padding; 0 means no
    /// known maximum and is the usual choice.
    #[corresponds(OSSL_ECHSTORE_new_config)]
    pub fn new_config(
        &mut self,
        version: u16,
        max_name_length: u8,
        public_name: &str,
        suite: HpkeSuite,
    ) -> Result<(), ErrorStack> {
        let public_name = CString::new(public_name).unwrap();
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_new_config(
                self.as_ptr(),
                version,
                max_name_length,
                public_name.as_ptr(),
                suite.to_ffi(),
            ))?;
        }
        Ok(())
    }

    /// Serializes one entry as an ECH PEM file body: its private-key
    /// block (when the store holds the key) followed by its ECHCONFIG
    /// block. This is the on-disk key-file form consumed by
    /// [`read_pem`](Self::read_pem); handle it as a secret.
    ///
    /// `index` selects the entry; `ffi::OSSL_ECHSTORE_LAST` selects the
    /// last entry and `ffi::OSSL_ECHSTORE_ALL` writes every entry
    /// (public values only).
    #[corresponds(OSSL_ECHSTORE_write_pem)]
    pub fn write_pem(&mut self, index: c_int) -> Result<Vec<u8>, ErrorStack> {
        let bio = MemBio::new()?;
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_write_pem(
                self.as_ptr(),
                index,
                bio.as_ptr(),
            ))?;
        }
        Ok(bio.get_buf().to_vec())
    }

    /// Loads an ECH PEM file body: a private key plus its ECHConfigList.
    ///
    /// With `for_retry`, the loaded configs join the retry-configs a
    /// server hands to clients whose ECH attempt failed.
    #[corresponds(OSSL_ECHSTORE_read_pem)]
    pub fn read_pem(&mut self, pem: &[u8], for_retry: bool) -> Result<(), ErrorStack> {
        let bio = MemBioSlice::new(pem)?;
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_read_pem(
                self.as_ptr(),
                bio.as_ptr(),
                for_retry as c_int,
            ))?;
        }
        Ok(())
    }

    /// Loads an ECH PEM file body, taking the private key for its
    /// ECHConfigs from `key` instead of the file.
    ///
    /// With `for_retry`, the loaded configs join the retry-configs a
    /// server hands to clients whose ECH attempt failed.
    #[corresponds(OSSL_ECHSTORE_set1_key_and_read_pem)]
    pub fn set1_key_and_read_pem(
        &mut self,
        key: &PKeyRef<Private>,
        pem: &[u8],
        for_retry: bool,
    ) -> Result<(), ErrorStack> {
        let bio = MemBioSlice::new(pem)?;
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_set1_key_and_read_pem(
                self.as_ptr(),
                key.as_ptr(),
                bio.as_ptr(),
                for_retry as c_int,
            ))?;
        }
        Ok(())
    }

    /// Loads a base64-encoded ECHConfigList - the value of the `ech`
    /// SvcParam in a DNS HTTPS record - as public-only entries.
    #[corresponds(OSSL_ECHSTORE_read_echconfiglist)]
    pub fn read_echconfiglist(&mut self, config_list: &[u8]) -> Result<(), ErrorStack> {
        let bio = MemBioSlice::new(config_list)?;
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_read_echconfiglist(
                self.as_ptr(),
                bio.as_ptr(),
            ))?;
        }
        Ok(())
    }

    /// Returns the public metadata of one entry.
    ///
    /// `index` selects the entry; `ffi::OSSL_ECHSTORE_LAST` selects the
    /// last entry.
    #[corresponds(OSSL_ECHSTORE_get1_info)]
    pub fn get1_info(&mut self, index: c_int) -> Result<EchEntryInfo, ErrorStack> {
        let mut loaded_secs: time_t = 0;
        let mut public_name: *mut c_char = ptr::null_mut();
        let mut echconfig: *mut c_char = ptr::null_mut();
        let mut has_private: c_int = 0;
        let mut for_retry: c_int = 0;
        let ret = unsafe {
            ffi::OSSL_ECHSTORE_get1_info(
                self.as_ptr(),
                index,
                &mut loaded_secs,
                &mut public_name,
                &mut echconfig,
                &mut has_private,
                &mut for_retry,
            )
        };
        // The two strings are OpenSSL-allocated on both success and
        // failure; take ownership of them either way.
        let public_name = unsafe { take_openssl_string(public_name) };
        let display = unsafe { take_openssl_string(echconfig) };
        cvt(ret)?;
        Ok(EchEntryInfo {
            display,
            for_retry: for_retry != 0,
            has_private: has_private != 0,
            loaded_secs: u64::try_from(loaded_secs).unwrap_or(0),
            public_name,
        })
    }

    /// Discards every entry except `index`, e.g. to retire old configs
    /// after a rotation.
    #[corresponds(OSSL_ECHSTORE_downselect)]
    pub fn downselect(&mut self, index: c_int) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_downselect(self.as_ptr(), index))?;
        }
        Ok(())
    }

    /// Returns the number of ECHConfig entries in the store.
    #[corresponds(OSSL_ECHSTORE_num_entries)]
    pub fn num_entries(&self) -> Result<usize, ErrorStack> {
        let mut count: c_int = 0;
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_num_entries(self.as_ptr(), &mut count))?;
        }
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Returns the number of private keys in the store. A server store
    /// must hold at least one key to accept ECH.
    #[corresponds(OSSL_ECHSTORE_num_keys)]
    pub fn num_keys(&mut self) -> Result<usize, ErrorStack> {
        let mut count: c_int = 0;
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_num_keys(self.as_ptr(), &mut count))?;
        }
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Drops private keys loaded more than `max_age` ago, the rotation
    /// companion to periodic loads.
    #[corresponds(OSSL_ECHSTORE_flush_keys)]
    pub fn flush_keys(&mut self, max_age: Duration) -> Result<(), ErrorStack> {
        let age = time_t::try_from(max_age.as_secs()).unwrap_or(time_t::MAX);
        unsafe {
            cvt(ffi::OSSL_ECHSTORE_flush_keys(self.as_ptr(), age))?;
        }
        Ok(())
    }
}

/// An HPKE suite (RFC 9180) for a generated ECHConfig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeSuite {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
}

impl HpkeSuite {
    /// RFC 9849's mandatory-to-implement suite: DHKEM(X25519,
    /// HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
    pub const DEFAULT: HpkeSuite = HpkeSuite {
        kem_id: ffi::OSSL_HPKE_KEM_ID_X25519,
        kdf_id: ffi::OSSL_HPKE_KDF_ID_HKDF_SHA256,
        aead_id: ffi::OSSL_HPKE_AEAD_ID_AES_GCM_128,
    };

    /// Creates a suite from raw HPKE identifiers; the `OSSL_HPKE_*_ID_*`
    /// constants in `openssl-sys` list the registered values.
    pub fn new(kem_id: u16, kdf_id: u16, aead_id: u16) -> Self {
        HpkeSuite {
            kem_id,
            kdf_id,
            aead_id,
        }
    }

    /// The key encapsulation method identifier.
    pub fn kem_id(&self) -> u16 {
        self.kem_id
    }

    /// The key derivation function identifier.
    pub fn kdf_id(&self) -> u16 {
        self.kdf_id
    }

    /// The AEAD identifier.
    pub fn aead_id(&self) -> u16 {
        self.aead_id
    }

    fn to_ffi(self) -> ffi::OSSL_HPKE_SUITE {
        ffi::OSSL_HPKE_SUITE {
            kem_id: self.kem_id,
            kdf_id: self.kdf_id,
            aead_id: self.aead_id,
        }
    }
}

/// The public metadata of one store entry, as reported by
/// [`EchStoreRef::get1_info`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchEntryInfo {
    display: Option<String>,
    for_retry: bool,
    has_private: bool,
    loaded_secs: u64,
    public_name: Option<String>,
}

impl EchEntryInfo {
    /// OpenSSL's string form of the entry's ECHConfig, for display and
    /// logging. Do not parse it.
    pub fn display(&self) -> Option<&str> {
        self.display.as_deref()
    }

    /// Whether the entry is included in retry-configs.
    pub fn for_retry(&self) -> bool {
        self.for_retry
    }

    /// Whether the store holds the entry's private key.
    pub fn has_private(&self) -> bool {
        self.has_private
    }

    /// Seconds since the entry was loaded into the store.
    pub fn loaded_secs(&self) -> u64 {
        self.loaded_secs
    }

    /// The entry's public (cover) name.
    pub fn public_name(&self) -> Option<&str> {
        self.public_name.as_deref()
    }
}

/// The outcome of an ECH attempt on one connection, as reported by
/// [`SslRef::ech_status`](crate::ssl::SslRef::ech_status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchStatus {
    /// ECH backend: this connection is the inner leg of a split-mode
    /// deployment.
    Backend,
    /// Bad arguments were passed to the status query.
    BadCall,
    /// ECH succeeded but the peer's certificate name was bad.
    BadName,
    /// Internal or protocol error.
    Failed,
    /// ECH was attempted and failed; the peer supplied retry-configs
    /// authenticated under a verified name.
    FailedEch,
    /// ECH was attempted and failed; retry-configs were supplied under
    /// an unverified name.
    FailedEchBadName,
    /// The peer sent a GREASE ECH extension. Server-side, attempts
    /// OpenSSL rejected are indistinguishable from GREASE: rejection
    /// folds connections into this state by design.
    Grease,
    /// The peer GREASEd and an ECH retry-config came back.
    GreaseEch,
    /// ECH is not configured on this connection.
    NotConfigured,
    /// ECH was not attempted on this connection.
    NotTried,
    /// ECH succeeded: the inner ClientHello was decrypted.
    Success,
    /// A status code this version of the crate does not know.
    Unknown(c_int),
}

impl EchStatus {
    pub(crate) fn from_raw(code: c_int) -> EchStatus {
        match code {
            ffi::SSL_ECH_STATUS_BACKEND => EchStatus::Backend,
            ffi::SSL_ECH_STATUS_BAD_CALL => EchStatus::BadCall,
            ffi::SSL_ECH_STATUS_BAD_NAME => EchStatus::BadName,
            ffi::SSL_ECH_STATUS_FAILED => EchStatus::Failed,
            ffi::SSL_ECH_STATUS_FAILED_ECH => EchStatus::FailedEch,
            ffi::SSL_ECH_STATUS_FAILED_ECH_BAD_NAME => EchStatus::FailedEchBadName,
            ffi::SSL_ECH_STATUS_GREASE => EchStatus::Grease,
            ffi::SSL_ECH_STATUS_GREASE_ECH => EchStatus::GreaseEch,
            ffi::SSL_ECH_STATUS_NOT_CONFIGURED => EchStatus::NotConfigured,
            ffi::SSL_ECH_STATUS_NOT_TRIED => EchStatus::NotTried,
            ffi::SSL_ECH_STATUS_SUCCESS => EchStatus::Success,
            other => EchStatus::Unknown(other),
        }
    }

    #[cfg(test)]
    pub(crate) fn to_raw(self) -> c_int {
        match self {
            EchStatus::Backend => ffi::SSL_ECH_STATUS_BACKEND,
            EchStatus::BadCall => ffi::SSL_ECH_STATUS_BAD_CALL,
            EchStatus::BadName => ffi::SSL_ECH_STATUS_BAD_NAME,
            EchStatus::Failed => ffi::SSL_ECH_STATUS_FAILED,
            EchStatus::FailedEch => ffi::SSL_ECH_STATUS_FAILED_ECH,
            EchStatus::FailedEchBadName => ffi::SSL_ECH_STATUS_FAILED_ECH_BAD_NAME,
            EchStatus::Grease => ffi::SSL_ECH_STATUS_GREASE,
            EchStatus::GreaseEch => ffi::SSL_ECH_STATUS_GREASE_ECH,
            EchStatus::NotConfigured => ffi::SSL_ECH_STATUS_NOT_CONFIGURED,
            EchStatus::NotTried => ffi::SSL_ECH_STATUS_NOT_TRIED,
            EchStatus::Success => ffi::SSL_ECH_STATUS_SUCCESS,
            EchStatus::Unknown(code) => code,
        }
    }
}

/// One connection's ECH outcome: the status plus the inner (decrypted,
/// real) and outer (cover) server names, when the handshake determined
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConnectionStatus {
    status: EchStatus,
    inner_sni: Option<String>,
    outer_sni: Option<String>,
}

impl EchConnectionStatus {
    pub(crate) fn new(
        status: EchStatus,
        inner_sni: Option<String>,
        outer_sni: Option<String>,
    ) -> Self {
        EchConnectionStatus {
            status,
            inner_sni,
            outer_sni,
        }
    }

    /// The outcome of the ECH attempt.
    pub fn status(&self) -> EchStatus {
        self.status
    }

    /// The inner server name the client really wanted, if decrypted.
    pub fn inner_sni(&self) -> Option<&str> {
        self.inner_sni.as_deref()
    }

    /// The outer (cover) server name, if one was used.
    pub fn outer_sni(&self) -> Option<&str> {
        self.outer_sni.as_deref()
    }
}

/// Takes ownership of a string OpenSSL allocated (via `OPENSSL_strdup`)
/// and converts it to a Rust `String`, freeing the original. `NULL` maps
/// to `None`.
///
/// # Safety
///
/// `ptr` must be NULL or a NUL-terminated string allocated by OpenSSL
/// that the caller owns and has not freed.
pub(crate) unsafe fn take_openssl_string(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let text = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ffi::OPENSSL_free(ptr as *mut c_void);
    Some(text)
}

#[cfg(test)]
mod test;
