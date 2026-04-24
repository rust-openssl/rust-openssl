#[cfg(ossl320)]
use crate::OSSL_HPKE_SUITE;
use libc::c_int;

#[cfg(ossl320)]
pub const OSSL_HPKE_MODE_BASE: c_int = 0x00;
#[cfg(ossl320)]
pub const OSSL_HPKE_MODE_PSK: c_int = 0x01;
#[cfg(ossl320)]
pub const OSSL_HPKE_MODE_AUTH: c_int = 0x02;
#[cfg(ossl320)]
pub const OSSL_HPKE_MODE_PSKAUTH: c_int = 0x03;

#[cfg(ossl320)]
pub const OSSL_HPKE_ROLE_SENDER: c_int = 0x00;
#[cfg(ossl320)]
pub const OSSL_HPKE_ROLE_RECEIVER: c_int = 0x01;

#[cfg(ossl320)]
pub const OSSL_HPKE_KEM_ID_P256: u16 = 0x10;
#[cfg(ossl320)]
pub const OSSL_HPKE_KEM_ID_P384: u16 = 0x11;
#[cfg(ossl320)]
pub const OSSL_HPKE_KEM_ID_P521: u16 = 0x12;
#[cfg(ossl320)]
pub const OSSL_HPKE_KEM_ID_X25519: u16 = 0x20;
#[cfg(ossl320)]
pub const OSSL_HPKE_KEM_ID_X448: u16 = 0x21;

#[cfg(ossl320)]
pub const OSSL_HPKE_KDF_ID_HKDF_SHA256: u16 = 0x01;
#[cfg(ossl320)]
pub const OSSL_HPKE_KDF_ID_HKDF_SHA384: u16 = 0x02;
#[cfg(ossl320)]
pub const OSSL_HPKE_KDF_ID_HKDF_SHA512: u16 = 0x03;

#[cfg(ossl320)]
pub const OSSL_HPKE_AEAD_ID_AES_GCM_128: u16 = 0x01;
#[cfg(ossl320)]
pub const OSSL_HPKE_AEAD_ID_AES_GCM_256: u16 = 0x02;
#[cfg(ossl320)]
pub const OSSL_HPKE_AEAD_ID_CHACHA_POLY1305: u16 = 0x03;
#[cfg(ossl320)]
pub const OSSL_HPKE_AEAD_ID_EXPORTONLY: u16 = 0xFFFF;

#[cfg(all(ossl320, not(osslconf = "OPENSSL_NO_ECX")))]
pub const OSSL_HPKE_SUITE_DEFAULT: OSSL_HPKE_SUITE = OSSL_HPKE_SUITE {
    kem_id: OSSL_HPKE_KEM_ID_X25519,
    kdf_id: OSSL_HPKE_KDF_ID_HKDF_SHA256,
    aead_id: OSSL_HPKE_AEAD_ID_AES_GCM_128,
};

#[cfg(all(ossl320, osslconf = "OPENSSL_NO_ECX"))]
pub const OSSL_HPKE_SUITE_DEFAULT: OSSL_HPKE_SUITE = OSSL_HPKE_SUITE {
    kem_id: OSSL_HPKE_KEM_ID_P256,
    kdf_id: OSSL_HPKE_KDF_ID_HKDF_SHA256,
    aead_id: OSSL_HPKE_AEAD_ID_AES_GCM_128,
};
