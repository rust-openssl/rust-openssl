use libc::*;

pub const CMS_TEXT: c_uint = 0x1;
pub const CMS_NOCERTS: c_uint = 0x2;
pub const CMS_NO_CONTENT_VERIFY: c_uint = 0x4;
pub const CMS_NO_ATTR_VERIFY: c_uint = 0x8;
pub const CMS_NOSIGS: c_uint = 0x4 | 0x8;
pub const CMS_NOINTERN: c_uint = 0x10;
pub const CMS_NO_SIGNER_CERT_VERIFY: c_uint = 0x20;
pub const CMS_NOVERIFY: c_uint = 0x20;
pub const CMS_DETACHED: c_uint = 0x40;
pub const CMS_BINARY: c_uint = 0x80;
pub const CMS_NOATTR: c_uint = 0x100;
pub const CMS_NOSMIMECAP: c_uint = 0x200;
pub const CMS_NOOLDMIMETYPE: c_uint = 0x400;
pub const CMS_CRLFEOL: c_uint = 0x800;
pub const CMS_STREAM: c_uint = 0x1000;
pub const CMS_NOCRL: c_uint = 0x2000;
pub const CMS_PARTIAL: c_uint = 0x4000;
pub const CMS_REUSE_DIGEST: c_uint = 0x8000;
pub const CMS_USE_KEYID: c_uint = 0x10000;
pub const CMS_DEBUG_DECRYPT: c_uint = 0x20000;
pub const CMS_KEY_PARAM: c_uint = 0x40000;
#[cfg(any(ossl110, libressl))]
pub const CMS_ASCIICRLF: c_uint = 0x80000;
#[cfg(ossl300)]
pub const CMS_CADES: c_uint = 0x100000;
