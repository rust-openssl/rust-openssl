use super::super::*;
use libc::*;

pub enum CMS_ContentInfo {}
pub enum CMS_SignerInfo {}

extern "C" {
    pub fn CMS_ContentInfo_free(cms: *mut CMS_ContentInfo);
}

const_ptr_api! {
    extern "C" {
        pub fn i2d_CMS_ContentInfo(a: #[const_ptr_if(ossl300)] CMS_ContentInfo, pp: *mut *mut c_uchar) -> c_int;
    }
}

extern "C" {
    pub fn d2i_CMS_ContentInfo(
        a: *mut *mut CMS_ContentInfo,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut CMS_ContentInfo;

    pub fn SMIME_read_CMS(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut CMS_ContentInfo;

    pub fn CMS_sign(
        signcert: *mut X509,
        pkey: *mut EVP_PKEY,
        certs: *mut stack_st_X509,
        data: *mut BIO,
        flags: c_uint,
    ) -> *mut CMS_ContentInfo;

    pub fn CMS_add1_signer(
        cms: *mut CMS_ContentInfo,
        signer: *mut X509,
        pk: *mut EVP_PKEY,
        md: *const EVP_MD,
        flags: c_uint,
    ) -> *mut CMS_SignerInfo;

    pub fn CMS_add1_cert(cms: *mut CMS_ContentInfo, cert: *mut X509) -> c_int;

    pub fn CMS_verify(
        cms: *mut CMS_ContentInfo,
        certs: *mut stack_st_X509,
        store: *mut X509_STORE,
        detached_data: *mut BIO,
        out: *mut BIO,
        flags: c_uint,
    ) -> c_int;

    pub fn CMS_encrypt(
        certs: *mut stack_st_X509,
        data: *mut BIO,
        cipher: *const EVP_CIPHER,
        flags: c_uint,
    ) -> *mut CMS_ContentInfo;

    pub fn CMS_decrypt(
        cms: *mut CMS_ContentInfo,
        pkey: *mut EVP_PKEY,
        cert: *mut X509,
        dcont: *mut BIO,
        out: *mut BIO,
        flags: c_uint,
    ) -> c_int;

    pub fn CMS_get0_signers(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509;

    pub fn CMS_get1_certs(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509;

    pub fn CMS_final(
        cms: *mut CMS_ContentInfo,
        data: *mut BIO,
        dcont: *mut BIO,
        flags: c_uint,
    ) -> c_int;
}
