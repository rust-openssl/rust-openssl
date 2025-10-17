#![allow(clippy::uninlined_format_args)]

use std::env;

#[allow(clippy::inconsistent_digit_grouping, clippy::unusual_byte_groupings)]
#[path = "../openssl-sys/build/cfgs.rs"]
mod cfgs;

fn main() {
    let mut cfg = ctest::TestGenerator::new();
    let target = env::var("TARGET").unwrap();

    if let Ok(out) = env::var("DEP_OPENSSL_INCLUDE") {
        cfg.include(&out);
    }

    // Needed to get OpenSSL to correctly undef symbols that are already on
    // Windows like X509_NAME
    if target.contains("windows") {
        cfg.header("windows.h");

        // weird "different 'const' qualifiers" error on Windows, maybe a cl.exe
        // thing?
        if target.contains("msvc") {
            cfg.flag("/wd4090");
        }

        // https://github.com/rust-openssl/rust-openssl/issues/889
        cfg.define("WIN32_LEAN_AND_MEAN", None);
    }

    let openssl_version = env::var("DEP_OPENSSL_VERSION_NUMBER")
        .ok()
        .map(|v| u64::from_str_radix(&v, 16).unwrap());
    let libressl_version = env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER")
        .ok()
        .map(|v| u64::from_str_radix(&v, 16).unwrap());

    cfg.cfg("openssl", None);

    for c in cfgs::get(openssl_version, libressl_version) {
        cfg.cfg(c, None);
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(',') {
            cfg.cfg("osslconf", Some(var));
        }
    }

    cfg.header("openssl/comp.h")
        .header("openssl/dh.h")
        .header("openssl/ossl_typ.h")
        .header("openssl/stack.h")
        .header("openssl/x509.h")
        .header("openssl/bio.h")
        .header("openssl/x509v3.h")
        .header("openssl/safestack.h")
        .header("openssl/cmac.h")
        .header("openssl/hmac.h")
        .header("openssl/obj_mac.h")
        .header("openssl/ssl.h")
        .header("openssl/err.h")
        .header("openssl/rand.h")
        .header("openssl/pkcs12.h")
        .header("openssl/bn.h")
        .header("openssl/aes.h")
        .header("openssl/ocsp.h")
        .header("openssl/evp.h")
        .header("openssl/dsa.h")
        .header("openssl/rsa.h")
        .header("openssl/x509_vfy.h");

    if let Some(version) = libressl_version {
        cfg.header("openssl/cms.h").header("openssl/poly1305.h");
        if version >= 0x30600000 {
            cfg.header("openssl/kdf.h");
        }
    }

    if let Some(version) = openssl_version {
        cfg.header("openssl/cms.h");
        if version >= 0x10100000 {
            cfg.header("openssl/kdf.h");
        }

        if version >= 0x30000000 {
            cfg.header("openssl/decoder.h")
                .header("openssl/encoder.h")
                .header("openssl/provider.h")
                .header("openssl/params.h")
                .header("openssl/param_build.h")
                .header("openssl/ssl.h");
        }
        if version >= 0x30200000 {
            cfg.header("openssl/thread.h");
        }
    }

    cfg.skip_alias(|a| {
        // function pointers are declared without a `*` in openssl so their
        // sizeof is 1 which isn't what we want.
        let name = a.ident();
        name == "PasswordCallback"
            || name == "pem_password_cb"
            || name == "bio_info_cb"
            || name == "OSSL_PASSPHRASE_CALLBACK" 
            || name.starts_with("CRYPTO_EX_")
    });

    cfg.skip_const(|c| {
        let name = c.ident();
        name == "X509_L_ADD_DIR"
    });

    cfg.skip_struct(|s| {
        let name = s.ident();
        name == "ProbeResult" ||
            name == "X509_OBJECT_data" || // inline union
            name == "DIST_POINT_NAME_st_anon_union" || // inline union
            name == "PKCS7_data" ||
            name == "ASN1_TYPE_value"
    });

    cfg.skip_fn(move |f| {
        let name = f.ident();
        name == "CRYPTO_memcmp" ||                 // uses volatile

        // Skip some functions with function pointers on windows, not entirely
        // sure how to get them to work out...
        (target.contains("windows") && {
            name.starts_with("PEM_read_bio_") ||
            (name.starts_with("PEM_write_bio_") && name.ends_with("PrivateKey")) ||
            name == "d2i_PKCS8PrivateKey_bio" ||
            name == "i2d_PKCS8PrivateKey_bio" ||
            name == "SSL_get_ex_new_index" ||
            name == "SSL_CTX_get_ex_new_index" ||
            name == "CRYPTO_get_ex_new_index"
        })
    });

    cfg.skip_struct_field(|s, field| {
        let struct_name = s.ident();
        let field_name = field.ident();
        (struct_name == "EVP_PKEY" && field_name == "pkey") ||      // union
            (struct_name == "GENERAL_NAME" && field_name == "d") || // union
            (struct_name == "DIST_POINT_NAME" && field_name == "name") || // union
            (struct_name == "X509_OBJECT" && field_name == "data") || // union
            (struct_name == "PKCS7" && field_name == "d") || // union
            (struct_name == "ASN1_TYPE" && field_name == "value") // union
    });

    cfg.skip_signededness(|s| {
        s.ends_with("_cb")
            || s.ends_with("_CB")
            || s.ends_with("_cb_fn")
            || s.starts_with("CRYPTO_")
            || s == "PasswordCallback"
            || s.ends_with("_cb_func")
            || s.ends_with("_cb_ex")
    });

    cfg.generate_files("../openssl-sys/src/lib.rs", "all.rs")
        .expect("Failed to generate test files");
}
