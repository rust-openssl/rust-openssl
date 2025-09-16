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

        // https://github.com/sfackler/rust-openssl/issues/889
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
        .header("openssl/x509_vfy.h");

    if let Some(version) = libressl_version {
        cfg.header("openssl/poly1305.h");
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

    #[allow(clippy::if_same_then_else)]
    cfg.type_name(|s, is_struct, _is_union| {
        // Add some `*` on some callback parameters to get function pointer to
        // typecheck in C, especially on MSVC.
        if s == "PasswordCallback" {
            "pem_password_cb*".to_string()
        } else if s == "bio_info_cb" {
            "bio_info_cb*".to_string()
        } else if s == "_STACK" {
            "struct stack_st".to_string()
        // This logic should really be cleaned up
        } else if is_struct
            && s != "point_conversion_form_t"
            && s.chars().next().unwrap().is_lowercase()
        {
            format!("struct {}", s)
        } else if s.starts_with("stack_st_") || s == "timeval" {
            format!("struct {}", s)
        } else {
            s.to_string()
        }
    });
    cfg.skip_type(|s| {
        // function pointers are declared without a `*` in openssl so their
        // sizeof is 1 which isn't what we want.
        s == "PasswordCallback"
            || s == "pem_password_cb"
            || s == "bio_info_cb"
            || s == "OSSL_PASSPHRASE_CALLBACK"
            || s.starts_with("CRYPTO_EX_")
    });
    cfg.skip_struct(|s| {
        s == "ProbeResult" ||
            s == "X509_OBJECT_data" || // inline union
            s == "DIST_POINT_NAME_st_anon_union" || // inline union
            s == "PKCS7_data" ||
            s == "ASN1_TYPE_value"
    });
    cfg.skip_fn(move |s| {
        s == "CRYPTO_memcmp" ||                 // uses volatile

        // Skip some functions with function pointers on windows, not entirely
        // sure how to get them to work out...
        (target.contains("windows") && {
            s.starts_with("PEM_read_bio_") ||
            (s.starts_with("PEM_write_bio_") && s.ends_with("PrivateKey")) ||
            s == "d2i_PKCS8PrivateKey_bio" ||
            s == "i2d_PKCS8PrivateKey_bio" ||
            s == "SSL_get_ex_new_index" ||
            s == "SSL_CTX_get_ex_new_index" ||
            s == "CRYPTO_get_ex_new_index"
        })
    });
    cfg.skip_field_type(|s, field| {
        (s == "EVP_PKEY" && field == "pkey") ||      // union
            (s == "GENERAL_NAME" && field == "d") || // union
            (s == "DIST_POINT_NAME" && field == "name") || // union
            (s == "X509_OBJECT" && field == "data") || // union
            (s == "PKCS7" && field == "d") || // union
            (s == "ASN1_TYPE" && field == "value") // union
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
    cfg.field_name(|_s, field| {
        if field == "type_" {
            "type".to_string()
        } else {
            field.to_string()
        }
    });
    cfg.fn_cname(|rust, link_name| link_name.unwrap_or(rust).to_string());
    cfg.generate("../openssl-sys/src/lib.rs", "all.rs");
}
