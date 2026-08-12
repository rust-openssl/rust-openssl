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
            cfg.header("openssl/hpke.h");
        }
    }

    cfg.rename_type(|s| {
        // Add some `*` on some callback parameters to get function pointer to
        // typecheck in C, especially on MSVC.
        if s == "PasswordCallback" {
            Some("pem_password_cb*".to_string())
        } else if s == "bio_info_cb" {
            Some("bio_info_cb*".to_string())
        } else if s.starts_with("stack_st_") || s == "timeval" {
            Some(format!("struct {}", s))
        } else {
            None
        }
    });
    #[allow(clippy::if_same_then_else)]
    cfg.rename_struct_ty(|s| {
        if s == "_STACK" {
            Some("struct stack_st".to_string())
        // This logic should really be cleaned up
        } else if s != "point_conversion_form_t" && s.chars().next().unwrap().is_lowercase() {
            Some(format!("struct {}", s))
        } else if s.starts_with("stack_st_") || s == "timeval" {
            Some(format!("struct {}", s))
        } else {
            // Use typedef name without 'struct' prefix, matching
            // how OpenSSL exposes these types in C headers.
            Some(s.to_string())
        }
    });
    cfg.skip_const(|c| {
        // Defined inside a function body, not a public API constant.
        c.ident() == "X509_L_ADD_DIR"
    });
    cfg.skip_alias(|ty| {
        // function pointers are declared without a `*` in openssl so their
        // sizeof is 1 which isn't what we want.
        let s = ty.ident();
        s == "PasswordCallback"
            || s == "pem_password_cb"
            || s == "bio_info_cb"
            || s == "OSSL_PASSPHRASE_CALLBACK"
            || s.starts_with("CRYPTO_EX_")
    });
    cfg.skip_union(|u| {
        let s = u.ident();
        s == "X509_OBJECT_data"
            || s == "DIST_POINT_NAME_st_anon_union"
            || s == "PKCS7_data"
            || s == "ASN1_TYPE_value"
    });
    cfg.skip_struct(|st| {
        let s = st.ident();
        s == "ProbeResult"
    });
    cfg.skip_fn(move |f| {
        let s = f.ident();
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
    cfg.skip_struct_field_type(|st, field| {
        let s = st.ident();
        let f = field.ident();
        (s == "EVP_PKEY" && f == "pkey") ||      // union
            (s == "GENERAL_NAME" && f == "d") || // union
            (s == "DIST_POINT_NAME" && f == "name") || // union
            (s == "X509_OBJECT" && f == "data") || // union
            (s == "PKCS7" && f == "d") || // union
            (s == "ASN1_TYPE" && f == "value") // union
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
    cfg.rename_struct_field(|_st, field| {
        if field.ident() == "type_" {
            Some("type".to_string())
        } else {
            None
        }
    });
    cfg.rename_fn(|f| f.link_name().map(|s| s.to_string()));
    ctest::generate_test(&mut cfg, "../openssl-sys/src/lib.rs", "all.rs")
        .expect("generate_test failed");
}
