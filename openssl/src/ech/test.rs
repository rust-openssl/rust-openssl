use crate::base64;
use crate::ech::{EchStatus, EchStore, HpkeSuite};
use crate::ssl::{Ssl, SslContextBuilder, SslMethod};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const PUBLIC_NAME: &str = "cover.example.test";

fn generated_store() -> EchStore {
    let mut store = EchStore::new().unwrap();
    store
        .new_config(
            ffi::OSSL_ECH_RFC9849_VERSION,
            0,
            PUBLIC_NAME,
            HpkeSuite::DEFAULT,
        )
        .unwrap();
    store
}

/// Extracts the base64 body of the first ECHCONFIG block of an entry
/// PEM. For a generated entry the block is a singleton ECHConfigList.
fn echconfig_base64(pem: &[u8]) -> String {
    let text = String::from_utf8(pem.to_vec()).unwrap();
    let begin = "-----BEGIN ECHCONFIG-----";
    let end = "-----END ECHCONFIG-----";
    let start = text.find(begin).unwrap() + begin.len();
    let stop = text[start..].find(end).unwrap() + start;
    text[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[test]
fn generate_produces_singleton_with_private_key() {
    let mut store = generated_store();
    assert_eq!(store.num_entries().unwrap(), 1);
    assert_eq!(store.num_keys().unwrap(), 1);
    let info = store.get1_info(0).unwrap();
    assert_eq!(info.public_name(), Some(PUBLIC_NAME));
    assert!(info.has_private(), "generated entry must hold its key");
    let display = info.display().unwrap();
    assert!(
        display.starts_with("[fe0d,"),
        "display string must be the RFC 9849 string form, got {display}"
    );
}

/// Decodes the first ECHCONFIG block of an entry PEM to the bare
/// ECHConfig bytes. OpenSSL 4.0 serializes a generated entry's block as
/// a singleton ECHConfigList (length prefix + config) but a PEM-loaded
/// entry's block as the bare config, so the two shapes are normalized
/// before comparison.
fn bare_config(pem: &[u8]) -> Vec<u8> {
    let bytes = base64::decode_block(&echconfig_base64(pem)).unwrap();
    if bytes.starts_with(&[0xfe, 0x0d]) {
        bytes
    } else {
        let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(declared, bytes.len() - 2);
        bytes[2..].to_vec()
    }
}

#[test]
fn pem_round_trip_preserves_entry() {
    let mut original = generated_store();
    let pem = original.write_pem(0).unwrap();
    let text = String::from_utf8(pem.clone()).unwrap();
    assert!(text.contains("-----BEGIN PRIVATE KEY-----"), "{text}");
    assert!(text.contains("-----BEGIN ECHCONFIG-----"), "{text}");

    let mut loaded = EchStore::new().unwrap();
    loaded.read_pem(&pem, true).unwrap();
    assert_eq!(loaded.num_entries().unwrap(), 1);
    assert_eq!(loaded.num_keys().unwrap(), 1);
    // The PEM bytes are not stable across a load (see bare_config),
    // but the ECHConfig itself must be.
    assert_eq!(
        bare_config(&loaded.write_pem(0).unwrap()),
        bare_config(&pem)
    );
    let info = loaded.get1_info(0).unwrap();
    assert!(info.has_private());
    assert!(info.for_retry(), "loaded with for_retry=true");
}

#[test]
fn config_list_loads_as_public_only() {
    let mut original = generated_store();
    let pem = original.write_pem(0).unwrap();
    let mut public = EchStore::new().unwrap();
    public
        .read_echconfiglist(echconfig_base64(&pem).as_bytes())
        .unwrap();
    assert_eq!(public.num_entries().unwrap(), 1);
    assert_eq!(public.num_keys().unwrap(), 0, "public list carries no keys");
    let info = public.get1_info(0).unwrap();
    assert!(!info.has_private());
    assert_eq!(info.public_name(), Some(PUBLIC_NAME));
}

#[test]
fn config_list_has_length_prefix_and_version() {
    let mut store = generated_store();
    let pem = store.write_pem(0).unwrap();
    let binary = base64::decode_block(&echconfig_base64(&pem)).unwrap();
    assert!(binary.len() > 2, "ECHConfigList has a 2-byte prefix + body");
    let declared = u16::from_be_bytes([binary[0], binary[1]]) as usize;
    assert_eq!(
        declared,
        binary.len() - 2,
        "the u16 prefix must count the ECHConfig bytes that follow"
    );
    // RFC 9849 version is the first field of the ECHConfig.
    assert_eq!(&binary[2..4], &[0xfe, 0x0d]);
}

#[test]
fn write_pem_all_never_contains_private_key() {
    let mut store = generated_store();
    let pem = String::from_utf8(store.write_pem(ffi::OSSL_ECHSTORE_ALL).unwrap()).unwrap();
    assert!(pem.contains("-----BEGIN ECHCONFIG-----"), "{pem}");
    assert!(
        !pem.contains("PRIVATE KEY"),
        "public PEM leaked a key:\n{pem}"
    );
}

#[test]
fn load_pem_rejects_garbage() {
    let mut store = EchStore::new().unwrap();
    assert!(store
        .read_pem(b"this is not a PEM file at all\x00\x01\x02", true)
        .is_err());
    assert_eq!(
        store.num_entries().unwrap(),
        0,
        "failed load must not add entries"
    );
}

#[test]
fn load_pem_rejects_truncated_pem() {
    let mut original = generated_store();
    let pem = original.write_pem(0).unwrap();
    let truncated = &pem[..pem.len() / 2];
    let mut store = EchStore::new().unwrap();
    assert!(
        store.read_pem(truncated, true).is_err(),
        "a half-written key file must fail closed"
    );
}

#[test]
fn read_echconfiglist_rejects_garbage() {
    let mut store = EchStore::new().unwrap();
    assert!(store.read_echconfiglist(b"!!!not-base64!!!").is_err());
    assert!(
        store.read_echconfiglist(b"AAAA").is_err(),
        "decodes but is not an ECHConfigList"
    );
    assert_eq!(store.num_entries().unwrap(), 0);
}

#[test]
fn new_config_rejects_bad_public_names() {
    let mut store = EchStore::new().unwrap();
    for bad in ["", "has space.example", ".leading-dot.example"] {
        assert!(
            store
                .new_config(ffi::OSSL_ECH_RFC9849_VERSION, 0, bad, HpkeSuite::DEFAULT)
                .is_err(),
            "public_name {bad:?} must be rejected"
        );
    }
    let too_long = format!("{}.example", "a".repeat(250));
    assert!(too_long.len() > 255);
    assert!(store
        .new_config(
            ffi::OSSL_ECH_RFC9849_VERSION,
            0,
            &too_long,
            HpkeSuite::DEFAULT
        )
        .is_err());
    assert_eq!(
        store.num_entries().unwrap(),
        0,
        "rejected generates must not append"
    );
}

#[test]
fn entry_info_out_of_range() {
    let mut store = generated_store();
    assert!(store.get1_info(7).is_err());
    assert!(store.write_pem(7).is_err());
}

#[test]
fn status_codes_round_trip() {
    for status in [
        EchStatus::Backend,
        EchStatus::BadCall,
        EchStatus::BadName,
        EchStatus::Failed,
        EchStatus::FailedEch,
        EchStatus::FailedEchBadName,
        EchStatus::Grease,
        EchStatus::GreaseEch,
        EchStatus::NotConfigured,
        EchStatus::NotTried,
        EchStatus::Success,
    ] {
        assert_eq!(EchStatus::from_raw(status.to_raw()), status);
    }
    assert_eq!(EchStatus::from_raw(12345), EchStatus::Unknown(12345));
}

#[test]
fn plain_ctx_reports_not_configured() {
    let ctx = SslContextBuilder::new(SslMethod::tls_server())
        .unwrap()
        .build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    let status = ssl.ech_status();
    assert_eq!(status.status(), EchStatus::NotConfigured);
    assert_eq!(status.inner_sni(), None);
    assert_eq!(status.outer_sni(), None);
}

#[test]
fn attached_ctx_reports_not_tried_before_handshake() {
    let store = generated_store();
    let mut builder = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
    builder.set_echstore(&store).unwrap();
    let ctx = builder.build();

    // The context holds its own copy of the store.
    let attached = ctx.echstore().unwrap();
    assert_eq!(attached.num_entries().unwrap(), 1);

    let mut ssl = Ssl::new(&ctx).unwrap();
    assert_eq!(ssl.ech_status().status(), EchStatus::NotTried);
}

#[test]
fn ech_callback_install() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let mut builder = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
    builder.set_ech_callback(move |_, _| {
        calls2.fetch_add(1, Ordering::SeqCst);
        true
    });
    let ctx = builder.build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    // No handshake has run, so the callback cannot have fired; this
    // asserts installation coexists with ordinary context use.
    assert_eq!(ssl.ech_status().status(), EchStatus::NotConfigured);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn retry_config_on_fresh_connection_is_empty_or_error() {
    let ctx = SslContextBuilder::new(SslMethod::tls_server())
        .unwrap()
        .build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    // No ECH was attempted, so there can be no retry-config payload:
    // the call must yield an empty list (or a structured error), never
    // fabricated bytes.
    match ssl.ech_retry_config() {
        Ok(bytes) => assert!(bytes.is_empty(), "no attempt, no retry-config"),
        Err(err) => assert!(!err.to_string().is_empty()),
    }
}
