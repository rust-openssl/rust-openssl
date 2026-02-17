#[cfg(not(awslc))]
use cfg_if::cfg_if;
use openssl::error::Error;

openssl_errors::openssl_errors! {
    library Test("test library") {
        functions {
            FOO("function foo");
            BAR("function bar");
        }

        reasons {
            NO_MILK("out of milk");
            NO_BACON("out of bacon");
        }
    }
}

// AWS-LC does not support ERR_load_strings, so custom error string registration
// is a no-op. The tests below verify string content and are skipped on AWS-LC.
// The `awslc_put_error_smoke` test at the bottom covers the basic put_error!
// functionality on AWS-LC.

#[test]
#[cfg(not(awslc))]
fn basic() {
    openssl_errors::put_error!(Test::FOO, Test::NO_MILK);

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function foo");
    assert_eq!(error.reason().unwrap(), "out of milk");
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace('\\', "/"),
        "openssl-errors/tests/test.rs"
    );
    assert_eq!(error.line(), line!() - 11);
    cfg_if! {
        if #[cfg(ossl300)] {
            // https://github.com/openssl/openssl/issues/12530
            assert!(error.data().is_none() || error.data() == Some(""));
        } else {
            assert_eq!(error.data(), None);
        }
    }
}

#[test]
#[cfg(not(awslc))]
fn static_data() {
    openssl_errors::put_error!(Test::BAR, Test::NO_BACON, "foobar {{}}");

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function bar");
    assert_eq!(error.reason().unwrap(), "out of bacon");
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace('\\', "/"),
        "openssl-errors/tests/test.rs"
    );
    assert_eq!(error.line(), line!() - 11);
    assert_eq!(error.data(), Some("foobar {}"));
}

#[test]
#[cfg(not(awslc))]
fn dynamic_data() {
    openssl_errors::put_error!(Test::BAR, Test::NO_MILK, "hello {}", "world");

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function bar");
    assert_eq!(error.reason().unwrap(), "out of milk");
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace('\\', "/"),
        "openssl-errors/tests/test.rs"
    );
    assert_eq!(error.line(), line!() - 11);
    assert_eq!(error.data(), Some("hello world"));
}

#[test]
#[cfg(not(awslc))]
fn deferred_error_render() {
    openssl_errors::put_error!(Test::BAR, Test::NO_MILK);

    let error = Error::get().unwrap();

    for _ in 0..100 {
        openssl_errors::put_error!(Test::FOO, Test::NO_BACON);
    }

    assert_eq!(error.function().unwrap(), "function bar");
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace('\\', "/"),
        "openssl-errors/tests/test.rs"
    );

    // clear out the stack for other tests on the same thread
    while Error::get().is_some() {}
}

/// Smoke test for AWS-LC: custom error strings are not available, but
/// put_error! should still push an error onto the stack with the correct
/// file, line, and optional data fields.
#[test]
#[cfg(awslc)]
fn awslc_put_error_smoke() {
    // Basic put_error without data
    openssl_errors::put_error!(Test::FOO, Test::NO_MILK);

    let error = Error::get().unwrap();
    assert_eq!(
        error.file().replace('\\', "/"),
        "openssl-errors/tests/test.rs"
    );
    assert!(error.line() > 0);

    // put_error with dynamic data
    openssl_errors::put_error!(Test::BAR, Test::NO_BACON, "hello {}", "world");

    let error = Error::get().unwrap();
    assert_eq!(
        error.file().replace('\\', "/"),
        "openssl-errors/tests/test.rs"
    );
    assert!(error.line() > 0);
    assert_eq!(error.data(), Some("hello world"));

    // clear out the stack for other tests on the same thread
    while Error::get().is_some() {}
}
