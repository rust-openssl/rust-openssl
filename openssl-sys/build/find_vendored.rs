// `vendored-4` builds OpenSSL 4 from openssl-src 400.x; `vendored` builds the
// 3.x line. Both crates expose the same Build and Artifacts API.
#[cfg(not(feature = "vendored-4"))]
use openssl_src;
#[cfg(feature = "vendored-4")]
use openssl_src_400 as openssl_src;
use std::path::PathBuf;

use super::env;

pub fn get_openssl(_target: &str) -> (Vec<PathBuf>, PathBuf) {
    let openssl_config_dir = env("OPENSSL_CONFIG_DIR");

    let mut openssl_src_build = openssl_src::Build::new();
    if let Some(value) = openssl_config_dir {
        openssl_src_build.openssl_dir(PathBuf::from(value));
    }

    let artifacts = openssl_src_build.build();
    println!("cargo:vendored=1");
    println!(
        "cargo:root={}",
        artifacts.lib_dir().parent().unwrap().display()
    );

    (
        vec![artifacts.lib_dir().to_path_buf()],
        artifacts.include_dir().to_path_buf(),
    )
}
