#![allow(bad_style, deprecated, clippy::all)]

use libc::*;
use openssl_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
