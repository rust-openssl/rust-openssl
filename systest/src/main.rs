#![allow(bad_style, deprecated, clippy::all, function_casts_as_integer)]

use libc::*;
use openssl_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
