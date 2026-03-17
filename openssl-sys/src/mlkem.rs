//! ML-KEM bindings for BoringSSL
//!
//! This module re-exports ML-KEM types and functions from the bindgen-generated
//! BoringSSL bindings.

use super::*;

// Re-export ML-KEM types from bindgen
pub use super::{
    MLKEM1024_private_key, MLKEM1024_public_key, MLKEM768_private_key, MLKEM768_public_key,
};

// Re-export ML-KEM union types with user-friendly names
pub use super::MLKEM1024_private_key__bindgen_ty_1 as MLKEM1024_private_key_union;
pub use super::MLKEM1024_public_key__bindgen_ty_1 as MLKEM1024_public_key_union;
pub use super::MLKEM768_private_key__bindgen_ty_1 as MLKEM768_private_key_union;
pub use super::MLKEM768_public_key__bindgen_ty_1 as MLKEM768_public_key_union;

// Re-export ML-KEM functions from bindgen
pub use super::{
    MLKEM1024_decap, MLKEM1024_encap, MLKEM1024_generate_key, MLKEM1024_marshal_public_key,
    MLKEM1024_private_key_from_seed, MLKEM1024_public_from_private,
};
pub use super::{
    MLKEM768_decap, MLKEM768_encap, MLKEM768_generate_key, MLKEM768_marshal_public_key,
    MLKEM768_private_key_from_seed, MLKEM768_public_from_private,
};

// Re-export CBB/CBS types and functions from bindgen
pub use super::cbb_st as CBB;
pub use super::CBS;
pub use super::{CBB_cleanup, CBB_data, CBB_init, CBB_len, CBB_zero};

// Constants (bindgen generates these as i32; we want usize)
pub const MLKEM_SEED_BYTES: usize = 64;
pub const MLKEM_SHARED_SECRET_BYTES: usize = 32;

pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;

pub const MLKEM1024_PUBLIC_KEY_BYTES: usize = 1568;
pub const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;
