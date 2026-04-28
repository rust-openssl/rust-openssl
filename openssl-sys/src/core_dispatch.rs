use super::*;
use libc::size_t;
use std::ffi::c_int;

/* OpenSSL 3.* only */

pub const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
pub const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
pub const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
pub const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
pub const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

/// Sentinel value the `OSSL_PARAM_construct_*` typed constructors initialise
/// `OSSL_PARAM::return_size` to. After a get-params call, a `return_size`
/// still equal to this value indicates the parameter was not modified by
/// the keymgmt (typically because it did not recognise the parameter name).
pub const OSSL_PARAM_UNMODIFIED: size_t = size_t::MAX;
