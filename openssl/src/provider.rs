use crate::error::ErrorStack;
use crate::lib_ctx::LibCtxRef;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_char;
use openssl_macros::corresponds;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_PROVIDER;
    fn drop = ossl_provider_free;

    pub struct Provider;
    /// A reference to a [`Provider`].
    pub struct ProviderRef;
}

#[inline]
unsafe fn ossl_provider_free(p: *mut ffi::OSSL_PROVIDER) {
    ffi::OSSL_PROVIDER_unload(p);
}

impl Provider {
    /// Loads a new provider into the specified library context, disabling the fallback providers.
    ///
    /// If `ctx` is `None`, the provider will be loaded in to the default library context.
    #[corresponds(OSSL_provider_load)]
    pub fn load(ctx: Option<&LibCtxRef>, name: &str) -> Result<Self, ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            let p = cvt_p(ffi::OSSL_PROVIDER_load(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                name.as_ptr(),
            ))?;

            Ok(Provider::from_ptr(p))
        }
    }

    /// Loads a new provider into the specified library context, disabling the fallback providers if `retain_fallbacks`
    /// is `false` and the load succeeds.
    ///
    /// If `ctx` is `None`, the provider will be loaded into the default library context.
    #[corresponds(OSSL_provider_try_load)]
    pub fn try_load(
        ctx: Option<&LibCtxRef>,
        name: &str,
        retain_fallbacks: bool,
    ) -> Result<Self, ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            let p = cvt_p(ffi::OSSL_PROVIDER_try_load(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                name.as_ptr(),
                retain_fallbacks as _,
            ))?;

            // OSSL_PROVIDER_try_load seems to leave errors on the stack, even
            // when it succeeds.
            let _ = ErrorStack::get();

            Ok(Provider::from_ptr(p))
        }
    }

    /// Specifies the default search path that is to be used for looking for providers in the specified library context.
    /// If left unspecified, an environment variable and a fall back default value will be used instead
    ///
    /// If `ctx` is `None`, the provider will be loaded into the default library context.
    #[corresponds(OSSL_PROVIDER_set_default_search_path)]
    pub fn set_default_search_path(ctx: Option<&LibCtxRef>, path: &str) -> Result<(), ErrorStack> {
        let path = CString::new(path).unwrap();
        unsafe {
            cvt(ffi::OSSL_PROVIDER_set_default_search_path(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                path.as_ptr(),
            ))
            .map(|_| ())
        }
    }
}

impl ProviderRef {
    #[corresponds(OSSL_PROVIDER_get_params)]
    fn get_params<'a>(&self, params: &[&'a CStr]) -> Result<HashMap<&'a CStr, String>, ErrorStack> {
        // Create ptrs to receive the parameter results
        let mut values: Vec<*mut c_char> = params.iter().map(|_| ptr::null_mut()).collect();

        // Build an OSSL_PARAM array
        let mut param_array: Vec<ffi::OSSL_PARAM> = Vec::with_capacity(params.len() + 1);
        for (value, &param) in values.iter_mut().zip(params) {
            param_array
                .push(unsafe { ffi::OSSL_PARAM_construct_utf8_ptr(param.as_ptr(), value, 0) });
        }
        param_array.push(unsafe { ffi::OSSL_PARAM_construct_end() });

        // Get the params
        cvt(unsafe { ffi::OSSL_PROVIDER_get_params(self.as_ptr(), param_array.as_mut_ptr()) })?;

        // Build a HashMap with the params + values
        Ok(params
            .iter()
            .zip(values)
            .map(|(&param, value)| {
                (
                    param,
                    unsafe { CStr::from_ptr(value) }
                        .to_string_lossy()
                        .to_string(),
                )
            })
            .collect::<HashMap<_, _>>())
    }

    /// Get the name of the provider
    pub fn name(&self) -> Result<String, ErrorStack> {
        let param = CStr::from_bytes_with_nul(b"name\0").unwrap();
        Ok(self.get_params(&[param])?.remove(param).unwrap())
    }

    /// Get the build info of the provider
    pub fn buildinfo(&self) -> Result<String, ErrorStack> {
        let param = CStr::from_bytes_with_nul(b"buildinfo\0").unwrap();
        Ok(self.get_params(&[param])?.remove(param).unwrap())
    }

    /// Get the version string of the provider
    pub fn version_string(&self) -> Result<String, ErrorStack> {
        let param = CStr::from_bytes_with_nul(b"version\0").unwrap();
        Ok(self.get_params(&[param])?.remove(param).unwrap())
    }

    /// Get the version 3-tuple of the provider
    pub fn version(&self) -> Result<(u8, u8, u8), ErrorStack> {
        let version: Vec<_> = self
            .version_string()?
            .split(".")
            .map(|p| p.parse::<_>().unwrap())
            .collect();
        Ok((version[0], version[1], version[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let provider = Provider::load(None, "default").unwrap();
        assert_eq!(provider.name().unwrap(), "OpenSSL Default Provider");
    }

    #[test]
    fn test_version() {
        let provider = Provider::load(None, "default").unwrap();
        let version = provider.version().unwrap();
        assert_eq!(version.0, 3);
        assert!(version >= (3, 0, 0));
    }

    #[test]
    fn test_build_info() {
        let provider = Provider::load(None, "default").unwrap();
        provider.buildinfo().unwrap();
    }
}
