//! Interface for OpenSSL engine.

use std::{ffi::CString, ptr::null_mut};

use foreign_types::ForeignType;
use libc::c_void;
use openssl_macros::corresponds;

use crate::{
    cvt, cvt_p,
    error::ErrorStack,
    pkey::{PKey, Private, Public},
    ui::UiMethod,
};

fn engine_free(ptr: *mut ffi::ENGINE) {
    unsafe {
        // ENGINE_free() always returns 1
        ffi::ENGINE_free(ptr);
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ENGINE;
    fn drop = engine_free;

    pub struct Engine;
    pub struct EngineRef;
}

impl Engine {
    /// Create a new engine
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::engine::{Engine};
    ///
    /// let engine = Engine::new();
    /// ```
    #[corresponds(ENGINE_new)]
    pub fn new() -> Result<Engine, ErrorStack> {
        ffi::init();

        unsafe { cvt_p(ffi::ENGINE_new()).map(Engine) }
    }

    /// Load all bundled ENGINEs into memory and make them visible
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::engine::{Engine};
    ///
    /// let engine = Engine::load_builtin_engines();
    /// ```
    #[corresponds(ENGINE_load_builtin_engines)]
    pub fn load_builtin_engines() {
        ffi::init();

        // TODO: not sure about the ffi::init for this one.
        unsafe { ffi::ENGINE_load_builtin_engines() }
    }

    /// Get an engine from the `engine_id`
    ///
    /// # Examples
    ///
    /// ```(ignore)
    /// use openssl::engine::{Engine};
    ///
    /// let engine = Engine::new("pkcs11");
    /// ```
    #[corresponds(ENGINE_by_id)]
    pub fn by_id(id: &str) -> Result<Engine, ErrorStack> {
        ffi::init();

        let id = CString::new(id).unwrap();
        unsafe { cvt_p(ffi::ENGINE_by_id(id.as_ptr())).map(Engine) }
    }

    /// Lock the engine
    #[corresponds(ENGINE_init)]
    pub fn init(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::ENGINE_init(self.as_ptr())).map(|_| ()) }
    }

    /// Unlock the engine
    #[corresponds(ENGINE_finish)]
    pub fn finish(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::ENGINE_finish(self.as_ptr())).map(|_| ()) }
    }

    /// Loads a private key
    #[corresponds(ENGINE_load_private_key)]
    pub fn load_private_key<T>(
        &mut self,
        key_id: &str,
        ui_method: Option<UiMethod>,
        callback_data: Option<T>,
    ) -> Result<PKey<Private>, ErrorStack> {
        let key_id = CString::new(key_id).unwrap();
        let raw = match callback_data {
            Some(callback_data) => Box::into_raw(Box::new(callback_data)) as *mut c_void,
            None => null_mut(),
        };

        let res = unsafe {
            cvt_p(ffi::ENGINE_load_private_key(
                self.as_ptr(),
                key_id.as_ptr(),
                ui_method.map_or(null_mut(), |value| value.as_ptr()),
                raw,
            ))
            .map(|op| PKey::from_ptr(op))
        };

        // cleanup
        if !raw.is_null() {
            let _ = unsafe { Box::<T>::from_raw(raw as *mut T) };
        };

        res
    }

    /// Loads a public key
    #[corresponds(ENGINE_load_public_key)]
    pub fn load_public_key<T: ForeignType>(
        &mut self,
        key_id: &str,
        ui_method: Option<UiMethod>,
        callback_data: Option<T>,
    ) -> Result<PKey<Public>, ErrorStack> {
        let key_id = CString::new(key_id).unwrap();
        let raw = match callback_data {
            Some(callback_data) => Box::into_raw(Box::new(callback_data)) as *mut c_void,
            None => null_mut(),
        };

        let res = unsafe {
            cvt_p(ffi::ENGINE_load_public_key(
                self.as_ptr(),
                key_id.as_ptr(),
                ui_method.map_or(null_mut(), |value| value.as_ptr()),
                raw,
            ))
            .map(|op| PKey::from_ptr(op))
        };

        // cleanup
        if !raw.is_null() {
            let _ = unsafe { Box::<T>::from_raw(raw as *mut T) };
        };

        res
    }
}
