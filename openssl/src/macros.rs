macro_rules! private_key_from_pem {
    ($(#[$m:meta])* $n:ident, $(#[$m2:meta])* $n2:ident, $(#[$m3:meta])* $n3:ident, $t:ty, $struc: path, $f:path) => {
        from_pem!($(#[$m])* $n, $t, $struc, $f);

        $(#[$m2])*
        pub fn $n2(pem: &[u8], passphrase: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return Ok(crate::ossl_encdec::Decoder::new()
                .set_format(crate::ossl_encdec::KeyFormat::Pem)
                .set_structure($struc)
                .set_passphrase(passphrase)
                .decode(pem)?.try_into().unwrap());

            #[cfg(not(ossl300))]
            unsafe {
                ffi::init();
                let bio = crate::bio::MemBioSlice::new(pem)?;
                let passphrase = ::std::ffi::CString::new(passphrase).unwrap();
                cvt_p($f(bio.as_ptr(),
                         ::std::ptr::null_mut(),
                         None,
                         passphrase.as_ptr() as *const _ as *mut _))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }

        $(#[$m3])*
        pub fn $n3<F>(pem: &[u8], callback: F) -> Result<$t, crate::error::ErrorStack>
            where F: FnOnce(&mut [u8]) -> Result<usize, crate::error::ErrorStack>
        {
            #[cfg(ossl300)]
            return Ok(crate::ossl_encdec::Decoder::new()
                .set_format(crate::ossl_encdec::KeyFormat::Pem)
                .set_structure($struc)
                .set_passphrase_callback(callback)
                .decode(pem)?.try_into().unwrap());

            #[cfg(not(ossl300))]
            unsafe {
                ffi::init();
                let mut cb = crate::util::CallbackState::new(callback);
                let bio = crate::bio::MemBioSlice::new(pem)?;
                cvt_p($f(bio.as_ptr(),
                         ::std::ptr::null_mut(),
                         Some(crate::util::invoke_passwd_cb::<F>),
                         &mut cb as *mut _ as *mut _))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    };
    ($(#[$m:meta])* $n:ident, $(#[$m2:meta])* $n2:ident, $(#[$m3:meta])* $n3:ident, $t:ty, $f:path) => {
        from_pem!($(#[$m])* $n, $t, $f);

        $(#[$m2])*
        pub fn $n2(pem: &[u8], passphrase: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            unsafe {
                ffi::init();
                let bio = crate::bio::MemBioSlice::new(pem)?;
                let passphrase = ::std::ffi::CString::new(passphrase).unwrap();
                crate::cvt_p($f(bio.as_ptr(),
                         ::std::ptr::null_mut(),
                         None,
                         passphrase.as_ptr() as *const _ as *mut _))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }

        $(#[$m3])*
        pub fn $n3<F>(pem: &[u8], callback: F) -> Result<$t, crate::error::ErrorStack>
            where F: FnOnce(&mut [u8]) -> Result<usize, crate::error::ErrorStack>
        {
            unsafe {
                ffi::init();
                let mut cb = crate::util::CallbackState::new(callback);
                let bio = crate::bio::MemBioSlice::new(pem)?;
                crate::cvt_p($f(bio.as_ptr(),
                         ::std::ptr::null_mut(),
                         Some(crate::util::invoke_passwd_cb::<F>),
                         &mut cb as *mut _ as *mut _))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! private_key_to_pem {
    ($(#[$m:meta])* $n:ident, $(#[$m2:meta])* $n2:ident, $sel:path, $struc:path, $f:path) => {
        $(#[$m])*
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return crate::ossl_encdec::Encoder::new($sel)
                .set_format(crate::ossl_encdec::KeyFormat::Pem)
                .set_structure($struc)
                .encode(&self.0);

            #[cfg(not(ossl300))]
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                crate::cvt($f(bio.as_ptr(),
                        self.as_ptr(),
                        ::std::ptr::null(),
                        ::std::ptr::null_mut(),
                        -1,
                        None,
                        ::std::ptr::null_mut()))?;
                Ok(bio.get_buf().to_owned())
            }
        }

        $(#[$m2])*
        pub fn $n2(
            &self,
            cipher: crate::symm::Cipher,
            passphrase: &[u8]
        ) -> Result<Vec<u8>, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return crate::ossl_encdec::Encoder::new($sel)
                .set_format(crate::ossl_encdec::KeyFormat::Pem)
                .set_cipher(cipher)
                .set_passphrase(passphrase)
                .encode(&self.0);

            #[cfg(not(ossl300))]
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                assert!(passphrase.len() <= ::libc::c_int::MAX as usize);
                crate::cvt($f(bio.as_ptr(),
                        self.as_ptr(),
                        cipher.as_ptr(),
                        passphrase.as_ptr() as *const _ as *mut _,
                        passphrase.len() as ::libc::c_int,
                        None,
                        ::std::ptr::null_mut()))?;
                Ok(bio.get_buf().to_owned())
            }
        }
    };
    ($(#[$m:meta])* $n:ident, $(#[$m2:meta])* $n2:ident, $f:path) => {
        $(#[$m])*
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                crate::cvt($f(bio.as_ptr(),
                        self.as_ptr(),
                        ::std::ptr::null(),
                        ::std::ptr::null_mut(),
                        -1,
                        None,
                        ::std::ptr::null_mut()))?;
                Ok(bio.get_buf().to_owned())
            }
        }

        $(#[$m2])*
        pub fn $n2(
            &self,
            cipher: crate::symm::Cipher,
            passphrase: &[u8]
        ) -> Result<Vec<u8>, crate::error::ErrorStack> {
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                assert!(passphrase.len() <= ::libc::c_int::MAX as usize);
                crate::cvt($f(bio.as_ptr(),
                        self.as_ptr(),
                        cipher.as_ptr(),
                        passphrase.as_ptr() as *const _ as *mut _,
                        passphrase.len() as ::libc::c_int,
                        None,
                        ::std::ptr::null_mut()))?;
                Ok(bio.get_buf().to_owned())
            }
        }
    }
}

macro_rules! to_pem {
    ($(#[$m:meta])* $n:ident, $sel:path, $struc:path, $f:path) => {
        $(#[$m])*
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return crate::ossl_encdec::Encoder::new($sel)
                .set_format(crate::ossl_encdec::KeyFormat::Pem)
                .set_structure($struc)
                .encode(&self.0);

            #[cfg(not(ossl300))]
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                crate::cvt($f(bio.as_ptr(), self.as_ptr()))?;
                Ok(bio.get_buf().to_owned())
            }
        }
    };
    ($(#[$m:meta])* $n:ident, $f:path) => {
        $(#[$m])*
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            unsafe {
                let bio = crate::bio::MemBio::new()?;
                crate::cvt($f(bio.as_ptr(), self.as_ptr()))?;
                Ok(bio.get_buf().to_owned())
            }
        }
    }
}

macro_rules! to_der {
    ($(#[$m:meta])* $n:ident, $sel:path, $struc:path, $f:path) => {
        $(#[$m])*
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return crate::ossl_encdec::Encoder::new($sel)
                .set_format(crate::ossl_encdec::KeyFormat::Der)
                .set_structure($struc)
                .encode(&self.0);

            #[cfg(not(ossl300))]
            unsafe {
                let len = crate::cvt($f(::foreign_types::ForeignTypeRef::as_ptr(self),
                                        ::std::ptr::null_mut()))?;
                let mut buf = vec![0; len as usize];
                crate::cvt($f(::foreign_types::ForeignTypeRef::as_ptr(self),
                              &mut buf.as_mut_ptr()))?;
                Ok(buf)
            }
        }
    };
    ($(#[$m:meta])* $n:ident, $f:path) => {
        $(#[$m])*
        pub fn $n(&self) -> Result<Vec<u8>, crate::error::ErrorStack> {
            unsafe {
                let len = crate::cvt($f(::foreign_types::ForeignTypeRef::as_ptr(self),
                                        ::std::ptr::null_mut()))?;
                let mut buf = vec![0; len as usize];
                crate::cvt($f(::foreign_types::ForeignTypeRef::as_ptr(self),
                              &mut buf.as_mut_ptr()))?;
                Ok(buf)
            }
        }
    };
}

macro_rules! from_der {
    ($(#[$m:meta])* $n:ident, $t:ty, $struc: path, $f:path) => {
        $(#[$m])*
        pub fn $n(der: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return Ok(crate::ossl_encdec::Decoder::new()
                .set_format(crate::ossl_encdec::KeyFormat::Der)
                .set_key_type(Self::ID)
                .set_structure($struc)
                .decode(der)?.try_into().unwrap());

            #[cfg(not(ossl300))]
            unsafe {
                use std::convert::TryInto;
                ffi::init();
                let len = ::std::cmp::min(der.len(), ::libc::c_long::MAX as usize) as ::libc::c_long;
                crate::cvt_p($f(::std::ptr::null_mut(), &mut der.as_ptr(), len.try_into().unwrap()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    };
    ($(#[$m:meta])* $n:ident, $t:ty, $f:path) => {
        $(#[$m])*
        pub fn $n(der: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            use std::convert::TryInto;
            unsafe {
                ffi::init();
                let len = ::std::cmp::min(der.len(), ::libc::c_long::MAX as usize) as ::libc::c_long;
                crate::cvt_p($f(::std::ptr::null_mut(), &mut der.as_ptr(), len.try_into().unwrap()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! from_pem {
    ($(#[$m:meta])* $n:ident, $t:ty, $struc: path, $f:path) => {
        $(#[$m])*
        pub fn $n(pem: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            #[cfg(ossl300)]
            return Ok(crate::ossl_encdec::Decoder::new()
                .set_format(crate::ossl_encdec::KeyFormat::Pem)
                .set_structure($struc)
                .decode(pem)?.try_into().unwrap());

            #[cfg(not(ossl300))]
            unsafe {
                crate::init();
                let bio = crate::bio::MemBioSlice::new(pem)?;
                crate::cvt_p($f(bio.as_ptr(), ::std::ptr::null_mut(), None, ::std::ptr::null_mut()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    };
    ($(#[$m:meta])* $n:ident, $t:ty, $f:path) => {
        $(#[$m])*
        pub fn $n(pem: &[u8]) -> Result<$t, crate::error::ErrorStack> {
            unsafe {
                crate::init();
                let bio = crate::bio::MemBioSlice::new(pem)?;
                crate::cvt_p($f(bio.as_ptr(), ::std::ptr::null_mut(), None, ::std::ptr::null_mut()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident;
    )
        => {
            ::foreign_types::foreign_type! {
                $(#[$impl_attr])*
                type CType = $ctype;
                fn drop = $drop;
                $(fn clone = $clone;)*
                $(#[$owned_attr])*
                pub struct $owned;
                $(#[$borrowed_attr])*
                pub struct $borrowed;
            }

            unsafe impl Send for $owned{}
            unsafe impl Send for $borrowed{}
            unsafe impl Sync for $owned{}
            unsafe impl Sync for $borrowed{}
        };
}

macro_rules! generic_foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident<T>;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident<T>;
    ) => {
        $(#[$owned_attr])*
        pub struct $owned<T>(*mut $ctype, ::std::marker::PhantomData<T>);

        $(#[$impl_attr])*
        impl<T> ::foreign_types::ForeignType for $owned<T> {
            type CType = $ctype;
            type Ref = $borrowed<T>;

            #[inline]
            unsafe fn from_ptr(ptr: *mut $ctype) -> $owned<T> {
                $owned(ptr, ::std::marker::PhantomData)
            }

            #[inline]
            fn as_ptr(&self) -> *mut $ctype {
                self.0
            }
        }

        impl<T> Drop for $owned<T> {
            #[inline]
            fn drop(&mut self) {
                unsafe { $drop(self.0) }
            }
        }

        $(
            impl<T> Clone for $owned<T> {
                #[inline]
                fn clone(&self) -> $owned<T> {
                    unsafe {
                        let handle: *mut $ctype = $clone(self.0);
                        ::foreign_types::ForeignType::from_ptr(handle)
                    }
                }
            }

            impl<T> ::std::borrow::ToOwned for $borrowed<T> {
                type Owned = $owned<T>;
                #[inline]
                fn to_owned(&self) -> $owned<T> {
                    unsafe {
                        let handle: *mut $ctype =
                            $clone(::foreign_types::ForeignTypeRef::as_ptr(self));
                        $crate::ForeignType::from_ptr(handle)
                    }
                }
            }
        )*

        impl<T> ::std::ops::Deref for $owned<T> {
            type Target = $borrowed<T>;

            #[inline]
            fn deref(&self) -> &$borrowed<T> {
                unsafe { ::foreign_types::ForeignTypeRef::from_ptr(self.0) }
            }
        }

        impl<T> ::std::ops::DerefMut for $owned<T> {
            #[inline]
            fn deref_mut(&mut self) -> &mut $borrowed<T> {
                unsafe { ::foreign_types::ForeignTypeRef::from_ptr_mut(self.0) }
            }
        }

        impl<T> ::std::borrow::Borrow<$borrowed<T>> for $owned<T> {
            #[inline]
            fn borrow(&self) -> &$borrowed<T> {
                &**self
            }
        }

        impl<T> ::std::convert::AsRef<$borrowed<T>> for $owned<T> {
            #[inline]
            fn as_ref(&self) -> &$borrowed<T> {
                &**self
            }
        }

        $(#[$borrowed_attr])*
        pub struct $borrowed<T>(::foreign_types::Opaque, ::std::marker::PhantomData<T>);

        $(#[$impl_attr])*
        impl<T> ::foreign_types::ForeignTypeRef for $borrowed<T> {
            type CType = $ctype;
        }

        unsafe impl<T> Send for $owned<T>{}
        unsafe impl<T> Send for $borrowed<T>{}
        unsafe impl<T> Sync for $owned<T>{}
        unsafe impl<T> Sync for $borrowed<T>{}
    };
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident<T>;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident<T>;
        key_id = $key_id:path;
        pkey_type = $pkey_type:ident;
    ) => {
        cfg_if::cfg_if!{
            if #[cfg(ossl300)] {
                use crate::pkey::KeyID;

                $(#[$owned_attr])*
                pub struct $owned<T>(crate::pkey::PKey<T>);

                impl<T> crate::pkey::KeyID for $owned<T>{
                    const ID: crate::pkey::Id = $key_id;
                }

                $(#[$impl_attr])*
                impl<T> ForeignType for $owned<T> {
                    type CType = ffi::EVP_PKEY;
                    type Ref = $borrowed<T>;

                    #[inline]
                    unsafe fn from_ptr(ptr: *mut ffi::EVP_PKEY) -> $owned<T> {
                        Self(crate::pkey::PKey::from_ptr(ptr))
                    }

                    #[inline]
                    fn as_ptr(&self) -> *mut ffi::EVP_PKEY {
                        self.0.as_ptr()
                    }
                }

                impl<T> Clone for $owned<T> {
                    #[inline]
                    fn clone(&self) -> $owned<T> {
                        Self(self.0.clone())
                    }
                }

                impl<T> ToOwned for $borrowed<T> {
                    type Owned = $owned<T>;

                    #[inline]
                    fn to_owned(&self) -> $owned<T> {
                        self.0.$pkey_type().unwrap()
                    }
                }

                impl<T> std::ops::Deref for $owned<T> {
                    type Target = $borrowed<T>;

                    #[inline]
                    fn deref(&self) -> &$borrowed<T> {
                        unsafe { $borrowed::from_ptr(self.as_ptr()) }
                    }
                }

                impl<T> std::ops::DerefMut for $owned<T> {
                    #[inline]
                    fn deref_mut(&mut self) -> &mut $borrowed<T> {
                        unsafe { $borrowed::from_ptr_mut(self.as_ptr()) }
                    }
                }

                impl<T> std::borrow::Borrow<$borrowed<T>> for $owned<T> {
                    #[inline]
                    fn borrow(&self) -> &$borrowed<T> {
                        self
                    }
                }

                impl<T> AsRef<$borrowed<T>> for $owned<T> {
                    #[inline]
                    fn as_ref(&self) -> &$borrowed<T> {
                        self
                    }
                }

                $(#[$borrowed_attr])*
                pub struct $borrowed<T>(crate::pkey::PKeyRef<T>);

                impl<T> ForeignTypeRef for $borrowed<T> {
                    type CType = ffi::EVP_PKEY;
                }

                unsafe impl<T> Send for $owned<T>{}
                unsafe impl<T> Send for $borrowed<T>{}
                unsafe impl<T> Sync for $owned<T>{}
                unsafe impl<T> Sync for $borrowed<T>{}

                impl<T> From<&$borrowed<T>> for crate::pkey::PKey<T> {
                    fn from(value: &$borrowed<T>) -> Self {
                        value.0.to_owned()
                    }
                }
            } else {
                generic_foreign_type_and_impl_send_sync!{
                    $(#[$impl_attr])*
                    type CType = $ctype;
                    fn drop = $drop;
                    $(fn clone = $clone;)*

                    $(#[$owned_attr])*
                    pub struct $owned<T>;
                    $(#[$borrowed_attr])*
                    pub struct $borrowed<T>;
                }

                impl<T> From<&$borrowed<T>> for crate::pkey::PKey<T> {
                    fn from(value: &$borrowed<T>) -> Self {
                        crate::pkey::PKey::try_from(value.to_owned()).unwrap()
                    }
                }
            }
        }
    }
}

#[cfg_attr(not(ossl300), allow(unused_macros))]
macro_rules! cstr_const {
    // Safety: these all have null terminators.
    // We cen remove these CStr::from_bytes_with_nul_unchecked calls
    // when we upgrade to Rust 1.77+ with literal c"" syntax.
    ($(#[$doc:meta])* $vis:vis $name:ident, $key:literal) => {
        $(#[$doc])*
        #[allow(dead_code)]
        $vis const $name: &std::ffi::CStr = unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked($key) };
    }
}
