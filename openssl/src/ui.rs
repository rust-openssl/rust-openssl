use foreign_types::ForeignType;
use libc::c_void;
use openssl_macros::corresponds;

use crate::{cvt_p, error::ErrorStack, ex_data::Index};

fn safe_null_destroy_method(ui_method: *mut ffi::UI_METHOD) {
    // pre-check UI_null
    let ui_null: *const ffi::UI_METHOD = unsafe { ffi::UI_null() };

    // Ensure the comparison is done correctly
    if ui_method != ui_null as *mut ffi::UI_METHOD {
        unsafe { ffi::UI_destroy_method(ui_method) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::UI_METHOD;
    fn drop = safe_null_destroy_method;

    /// A User Interface
    ///
    /// UI stands for User Interface, and is general purpose set of routines to prompt the user for text-based information.
    /// Through user-written methods (see UI_create_method(3)), prompting can be done in any way imaginable,
    /// be it plain text prompting, through dialog boxes or from a cell phone.
    pub struct UiMethod;

    /// Reference to [`UiMethod`]
    ///
    /// [`UiMethod`]: struct.Ui.html
    pub struct UiMethodRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::UI;
    fn drop = ffi::UI_free;

    /// A User Interface
    ///
    /// UI stands for User Interface, and is general purpose set of routines to prompt the user for text-based information.
    /// Through user-written methods (see UI_create_method(3)), prompting can be done in any way imaginable,
    /// be it plain text prompting, through dialog boxes or from a cell phone.
    pub struct Ui;

    /// Reference to [`Ui`]
    ///
    /// [`Ui`]: struct.Ui.html
    pub struct UiRef;
}

impl Ui {
    #[corresponds(UI_new)]
    pub fn new() -> Result<Ui, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::UI_new()).map(Ui)
        }
    }

    /// Sets the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `Ssl::new_ex_index` method to create an `Index`.
    // FIXME should return a result
    #[corresponds(UI_set_ex_data)]
    pub fn set_ex_data<T>(&mut self, index: Index<Ui, T>, data: T) {
        match self.ex_data_mut(index) {
            Some(v) => *v = data,
            None => unsafe {
                let data = Box::new(data);
                ffi::UI_set_ex_data(
                    self.as_ptr(),
                    index.as_raw(),
                    Box::into_raw(data) as *mut c_void,
                );
            },
        }
    }

    /// Returns a reference to the extra data at the specified index.
    #[corresponds(UI_get_ex_data)]
    pub fn ex_data<T>(&self, index: Index<Ui, T>) -> Option<&T> {
        unsafe {
            let data = ffi::UI_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    /// Returns a mutable reference to the extra data at the specified index.
    #[corresponds(UI_get_ex_data)]
    pub fn ex_data_mut<T>(&mut self, index: Index<Ui, T>) -> Option<&mut T> {
        unsafe {
            let data = ffi::UI_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&mut *(data as *mut T))
            }
        }
    }
}
