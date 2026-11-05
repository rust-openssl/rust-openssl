use super::super::*;
use libc::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum UI_string_types {
    UIT_NONE = 0,
    UIT_PROMPT,
    UIT_VERIFY,
    UIT_BOOLEAN,
    UIT_INFO,
    UIT_ERROR,
}

pub enum UI_STRING {}

extern "C" {
    pub fn UI_get_string_type(uis: *mut UI_STRING) -> c_uint;
    pub fn UI_get_input_flags(uis: *mut UI_STRING) -> c_int;
    pub fn UI_get0_output_string(uis: *mut UI_STRING) -> *const c_char;
    pub fn UI_get0_action_string(uis: *mut UI_STRING) -> *const c_char;
    pub fn UI_get0_result_string(uis: *mut UI_STRING) -> *const c_char;
    pub fn UI_get_result_string_length(uis: *mut UI_STRING) -> c_int;
    pub fn UI_get0_test_string(uis: *mut UI_STRING) -> *const c_char;
    pub fn UI_get_result_minsize(uis: *mut UI_STRING) -> c_int;
    pub fn UI_get_result_maxsize(uis: *mut UI_STRING) -> c_int;
    pub fn UI_set_result(ui: *mut UI, uis: *mut UI_STRING, result: *const c_char) -> c_int;
    pub fn UI_set_result_ex(
        ui: *mut UI,
        uis: *mut UI_STRING,
        result: *const c_char,
        len: c_int,
    ) -> c_int;
}

pub enum UI_METHOD {}
// #[repr(C)]
// pub struct UI_METHOD {
//     pub name: *const c_char,
//     pub ui_open_session: Option<extern "C" fn(ui: *mut UI) -> c_int>,
//     pub ui_write_string: Option<extern "C" fn(ui: *mut UI, uis: *mut UI_STRING) -> c_int>,
//     pub ui_flush: Option<extern "C" fn(ui: *mut UI) -> c_int>,
//     pub ui_read_string: Option<extern "C" fn(ui: *mut UI, uis: *mut UI_STRING) -> c_int>,
//     pub ui_close_session: Option<extern "C" fn(ui: *mut UI) -> c_int>,
//     pub ui_duplicate_data: Option<extern "C" fn(ui: *mut UI, ui_data: *mut c_void) -> *mut c_void>,
//     pub ui_destroy_data: Option<extern "C" fn(ui: *mut UI, ui_data: *mut c_void)>,
//     pub ui_construct_prompt: Option<extern "C" fn(
//         ui: *mut UI,
//         object_desc: *const c_char,
//         object_name: *const c_char,
//     ) -> *mut c_char>,
//     pub ex_data: CRYPTO_EX_DATA,
// }

extern "C" {
    pub fn UI_create_method(name: *const c_char) -> *mut UI_METHOD;
    pub fn UI_destroy_method(ui_method: *mut UI_METHOD);
    pub fn UI_method_set_opener(
        method: *mut UI_METHOD,
        opener: Option<extern "C" fn(*mut UI) -> c_int>,
    ) -> c_int;
    pub fn UI_method_set_writer(
        method: *mut UI_METHOD,
        writer: Option<extern "C" fn(*mut UI, *mut UI_STRING) -> c_int>,
    ) -> c_int;
    pub fn UI_method_set_flusher(
        method: *mut UI_METHOD,
        flusher: Option<extern "C" fn(*mut UI) -> c_int>,
    ) -> c_int;
    pub fn UI_method_set_reader(
        method: *mut UI_METHOD,
        reader: Option<extern "C" fn(*mut UI, *mut UI_STRING) -> c_int>,
    ) -> c_int;
    pub fn UI_method_set_closer(
        method: *mut UI_METHOD,
        closer: Option<extern "C" fn(*mut UI) -> c_int>,
    ) -> c_int;
    pub fn UI_method_set_data_duplicator(
        method: *mut UI_METHOD,
        duplicator: Option<extern "C" fn(*mut UI, *mut c_void) -> *mut c_void>,
        destructor: Option<extern "C" fn(*mut UI, *mut c_void)>,
    ) -> c_int;
    pub fn UI_method_set_prompt_constructor(
        method: *mut UI_METHOD,
        prompt_constructor: Option<
            extern "C" fn(*mut UI, *const c_char, *const c_char) -> *mut c_char,
        >,
    ) -> c_int;
    // Next functions will return:
    // int(*)(UI*) (*__test_fn_UI_method_get_opener(void))(const UI_METHOD*)
    // But, our needs is int (*__test_UI_method_get_opener(const UI_METHOD *method)) (UI *);
    // pub fn UI_method_get_opener(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI) -> c_int>;
    // pub fn UI_method_get_writer(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> c_int>;
    // pub fn UI_method_get_flusher(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI) -> c_int>;
    // pub fn UI_method_get_reader(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> c_int>;
    // pub fn UI_method_get_closer(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI) -> c_int>;
    // pub fn UI_method_get_prompt_constructor(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI, *const c_char, *const c_char) -> *mut c_char>;
    // pub fn UI_method_get_data_duplicator(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI, *mut c_void) -> *mut c_void>;
    // pub fn UI_method_get_data_destructor(
    //     method: *const UI_METHOD,
    // ) -> Option<unsafe extern "C" fn(*mut UI, *mut c_void)>;
}

extern "C" {
    pub fn UI_method_set_ex_data(method: *mut UI_METHOD, idx: c_int, data: *mut c_void) -> c_int;
    pub fn UI_method_get_ex_data(method: *const UI_METHOD, idx: c_int) -> *const c_void;
}

pub enum UI {}

extern "C" {
    pub fn UI_new() -> *mut UI;
    pub fn UI_new_method(meth: *const UI_METHOD) -> *mut UI;
    pub fn UI_free(e: *mut UI);
    pub fn UI_add_input_string(
        ui: *mut UI,
        prompt: *const c_char,
        flags: c_int,
        result_buf: *mut c_char,
        minsize: c_int,
        maxsize: c_int,
    ) -> c_int;
    pub fn UI_dup_input_string(
        ui: *mut UI,
        prompt: *const c_char,
        flags: c_int,
        result_buf: *mut c_char,
        minsize: c_int,
        maxsize: c_int,
    ) -> c_int;
    pub fn UI_add_verify_string(
        ui: *mut UI,
        prompt: *const c_char,
        flags: c_int,
        result_buf: *mut c_char,
        minsize: c_int,
        maxsize: c_int,
        test_buf: *const c_char,
    ) -> c_int;
    pub fn UI_dup_verify_string(
        ui: *mut UI,
        prompt: *const c_char,
        flags: c_int,
        result_buf: *mut c_char,
        minsize: c_int,
        maxsize: c_int,
        test_buf: *const c_char,
    ) -> c_int;
    pub fn UI_add_input_boolean(
        ui: *mut UI,
        prompt: *const c_char,
        action_desc: *const c_char,
        ok_chars: *const c_char,
        cancel_chars: *const c_char,
        flags: c_int,
        result_buf: *mut c_char,
    ) -> c_int;
    pub fn UI_dup_input_boolean(
        ui: *mut UI,
        prompt: *const c_char,
        action_desc: *const c_char,
        ok_chars: *const c_char,
        cancel_chars: *const c_char,
        flags: c_int,
        result_buf: *mut c_char,
    ) -> c_int;
    pub fn UI_add_info_string(ui: *mut UI, text: *const c_char) -> c_int;
    pub fn UI_dup_info_string(ui: *mut UI, text: *const c_char) -> c_int;
    pub fn UI_add_error_string(ui: *mut UI, text: *const c_char) -> c_int;
    pub fn UI_dup_error_string(ui: *mut UI, text: *const c_char) -> c_int;
    pub fn UI_construct_prompt(
        ui: *mut UI,
        phrase_desc: *const c_char,
        object_name: *const c_char,
    ) -> *mut c_char;
    pub fn UI_add_user_data(ui: *mut UI, user_data: *mut c_void) -> *mut c_void;
    pub fn UI_dup_user_data(ui: *mut UI, user_data: *mut c_void) -> c_int;
    pub fn UI_get0_user_data(ui: *mut UI) -> *mut c_void;
    pub fn UI_get0_result(ui: *mut UI, i: c_int) -> *const c_char;
    pub fn UI_get_result_length(ui: *mut UI, i: c_int) -> c_int;
    pub fn UI_process(ui: *mut UI) -> c_int;
    pub fn UI_ctrl(
        ui: *mut UI,
        cmd: c_int,
        i: c_long,
        p: *mut c_void,
        f: unsafe extern "C" fn(),
    ) -> c_int;
    pub fn UI_set_default_method(meth: *const UI_METHOD);
    pub fn UI_get_default_method() -> *const UI_METHOD;
    pub fn UI_get_method(ui: *mut UI) -> *const UI_METHOD;
    pub fn UI_set_method(ui: *mut UI, meth: *const UI_METHOD) -> *const UI_METHOD;
    pub fn UI_OpenSSL() -> *mut UI_METHOD;
    pub fn UI_null() -> *const UI_METHOD;
}

extern "C" {
    #[cfg(not(ossl110))]
    pub fn UI_get_ex_new_index(
        argl: c_long,
        argp: *mut c_void,
        new_func: Option<CRYPTO_EX_new>,
        dup_func: Option<CRYPTO_EX_dup>,
        free_func: Option<CRYPTO_EX_free>,
    ) -> c_int;

    pub fn UI_set_ex_data(ssl: *mut UI, idx: c_int, data: *mut c_void) -> c_int;
    pub fn UI_get_ex_data(ssl: *const UI, idx: c_int) -> *mut c_void;
}
