//! FFI interface for calling from Go

use crate::types::{DetectionResult, IOC};
use crate::Engine;
use libc::{c_char, c_int, size_t};
use std::ffi::{CStr, CString};
use std::ptr;

/// Opaque pointer to the engine
pub type EngineHandle = *mut Engine;

/// Create a new detection engine
#[no_mangle]
pub extern "C" fn engine_new() -> EngineHandle {
    Box::into_raw(Box::new(Engine::new()))
}

/// Free the detection engine
#[no_mangle]
pub extern "C" fn engine_free(engine: EngineHandle) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

/// Load IOCs from JSON string
#[no_mangle]
pub extern "C" fn engine_load_iocs(
    engine: EngineHandle,
    json: *const c_char,
) -> c_int {
    if engine.is_null() || json.is_null() {
        return -1;
    }

    let engine = unsafe { &mut *engine };
    let json_str = unsafe { CStr::from_ptr(json) }.to_str().unwrap_or("");

    match serde_json::from_str::<Vec<IOC>>(json_str) {
        Ok(iocs) => {
            if engine.load_iocs(&iocs).is_ok() {
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Add a pattern to the engine
#[no_mangle]
pub extern "C" fn engine_add_pattern(
    engine: EngineHandle,
    pattern: *const c_char,
    id: size_t,
) -> c_int {
    if engine.is_null() || pattern.is_null() {
        return -1;
    }

    let engine = unsafe { &mut *engine };
    let pattern_str = unsafe { CStr::from_ptr(pattern) }.to_str().unwrap_or("");

    engine.add_pattern(pattern_str, id);
    0
}

/// Build the pattern matcher
#[no_mangle]
pub extern "C" fn engine_build(engine: EngineHandle) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let engine = unsafe { &mut *engine };
    engine.build_matcher();
    0
}

/// Detect in data
#[no_mangle]
pub extern "C" fn engine_detect(
    engine: EngineHandle,
    data: *const u8,
    data_len: size_t,
) -> *mut DetectionResult {
    if engine.is_null() || data.is_null() {
        return ptr::null_mut();
    }

    let engine = unsafe { &*engine };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };

    let result = engine.detect(data_slice);
    Box::into_raw(Box::new(result))
}

/// Detect in JSON data
#[no_mangle]
pub extern "C" fn engine_detect_json(
    engine: EngineHandle,
    json: *const c_char,
) -> *mut DetectionResult {
    if engine.is_null() || json.is_null() {
        return ptr::null_mut();
    }

    let engine = unsafe { &*engine };
    let json_str = unsafe { CStr::from_ptr(json) }.to_str().unwrap_or("");

    let result = engine.detect_json(json_str);
    Box::into_raw(Box::new(result))
}

/// Free detection result
#[no_mangle]
pub extern "C" fn result_free(result: *mut DetectionResult) {
    if !result.is_null() {
        unsafe {
            drop(Box::from_raw(result));
        }
    }
}

/// Get total matches from result
#[no_mangle]
pub extern "C" fn result_total_matches(result: *const DetectionResult) -> size_t {
    if result.is_null() {
        return 0;
    }

    unsafe { (*result).total_matches }
}

/// Get match count from result
#[no_mangle]
pub extern "C" fn result_match_count(result: *const DetectionResult) -> size_t {
    if result.is_null() {
        return 0;
    }

    unsafe { (*result).matches.len() }
}

/// Get match signature ID (caller must free the returned string)
#[no_mangle]
pub extern "C" fn result_match_signature_id(
    result: *const DetectionResult,
    index: size_t,
) -> *mut c_char {
    if result.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let matches = &(*result).matches;
        if index >= matches.len() {
            return ptr::null_mut();
        }

        match CString::new(matches[index].signature_id.clone()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }
}

/// Get match severity
#[no_mangle]
pub extern "C" fn result_match_severity(
    result: *const DetectionResult,
    index: size_t,
) -> c_int {
    if result.is_null() {
        return 0;
    }

    unsafe {
        let matches = &(*result).matches;
        if index >= matches.len() {
            return 0;
        }

        matches[index].severity as c_int
    }
}

/// Serialize detection result to JSON (caller must free)
#[no_mangle]
pub extern "C" fn result_to_json(result: *const DetectionResult) -> *mut c_char {
    if result.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        match serde_json::to_string(&*result) {
            Ok(json) => match CString::new(json) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        }
    }
}

/// Free a string returned from FFI
#[no_mangle]
pub extern "C" fn string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}
