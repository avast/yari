#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(deref_nullptr)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]

use std::fmt::Debug;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// SIZED_STRING structure
///
/// We need a custom definition because binding does not generate
/// __IncompleteArrayField for this struct.
#[repr(C)]
#[derive(Debug, Default)]
pub struct SIZED_STRING {
    pub length: u32,
    pub flags: u32,
    pub c_string: __IncompleteArrayField<::std::os::raw::c_char>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Debug for YR_SCAN_CONTEXT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        // Basic implementation just to satisfy derive Debug
        // We don't need all of the fields for now
        f.debug_struct("YR_SCAN_CONTEXT")
            .field("file_size", &self.file_size)
            .field("entry_point", &self.entry_point)
            .finish()
    }
}
