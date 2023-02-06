mod bindings;
pub mod error;
pub mod module;
pub mod parser;
pub mod utils;
pub mod yr_value;

extern crate regex;

use crate::bindings::yr_arena_ref_to_ptr;
use crate::bindings::yr_calloc;
use crate::bindings::yr_compiler_add_string;
use crate::bindings::yr_compiler_create;
use crate::bindings::yr_compiler_destroy;
use crate::bindings::yr_compiler_get_rules;
use crate::bindings::yr_filemap_map;
use crate::bindings::yr_filemap_unmap;
use crate::bindings::yr_finalize;
use crate::bindings::yr_get_configuration;
use crate::bindings::yr_hash_table_create;
use crate::bindings::yr_hash_table_lookup;
use crate::bindings::yr_initialize;
use crate::bindings::yr_modules_load;
use crate::bindings::yr_notebook_create;
use crate::bindings::yr_notebook_destroy;
use crate::bindings::yr_object_array_get_item;
use crate::bindings::yr_re_compile;
use crate::bindings::yr_rules_destroy;
use crate::bindings::yr_scan_verify_match;
use crate::bindings::yr_scanner_create;
use crate::bindings::yr_scanner_destroy;
use crate::bindings::yr_scanner_scan_mem_blocks;
use crate::bindings::yr_scanner_set_callback;
use crate::bindings::yr_scanner_set_flags;
use crate::bindings::yr_scanner_set_timeout;
use crate::bindings::CALLBACK_MSG_IMPORT_MODULE;
use crate::bindings::ERROR_SUCCESS;
use crate::bindings::OBJECT_TYPE_ARRAY;
use crate::bindings::OBJECT_TYPE_DICTIONARY;
use crate::bindings::OBJECT_TYPE_FLOAT;
use crate::bindings::OBJECT_TYPE_FUNCTION;
use crate::bindings::OBJECT_TYPE_INTEGER;
use crate::bindings::OBJECT_TYPE_STRING;
use crate::bindings::OBJECT_TYPE_STRUCTURE;
use crate::bindings::RE;
use crate::bindings::RE_ERROR;
use crate::bindings::SIZED_STRING;
use crate::bindings::YR_ARENA_REF;
use crate::bindings::YR_ARRAY_ITERATOR;
use crate::bindings::YR_COMPILER;
use crate::bindings::YR_DICT_ITERATOR;
use crate::bindings::YR_MAPPED_FILE;
use crate::bindings::YR_MATCH;
use crate::bindings::YR_MATCHES;
use crate::bindings::YR_MAX_OVERLOADED_FUNCTIONS;
use crate::bindings::YR_MEMORY_BLOCK;
use crate::bindings::YR_MEMORY_BLOCK_ITERATOR;
use crate::bindings::YR_MODULE_IMPORT;
use crate::bindings::YR_OBJECT;
use crate::bindings::YR_OBJECT_ARRAY;
use crate::bindings::YR_OBJECT_DICTIONARY;
use crate::bindings::YR_OBJECT_FUNCTION;
use crate::bindings::YR_OBJECT_STRUCTURE;
use crate::bindings::YR_RULE;
use crate::bindings::YR_SCANNER;
use crate::bindings::YR_SCAN_CONTEXT;
use crate::bindings::YR_STRING;
use crate::bindings::YR_STRUCTURE_MEMBER;
pub use crate::bindings::YR_UNDEFINED;
use crate::bindings::YR_VALUE;
pub use crate::error::YariError;
pub use crate::module::Module;
pub use crate::module::MODULES;
use crate::parser::{parse, Argument, Expression};
use crate::utils::expression_to_rules_with_condition;
pub use crate::yr_value::YrValue;
use core::ffi::c_void;
use log::{debug, error};
use parser::StrOperation;
use std::alloc::alloc;
use std::alloc::Layout;
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::Debug;
use std::mem::{size_of, ManuallyDrop};
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::str::FromStr;

#[cfg(feature = "avast")]
use crate::bindings::OBJECT_TYPE_REFERENCE;

#[cfg(feature = "avast")]
use crate::bindings::YR_OBJECT_REFERENCE;

/// Licenses of the third party packages
pub const LICENSES: &str = include_str!("../LICENSE-THIRD-PARTY");

macro_rules! YR_BITMASK_SIZE {
    ($n:expr) => {
        ($n + u64::BITS * 8 - 1) / (u64::BITS * 8)
    };
}

macro_rules! YR_AC_NEXT_STATE {
    ($t:expr) => {
        $t as isize >> 9
    };
}

#[derive(Debug)]
struct ModuleDataLinkedList {
    module: String,
    mapped_file: YR_MAPPED_FILE,
    next: Box<Option<ModuleDataLinkedList>>,
}

const RULE_FLAGS_NULL: i32 = 0x04;

impl YR_OBJECT_STRUCTURE {
    pub fn members(&self) -> YrStructureMemberIterator {
        YrStructureMemberIterator::new(self.members)
    }
}

pub fn object_type_to_string(object_type: i8) -> &'static str {
    match object_type {
        1 => "integer",
        2 => "string",
        3 => "structure",
        4 => "array",
        5 => "function",
        6 => "dictionary",
        7 => "float",
        8 => "reference",
        _ => unreachable!(),
    }
}

pub struct YrStructureMemberIterator {
    cur_member: *mut YR_STRUCTURE_MEMBER,
}

impl YrStructureMemberIterator {
    pub fn new(root: *mut YR_STRUCTURE_MEMBER) -> YrStructureMemberIterator {
        YrStructureMemberIterator { cur_member: root }
    }
}

impl Iterator for YrStructureMemberIterator {
    type Item = *mut YR_OBJECT;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            if self.cur_member.is_null() {
                None
            } else {
                let res = Some((*self.cur_member).object);
                // Advance to the next member
                self.cur_member = (*self.cur_member).next;
                res
            }
        }
    }
}

impl YR_DICT_ITERATOR {
    pub fn new(dict: *mut YR_OBJECT) -> YR_DICT_ITERATOR {
        YR_DICT_ITERATOR { dict, index: 0 }
    }
}

impl Iterator for YR_DICT_ITERATOR {
    type Item = (*mut SIZED_STRING, *mut YR_OBJECT);
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            let dict = *self.dict.cast::<YR_OBJECT_DICTIONARY>();
            let index = self.index as isize;

            if dict.items.is_null() || index >= (*dict.items).used as isize {
                None
            } else {
                let res = (*dict.items).objects.as_ptr().offset(index);
                let res = Some(((*res).key, (*res).obj));
                // Advance to the next member
                self.index = (index + 1) as i32;
                res
            }
        }
    }
}

impl Iterator for YR_ARRAY_ITERATOR {
    type Item = *mut YR_OBJECT;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            let obj = yr_object_array_get_item(self.array, 0, self.index);
            if obj.is_null() {
                None
            } else {
                self.index += 1;
                Some(obj)
            }
        }
    }
}

impl YR_OBJECT_ARRAY {
    fn members(&mut self) -> YR_ARRAY_ITERATOR {
        YR_ARRAY_ITERATOR {
            array: (self as *mut YR_OBJECT_ARRAY).cast::<YR_OBJECT>(),
            index: 0,
        }
    }
}

pub struct YrStringIterator {
    cur_member: *const YR_STRING,
}

impl YrStringIterator {
    pub fn new(root: *mut YR_STRING) -> YrStringIterator {
        YrStringIterator { cur_member: root }
    }
}

impl Iterator for YrStringIterator {
    type Item = *const YR_STRING;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            if self.cur_member.is_null() {
                None
            } else {
                let res = Some(self.cur_member);
                // Advance to the next member
                if (*self.cur_member).flags & 0x1000 != 0 {
                    self.cur_member = std::ptr::null();
                } else {
                    self.cur_member = self.cur_member.offset(1);
                }
                res
            }
        }
    }
}

/// # Safety
/// Caller must ensure that the block is a valid.
pub unsafe extern "C" fn _yr_fetch_block_data(block: *mut YR_MEMORY_BLOCK) -> *const u8 {
    (*block).context as *mut u8
}

/// # Safety
/// Caller must ensure that the iterator is a valid.
pub unsafe extern "C" fn _yr_get_first_block(
    iterator: *mut YR_MEMORY_BLOCK_ITERATOR,
) -> *mut YR_MEMORY_BLOCK {
    (*iterator).context.cast::<YR_MEMORY_BLOCK>()
}

/// # Safety
/// Caller must ensure that the iterator is a valid.
pub unsafe extern "C" fn _yr_get_next_block(
    _iterator: *mut YR_MEMORY_BLOCK_ITERATOR,
) -> *mut YR_MEMORY_BLOCK {
    ptr::null_mut::<YR_MEMORY_BLOCK>()
}

/// # Safety
/// Caller must ensure that the iterator is a valid.
pub unsafe extern "C" fn _yr_get_file_size(iterator: *mut YR_MEMORY_BLOCK_ITERATOR) -> u64 {
    (*((*iterator).context as *mut YR_MEMORY_BLOCK)).size
}

/// # Safety
/// Caller must ensure that the iterator is a valid.
pub unsafe extern "C" fn _yr_scanner_scan_mem_block(
    scanner: *mut YR_SCANNER,
    block_data: *const u8,
    block: *mut YR_MEMORY_BLOCK,
) {
    let block = *block;
    let rules = (*scanner).rules;
    let transition_table = (*rules).ac_transition_table;
    let match_table = (*rules).ac_match_table;
    let mut i = 0;
    let mut state = 0; // YR_AC_ROOT_STATE

    while i < block.size {
        if *match_table.offset(state) != 0 {
            let mut m = (*rules)
                .ac_match_pool
                .offset(*match_table.offset(state) as isize - 1);

            while !m.is_null() {
                if (*m).backtrack as u64 <= i {
                    yr_scan_verify_match(
                        scanner,
                        m,
                        block_data,
                        block.size,
                        block.base,
                        i - (*m).backtrack as u64,
                    );
                }
                m = (*m).__bindgen_anon_4.next;
            }
        }

        let index = *block_data.offset(i as isize) as isize + 1;
        i += 1;
        let mut transition = *transition_table.offset(state + index);

        while (transition & 0x1FF) != index as u32 {
            if state != 0 {
                state = YR_AC_NEXT_STATE!(*transition_table.offset(state));
                transition = *transition_table.offset(state + index);
            } else {
                transition = 0;
                break;
            }
        }
        state = YR_AC_NEXT_STATE!(transition);
    }

    if *match_table.offset(state) != 0 {
        let mut m = (*rules)
            .ac_match_pool
            .offset(*match_table.offset(state) as isize - 1);

        while !m.is_null() {
            if (*m).backtrack as u64 <= i {
                yr_scan_verify_match(
                    scanner,
                    m,
                    block_data,
                    block.size,
                    block.base,
                    i - (*m).backtrack as u64,
                );
            }
            m = (*m).__bindgen_anon_4.next;
        }
    }
}

extern "C" {
    pub fn yr_get_entry_point_offset(buffer: *const u8, buffer_length: usize) -> u64;
}

#[no_mangle]
pub extern "C" fn default_callback(
    context: *mut YR_SCAN_CONTEXT,
    message: i32,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    log::debug!(
        "Callback:\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}",
        context,
        message,
        message_data,
        user_data
    );

    match message as u32 {
        CALLBACK_MSG_IMPORT_MODULE => {
            let module_data_linked_list_ptr =
                dbg!(user_data.cast::<Option<ModuleDataLinkedList>>());
            let mut module_data_linked_list =
                dbg!(unsafe { module_data_linked_list_ptr.as_ref() }).unwrap();
            log::debug!("{:?}", module_data_linked_list);

            let module_import_ptr: *mut YR_MODULE_IMPORT = message_data.cast();
            let imported_module_cstr =
                dbg!(unsafe { CStr::from_ptr((*module_import_ptr).module_name) });
            let imported_module = imported_module_cstr.to_str().unwrap();

            while let Some(module_data) = module_data_linked_list {
                log::debug!("module_data {:?}", module_data);

                if imported_module == module_data.module {
                    unsafe {
                        (*module_import_ptr).module_data = module_data.mapped_file.data as *mut _;
                        (*module_import_ptr).module_data_size = module_data.mapped_file.size;
                    }
                    break;
                }
                module_data_linked_list = &module_data.next;
            }
        }
        _ => {}
    }
    ERROR_SUCCESS as i32
}

#[no_mangle]
pub extern "C" fn rule_match_callback(
    _context: *mut YR_SCAN_CONTEXT,
    message: i32,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    match message {
        1 => {
            // Match found
            let context = user_data.cast::<Context>();
            let rule = message_data.cast::<YR_RULE>();
            let rule_identifier = unsafe {
                CStr::from_ptr((*rule).__bindgen_anon_1.identifier)
                    .to_str()
                    .unwrap()
                    .to_string()
            };

            unsafe { (*context).rules_matching.push(rule_identifier) };
        }
        2 => {
            // No match found
            let context = user_data.cast::<Context>();
            let rule = message_data.cast::<YR_RULE>();
            let rule_identifier = unsafe {
                CStr::from_ptr((*rule).__bindgen_anon_1.identifier)
                    .to_str()
                    .unwrap()
                    .to_string()
            };

            unsafe { (*context).rules_not_matching.push(rule_identifier) };
        }
        _ => {}
    }
    0 // OK
}

/// YARA evaluation context.
///
/// ```
/// # use yari_sys::ContextBuilder;
/// # use yari_sys::YrValue;
/// let mut c = ContextBuilder::default().build().expect("Failed to create YARI context");
///
/// let val = c.eval("time.now()");
/// assert!(matches!(val, Ok(YrValue::Integer(_))));
/// ```
#[derive(Debug)]
pub struct Context {
    context: ManuallyDrop<Box<YR_SCAN_CONTEXT>>,
    compiler: *mut YR_COMPILER,
    modules: HashMap<Module, *mut YR_OBJECT_STRUCTURE>,
    module_data: HashMap<Module, String>,
    objects: HashMap<String, *mut YR_OBJECT>,
    /// Mapped files (used for dropping)
    yr_mapped_files: Vec<YR_MAPPED_FILE>,
    module_data_linked_list: Box<Option<ModuleDataLinkedList>>,
    rules_matching: Vec<String>,
    rules_not_matching: Vec<String>,

    iterator: Box<YR_MEMORY_BLOCK_ITERATOR>,
    block: Box<YR_MEMORY_BLOCK>,

    input: PathBuf,
    rule_string: Option<String>,
    fallback_scanner: *mut YR_SCANNER,
    use_fallback_eval: bool,
}

/// Builder to create a new YARA context.
#[derive(Debug, Default)]
pub struct ContextBuilder {
    rule_string: Option<String>,
    sample: Option<PathBuf>,
    module_data: HashMap<Module, PathBuf>,
}

impl ContextBuilder {
    /// Set builder to use `rule_string` as rule for context.
    ///
    /// If `None` is supplied, load bare context.
    pub fn with_rule_string<P: Into<String>>(mut self, rule_string: Option<P>) -> Self {
        self.rule_string = rule_string.map(|p| p.into());
        self
    }

    /// Set builder to use content of `rule_file` as rule for context.
    ///
    /// If `None` is supplied, load bare context.
    pub fn with_rule_file<P: Into<String>>(mut self, rule_file: Option<P>) -> Self {
        if let Some(rule_file) = rule_file {
            if let Ok(rule_string) = std::fs::read_to_string(rule_file.into()) {
                self.rule_string = Some(rule_string);
            }
        }
        self
    }

    /// Set builder to use `sample` as input.
    ///
    /// If `None` is supplied use /dev/null as sample.
    pub fn with_sample<P: Into<PathBuf>>(mut self, sample: Option<P>) -> Self {
        self.sample = sample.map(|p| p.into());
        self
    }

    /// Register a `module`, `data` pair with builder.
    pub fn with_module_data<P: AsRef<Path>>(mut self, module: Module, data: P) -> Self {
        self.module_data.insert(module, data.as_ref().to_owned());
        self
    }

    /// Parse the module data string.
    ///
    /// String format is expected in the same format as uses `yara` binary. That is following:
    /// `<module>=<data>` (e.g `cuckoo=sample_report.json`). Data is expected to be a valid path to
    /// a module data file.
    pub fn parse_module_data_str(data_string: &str) -> Option<(Module, String)> {
        let parts: Vec<&str> = data_string.split('=').collect();
        if parts.len() != 2 {
            return None;
        }

        let module = Module::from_str(parts[0]).ok()?;
        let data = parts[1];

        Some((module, data.to_owned()))
    }

    /// Consume builder and create new YARA context struct.
    pub fn build(self) -> Result<Context, YariError> {
        if let Some(sample) = &self.sample {
            if !sample.exists() {
                return Err(YariError::ContextBuilderError(format!(
                    "{:?} no such file",
                    sample
                )));
            }
        }

        let mut context = Context::new(self.sample, self.rule_string, false);

        for (module, data) in self.module_data {
            if !data.exists() {
                return Err(YariError::ContextBuilderError(format!(
                    "{:?} no such file",
                    data
                )));
            }
            context.with_module_data(module, data);
        }

        Ok(context)
    }
}

impl Context {
    pub fn new<P: AsRef<Path> + From<String>>(
        input: Option<P>,
        rule_string: Option<String>,
        use_fallback_eval: bool,
    ) -> Context {
        let input_file = input.unwrap_or_else(|| P::from("/dev/null".to_owned()));

        unsafe { yr_initialize() };

        let mut res = Context {
            context: ManuallyDrop::new(Box::new(YR_SCAN_CONTEXT::default())),
            compiler: ptr::null_mut(),
            modules: HashMap::new(),
            module_data: HashMap::new(),
            module_data_linked_list: Box::new(None),
            objects: HashMap::new(),
            yr_mapped_files: Vec::new(),
            rules_matching: Vec::new(),
            rules_not_matching: Vec::new(),
            iterator: Box::new(YR_MEMORY_BLOCK_ITERATOR::default()),
            block: Box::new(YR_MEMORY_BLOCK::default()),
            input: PathBuf::new(),
            rule_string: rule_string.clone(),
            use_fallback_eval,
            fallback_scanner: ptr::null_mut(),
        };

        unsafe {
            yr_scanner_set_callback(
                &mut **res.context,
                Some(default_callback),
                &mut *res.module_data_linked_list as *mut _ as *mut c_void,
            )
        };

        res.input.push(input_file.as_ref());

        unsafe {
            yr_compiler_create(&mut res.compiler as *mut *mut YR_COMPILER);

            res.iterator.context = &mut *res.context as *mut _ as *mut _;

            yr_hash_table_create(64, &mut (res.context.objects_table));

            res.context.rules = ptr::null_mut();
            res.context.entry_point = YR_UNDEFINED as u64;
            res.context.file_size = YR_UNDEFINED as u64;
            res.context.flags = 0;
            res.context.canary = 123;

            res.context.profiling_info = ptr::null_mut();

            let mfile = res.filemap(input_file);
            res.iterator_init(mfile.data, mfile.size);
            res.context.iterator = &mut *res.iterator;

            if let Some(rules_string) = rule_string {
                let rules_cstr = CString::new(rules_string).unwrap();
                if res.compile_string(&rules_cstr).is_ok() {
                    if use_fallback_eval {
                        yr_scanner_create(
                            res.context.rules,
                            &mut res.fallback_scanner as *mut *mut YR_SCANNER,
                        );
                        yr_scanner_set_callback(
                            res.fallback_scanner,
                            Some(rule_match_callback),
                            (&mut res as *mut Context).cast::<c_void>(),
                        );
                        yr_scanner_set_timeout(res.fallback_scanner, 0);
                        yr_scanner_set_flags(res.fallback_scanner, 8 | 16); // SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_REPORT_RULES_NOT_MATCHING
                        yr_scanner_scan_mem_blocks(res.fallback_scanner, res.iterator.as_mut());
                    } else {
                        res.setup_scanner();

                        let first_func = (*res.context.iterator).first.unwrap();
                        let block = first_func(res.context.iterator);

                        let fetch_data_func = (*block).fetch_data.expect("msg");
                        let data = fetch_data_func(block);

                        let mut max_match_data = 0_usize;
                        yr_get_configuration(
                            2, // YR_CONFIG_MAX_MATCH_DATA
                            (&mut max_match_data as *mut usize).cast::<c_void>(),
                        );
                        yr_notebook_create(
                            (1024 * (size_of::<YR_MATCH>() + max_match_data)) as u64,
                            &mut res.context.matches_notebook,
                        );

                        res.context.entry_point =
                            yr_get_entry_point_offset(data, (*block).size as usize);
                        _yr_scanner_scan_mem_block(&mut **res.context, data, block);
                    }
                }
            }
        }

        res
    }

    pub fn builder() -> ContextBuilder {
        ContextBuilder::default()
    }

    fn with_module_data<P: AsRef<Path>>(&mut self, module: Module, path: P) {
        self.module_data
            .insert(module, path.as_ref().to_str().unwrap().to_owned());

        debug!("Before: {:?}", self.module_data_linked_list);

        let mapped_file = self.filemap(path);

        let new_module_data = ModuleDataLinkedList {
            module: module.to_string(),
            mapped_file,
            next: Box::new(self.module_data_linked_list.take()),
        };

        self.module_data_linked_list = Box::new(Some(new_module_data));

        unsafe {
            yr_scanner_set_callback(
                &mut **self.context,
                Some(default_callback),
                &mut *self.module_data_linked_list as *mut _ as *mut c_void,
            )
        };

        debug!("After: {:?}", self.module_data_linked_list);
    }

    fn init_objects_cache(&mut self, structure: *mut YR_OBJECT_STRUCTURE) {
        self._init_objects_cache(structure.cast::<YR_OBJECT>(), "");
    }

    fn _init_objects_cache(&mut self, structure_ptr: *mut YR_OBJECT, root_path: &str) {
        let structure = unsafe { *structure_ptr };
        let identifier = unsafe {
            CStr::from_ptr(structure.identifier)
                .to_str()
                .expect("Invalid identifier data")
        };

        let path = if root_path.is_empty() {
            identifier.to_owned()
        } else {
            format!("{}.{}", root_path.to_owned(), identifier)
        };

        self._init_objects_cache_with_name(structure_ptr, &path)
    }

    fn _init_objects_cache_with_name(&mut self, structure_ptr: *mut YR_OBJECT, path: &String) {
        let structure = unsafe { *structure_ptr };
        self.objects.insert(path.clone(), structure_ptr);

        match structure.type_ as u32 {
            OBJECT_TYPE_ARRAY => {
                let mut arr = unsafe { *(structure_ptr as *mut YR_OBJECT_ARRAY) };
                for (i, s) in arr.members().enumerate() {
                    let path = format!("{}[{}]", path, i);
                    self._init_objects_cache_with_name(s, &path);
                }
            }
            OBJECT_TYPE_DICTIONARY => {
                for (key, s) in YR_DICT_ITERATOR::new(structure_ptr) {
                    let key = unsafe { CStr::from_ptr((*key).c_string.as_ptr()) };
                    let path = format!("{}[\"{}\"]", path, key.to_str().unwrap());

                    self._init_objects_cache_with_name(s, &path);
                }
            }
            OBJECT_TYPE_STRUCTURE => {
                let structure = structure_ptr.cast::<YR_OBJECT_STRUCTURE>();
                let structure = unsafe { *structure };

                for s in structure.members() {
                    self._init_objects_cache(s, path);
                }
            }
            _ => {}
        }
    }

    /// Import and initialize `module`.
    fn import_module(&mut self, module: Module) {
        if self.modules.contains_key(&module) {
            return;
        }

        debug!("Importing module {:?}", module);

        let module_name = CString::new(module.as_ref()).expect("Invalid string");
        let _res = unsafe { yr_modules_load(module_name.as_ptr(), &mut **self.context) };

        let new_module: *mut YR_OBJECT_STRUCTURE = unsafe {
            yr_hash_table_lookup(
                self.context.objects_table,
                module_name.as_ptr(),
                ptr::null(),
            )
        }
        .cast();

        self.modules.insert(module, new_module);
        self.init_objects_cache(new_module);
    }

    pub fn get_object(&self, path: &str) -> Option<&*mut YR_OBJECT> {
        self.objects.get(path)
    }

    /// Convert an integer to a new allocated YR_VALUE
    fn i_from_int(&self, i: &i64) -> YR_VALUE {
        // Allocate a new YR_VALUE
        let ptr = Box::leak(Box::new(YR_VALUE::default()));

        // Set the value
        ptr.i = *i;

        *ptr
    }

    fn str_from_str(&self, s: &str) -> YR_VALUE {
        // let c_string = CString::new(s).expect("Cannot convert value to CString");
        let struct_size = Layout::new::<SIZED_STRING>();
        let data_size = Layout::array::<i8>(s.len() + 1).unwrap();
        let (layout, _) = struct_size.extend(data_size).unwrap();

        let sized_string = unsafe { alloc(layout).cast::<SIZED_STRING>() };

        unsafe {
            (*sized_string).length = s.len() as u32;
            (*sized_string).flags = 0;
        };

        // Copy the string
        for (i, c) in s.bytes().enumerate() {
            unsafe { (*sized_string).c_string.as_mut_ptr().add(i).write(c as i8) };
        }

        // Write NULL byte
        unsafe { (*sized_string).c_string.as_mut_ptr().add(s.len()).write(0) };

        YR_VALUE { ss: sized_string }
    }

    fn yr_value_from_argument(&self, arg: &Argument) -> YR_VALUE {
        match arg {
            Argument::Regexp(r, m) => self.re_from_str(r, m),
            Argument::Integer(i) => self.i_from_int(i),
            Argument::Float(_f) => unimplemented!(),
            Argument::String(s) => self.str_from_str(s),
        }
    }

    /// Convert the regexp modifiers string to bitflags used by YARA.
    ///
    /// Values in this functions are from YARA sources (`libyara/include/yara/re.h`).
    ///
    /// ```rust
    /// # use yari_sys::Context;
    /// assert_eq!(Context::re_flags_from_modifier_string(""), 0);
    /// assert_eq!(Context::re_flags_from_modifier_string("i"), 0x20);
    /// assert_eq!(Context::re_flags_from_modifier_string("s"), 0x80);
    /// ```
    pub fn re_flags_from_modifier_string(modifiers: &str) -> i32 {
        let mut flags = 0;

        // no case
        if modifiers.contains('i') {
            flags |= 0x20;
        }

        // dot all
        if modifiers.contains('s') {
            flags |= 0x80;
        }

        flags
    }

    /// Convert a string to a new allocated YR_VALUE regexp
    fn re_from_str(&self, value: &str, modifiers: &str) -> YR_VALUE {
        let flags = Context::re_flags_from_modifier_string(modifiers);
        let c_value = CString::new(value).expect("Cannot convert value to CString");
        let mut arena_ref: YR_ARENA_REF = YR_ARENA_REF::default();
        let mut error: RE_ERROR = RE_ERROR::default();
        unsafe {
            yr_re_compile(
                c_value.as_ptr(),
                flags,
                (*self.compiler).arena,
                &mut arena_ref as *mut YR_ARENA_REF,
                &mut error as *mut RE_ERROR,
            );
        }

        // Get void* pointer to RE structure
        let re_ptr = unsafe {
            yr_arena_ref_to_ptr((*self.compiler).arena, &mut arena_ref as *mut YR_ARENA_REF)
        };

        // Cast it to correct pointer type
        let re_ptr = re_ptr.cast::<RE>();

        // Wrap it in the YR_VALUE
        YR_VALUE { re: re_ptr }
    }

    fn collect_arguments(&self, str_args: Vec<Argument>) -> *mut YR_VALUE {
        if str_args.is_empty() {
            return ptr::null_mut();
        }

        // Allocate argument array
        let mut args: Vec<YR_VALUE> = Vec::with_capacity(str_args.len());

        for arg in str_args {
            args.push(self.yr_value_from_argument(&arg));
        }

        // Convert to C array
        args.leak().as_mut_ptr()
    }

    pub fn call_function_with_args(
        &mut self,
        name: &str,
        args: Vec<Argument>,
    ) -> Result<*const YR_OBJECT, YariError> {
        debug!("Calling function {:?} with args {:?}", name, args);
        let obj_ref = self
            .objects
            .get_mut(name)
            .ok_or_else(|| YariError::SymbolNotFound(name.to_string()))?;

        let obj_ptr = *obj_ref;

        if unsafe { (*obj_ptr).type_ } != OBJECT_TYPE_FUNCTION as i8 {
            return Err(YariError::SymbolNotFound(name.to_string()));
        };

        let func_ptr = obj_ptr.cast::<YR_OBJECT_FUNCTION>();
        let func = unsafe { *func_ptr };

        let mut arguments_fmt = String::with_capacity(args.len());

        for arg in &args {
            arguments_fmt.push(arg.to_char());
        }
        let eval_args_c_string = CString::new(arguments_fmt).unwrap();

        for i in 0..YR_MAX_OVERLOADED_FUNCTIONS {
            let prototype = func.prototypes[i as usize];
            if prototype.arguments_fmt.is_null() {
                break;
            }

            let arg_str = unsafe { CStr::from_ptr(prototype.arguments_fmt) };

            if eval_args_c_string.as_c_str() == arg_str {
                let yr_args = self.collect_arguments(args);
                let func_code = prototype.code.expect("No function assigned");
                unsafe {
                    func_code(yr_args, &mut **self.context, func_ptr);
                };
                return Ok(func.return_obj);
            }
        }

        Err(YariError::SymbolNotFound(name.to_string()))
    }

    unsafe fn return_obj_if_type_ok(
        &mut self,
        obj: *const YR_OBJECT,
    ) -> Result<*const YR_OBJECT, YariError> {
        match (*obj).type_ as u32 {
            OBJECT_TYPE_STRING
            | OBJECT_TYPE_INTEGER
            | OBJECT_TYPE_FLOAT
            | OBJECT_TYPE_DICTIONARY
            | OBJECT_TYPE_ARRAY => Ok(obj),
            #[cfg(feature = "avast")]
            OBJECT_TYPE_REFERENCE => Ok(obj),
            _ => Err(YariError::EvalError),
        }
    }

    #[cfg(feature = "avast")]
    fn find_key_for_object(&self, value: *mut YR_OBJECT) -> Option<String> {
        self.objects.iter().find_map(|(key, &val)| {
            if val == value {
                Some(key.clone())
            } else {
                None
            }
        })
    }

    pub fn get_value(&mut self, name: &str) -> Result<*const YR_OBJECT, YariError> {
        debug!("Getting the value of {:?}", name);
        #[allow(unused_mut)]
        let mut name = name.to_string();
        #[allow(unused_mut)]
        let mut obj_ptr = self.get_object(&name);

        #[cfg(feature = "avast")]
        while let None = obj_ptr {
            let mut ref_found = false;
            for (i, _) in name.match_indices('.') {
                let ref_name = name[0..i].to_string().clone();
                let ref_ptr = self.get_object(&ref_name);

                if let Some(&ref_ptr) = ref_ptr {
                    if (unsafe { *ref_ptr }).type_ as u32 == OBJECT_TYPE_REFERENCE {
                        ref_found = true;
                        let ref_obj = unsafe { *ref_ptr.cast::<YR_OBJECT_REFERENCE>() };
                        let target_name = self
                            .find_key_for_object(ref_obj.target_obj)
                            .ok_or(YariError::EvalError)?;
                        name = name.replacen(&ref_name, &target_name, 1);
                        break;
                    }
                }
            }

            if ref_found {
                obj_ptr = self.get_object(&name);
            } else {
                // No reference found, which means that if the object has already not been found, it's not there
                break;
            }
        }

        let obj_ptr = *obj_ptr.ok_or_else(|| YariError::SymbolNotFound(name.to_string()))?;
        unsafe { self.return_obj_if_type_ok(obj_ptr) }
    }

    fn get_matching_string(
        &mut self,
        rule: YR_RULE,
        prefix: &str,
    ) -> Result<*const YR_STRING, YariError> {
        let prefix = CString::new(prefix).unwrap();
        let strings_table = unsafe { rule.__bindgen_anon_4.strings };

        for s in YrStringIterator::new(strings_table) {
            let mut prefix_ptr = prefix.as_ptr();

            unsafe {
                let mut identifier = (*s).__bindgen_anon_3.identifier.offset(1);
                while *identifier != '\0' as i8
                    && *prefix_ptr != '\0' as i8
                    && *identifier == *prefix_ptr
                {
                    identifier = identifier.offset(1);
                    prefix_ptr = prefix_ptr.offset(1);
                }

                if (*identifier == '\0' as i8 && *prefix_ptr == '\0' as i8)
                    || *prefix_ptr == '*' as i8
                {
                    return Ok(s);
                }
            }
        }
        Err(YariError::UndeclaredStringError)
    }

    pub fn get_string(
        &mut self,
        rule: YR_RULE,
        op: StrOperation,
        prefix: &str,
        index: Option<i64>,
    ) -> Result<YR_OBJECT, YariError> {
        debug!("Getting the value of string {:?}", prefix);
        let mut obj = YR_OBJECT::default();

        let string = self.get_matching_string(rule, prefix)?;
        let matches = unsafe { *self.context.matches.offset((*string).idx as isize) };

        let val = match op {
            StrOperation::MatchesOnce => Ok(!matches.tail.is_null() as i64),
            StrOperation::MatchesCount => {
                let mut cnt = 0;
                let mut m = matches.head;
                while !m.is_null() {
                    cnt += 1;
                    m = unsafe { (*m).next };
                }
                Ok(cnt)
            }
            StrOperation::MatchOffset => {
                let mut cnt = 0;
                let mut index_found = false;
                let mut offset = 0;
                let mut m = matches.head;
                while !m.is_null() {
                    cnt += 1;

                    if cnt == index.unwrap() {
                        index_found = true;
                        offset = unsafe { (*m).offset };
                        break;
                    }

                    m = unsafe { (*m).next };
                }

                if index_found {
                    Ok(offset)
                } else {
                    Err(YariError::IndexOutOfBounds)
                }
            }
            StrOperation::MatchLength => {
                let mut cnt = 0;
                let mut index_found = false;
                let mut match_length = 0;
                let mut m = matches.head;
                while !m.is_null() {
                    cnt += 1;

                    if cnt == index.unwrap() {
                        index_found = true;
                        match_length = unsafe { (*m).match_length as i64 };
                        break;
                    }

                    m = unsafe { (*m).next };
                }

                if index_found {
                    Ok(match_length)
                } else {
                    Err(YariError::IndexOutOfBounds)
                }
            }
        }?;
        obj.type_ = OBJECT_TYPE_INTEGER as i8;
        obj.value = YR_VALUE { i: val };
        Ok(obj)
    }

    fn get_rule_context(
        &mut self,
        rule_name: Option<&str>,
    ) -> Result<(Option<isize>, Option<YR_RULE>), YariError> {
        let mut rule_ctx = (None, None);
        if let Some(rule_name) = rule_name {
            if self.context.rules.is_null() {
                return Err(YariError::RuleMissingError);
            }

            let rules = unsafe { *self.context.rules };

            #[cfg(not(feature = "avast"))]
            let rules_table = unsafe { rules.__bindgen_anon_1.rules_table };
            #[cfg(feature = "avast")]
            let rules_table = rules.rules_table;

            let mut i = 0_isize;
            while (unsafe { *rules_table.offset(i) }).flags != RULE_FLAGS_NULL {
                let r = unsafe { *rules_table.offset(i) };
                let curr_rule_name = unsafe { CStr::from_ptr(r.__bindgen_anon_1.identifier) }
                    .to_str()
                    .unwrap();

                if curr_rule_name == rule_name {
                    rule_ctx = (Some(i), Some(r));
                    break;
                }

                i += 1;
            }
        }
        Ok(rule_ctx)
    }

    pub fn eval(&mut self, str_expr: &str) -> Result<YrValue, YariError> {
        debug!("Evaluating expression {:?}", str_expr);

        let (rule_name, expr) = parse(str_expr)?;
        debug!("Parsed expression {:?}", expr);

        // Import module used in expression
        let expr_module = expr.get_module();
        if let Some(module) = expr_module {
            self.import_module(module);
        }

        let rule_ctx = self.get_rule_context(rule_name)?;

        match expr {
            Expression::Function { name, args } => {
                let obj = self.call_function_with_args(name, args)?;
                Ok(unsafe { YrValue::from(obj) })
            }
            Expression::Value(name) => {
                if !self.use_fallback_eval {
                    // Try to evaluate expression using YARI
                    let obj = self.get_value(name);
                    if let Ok(obj) = obj {
                        Ok(unsafe { YrValue::from(obj) })
                    } else if let Some(rule_name) = rule_name {
                        // YARI evaluation failed, try fallback evaluation
                        let rules_text = expression_to_rules_with_condition(
                            self.rule_string
                                .as_ref()
                                .ok_or(YariError::RuleMissingError)?,
                            rule_name,
                            name,
                        )?;
                        Context::new(Some(self.input.clone()), Some(rules_text), true)
                            .eval(rule_name)
                    } else {
                        // Fallback evaluation without rule context, typically called when `name` is rule name itself
                        Context::new(Some(self.input.clone()), self.rule_string.clone(), true)
                            .eval(name)
                    }
                } else {
                    // Evaluation using fallback scanner
                    let mut obj = YR_OBJECT::default();
                    let mut obj_ptr = ptr::null::<YR_OBJECT>();

                    // Search for variables
                    #[cfg(feature = "avast")]
                    if let Some(idx) = rule_ctx.0 {
                        obj_ptr = unsafe {
                            let name = CString::new(name).unwrap();
                            yr_hash_table_lookup(
                                *(*self.fallback_scanner)
                                    .internal_variable_tables
                                    .offset(idx),
                                name.as_ptr(),
                                ptr::null(),
                            )
                        }
                        .cast::<YR_OBJECT>();
                    }

                    if obj_ptr.is_null() {
                        let rule_matching = self.rules_matching.contains(&name.to_string());
                        let rule_not_matching = self.rules_not_matching.contains(&name.to_string());

                        if rule_matching || rule_not_matching {
                            obj.type_ = OBJECT_TYPE_INTEGER as i8;
                            obj.value.i = rule_matching as i64;
                            obj_ptr = &obj;
                        }
                    }

                    if !obj_ptr.is_null() {
                        Ok(unsafe { YrValue::from(obj_ptr) })
                    } else {
                        Err(YariError::SymbolNotFound(name.to_string()))
                    }
                }
            }
            Expression::String {
                operator,
                prefix,
                index,
            } => {
                let obj = self.get_string(
                    rule_ctx.1.ok_or(YariError::RuleMissingError)?,
                    operator,
                    prefix,
                    index,
                )?;
                Ok(unsafe { YrValue::from(&obj) })
            }
            Expression::Complex(value) => {
                debug!(
                    "Evaluating expression {:?} using fallback YARA evaluation..",
                    str_expr
                );

                if self.use_fallback_eval {
                    // This should never happen.
                    // Complex expression can be sent to eval() only with fallback evaluation disabled.
                    // Then, the complex expression part gets chopped off and a Complex expression becomes a Value.
                    return Err(YariError::EvalError);
                }

                if let Some(rule_name) = rule_name {
                    // Extract expression into rule condition and call fallback evaluation.
                    // TODO: if ruleset is not present, try to generate a new rule
                    let rules_text = expression_to_rules_with_condition(
                        self.rule_string
                            .as_ref()
                            .ok_or(YariError::RuleMissingError)?,
                        rule_name,
                        value,
                    )?;
                    Context::new(Some(self.input.clone()), Some(rules_text), true).eval(rule_name)
                } else {
                    Err(YariError::RuleMissingError)
                }
            }
        }
    }

    fn filemap<P: AsRef<Path>>(&mut self, filename: P) -> YR_MAPPED_FILE {
        let filename_string = CString::new(filename.as_ref().to_str().expect("Invalid file name"))
            .expect("Invalid file name");

        // Push and get the last value
        self.yr_mapped_files.push(YR_MAPPED_FILE::default());
        let mfile = self.yr_mapped_files.last_mut().unwrap();

        unsafe {
            yr_filemap_map(filename_string.as_ptr(), &mut *mfile);
            *mfile
        }
    }

    fn iterator_init(&mut self, buffer: *const u8, buffer_size: u64) {
        self.block.size = buffer_size;
        self.block.base = 0;
        self.block.fetch_data = Some(_yr_fetch_block_data);
        self.block.context = buffer as *mut c_void;

        self.iterator.context = &mut *self.block as *mut _ as *mut _;
        self.iterator.first = Some(_yr_get_first_block);
        self.iterator.next = Some(_yr_get_next_block);
        self.iterator.file_size = Some(_yr_get_file_size);
    }

    unsafe fn compile_string(&mut self, rule_cstr: &CString) -> Result<(), YariError> {
        if yr_compiler_add_string(self.compiler, rule_cstr.as_ptr(), ptr::null())
            != ERROR_SUCCESS as i32
        {
            return Err(YariError::ParserError);
        }

        if yr_compiler_get_rules(self.compiler, &mut self.context.rules) != ERROR_SUCCESS as i32 {
            return Err(YariError::Unknown);
        }
        Ok(())
    }

    unsafe fn setup_scanner(&mut self) {
        self.context.rule_matches_flags = yr_calloc(
            size_of::<u64>() as u64,
            YR_BITMASK_SIZE!((*self.context.rules).num_rules) as u64,
        ) as *mut std::os::raw::c_ulong;

        self.context.ns_unsatisfied_flags = yr_calloc(
            size_of::<u64>() as u64,
            YR_BITMASK_SIZE!((*self.context.rules).num_namespaces) as u64,
        ) as *mut std::os::raw::c_ulong;

        self.context.strings_temp_disabled = yr_calloc(
            size_of::<u64>() as u64,
            YR_BITMASK_SIZE!((*self.context.rules).num_strings) as u64,
        ) as *mut std::os::raw::c_ulong;

        self.context.matches = yr_calloc(
            (*self.context.rules).num_strings as u64,
            size_of::<YR_MATCHES>() as u64,
        ) as *mut YR_MATCHES;

        self.context.unconfirmed_matches = yr_calloc(
            (*self.context.rules).num_strings as u64,
            size_of::<YR_MATCHES>() as u64,
        ) as *mut YR_MATCHES;
    }

    pub fn dump_module(&mut self, module: Module) {
        self.import_module(module);
        match self.modules.get(&module) {
            Some(module) => {
                self.visit_structure(module.cast::<YR_OBJECT>(), 0);
            }
            None => error!("Module '{}' not found", module),
        }
    }

    fn visit_structure(&self, structure_ptr: *const YR_OBJECT, depth: usize) {
        let identifier = unsafe { CStr::from_ptr((*structure_ptr).identifier) };
        self.visit_structure_with_name(identifier, structure_ptr, depth)
    }

    fn visit_structure_with_name(
        &self,
        identifier: &CStr,
        structure_ptr: *const YR_OBJECT,
        depth: usize,
    ) {
        let structure = unsafe { *structure_ptr };

        match structure.type_ as u32 {
            OBJECT_TYPE_INTEGER => {
                let value = unsafe { structure.value.i };

                if value == YR_UNDEFINED {
                    println!("{}{:?} = YR_UNDEFINED", "\t".repeat(depth), identifier,);
                } else {
                    println!("{}{:?} = {:#x}", "\t".repeat(depth), identifier, value);
                }
            }
            OBJECT_TYPE_FUNCTION => {
                let function = unsafe {
                    let function_ptr: *mut YR_OBJECT_FUNCTION = structure_ptr as *mut _;

                    *function_ptr
                };

                let ret = unsafe { object_type_to_string((*function.return_obj).type_) };

                for i in 0..YR_MAX_OVERLOADED_FUNCTIONS {
                    let prototype = function.prototypes[i as usize];
                    if prototype.arguments_fmt.is_null() {
                        break;
                    }
                    let arguments = unsafe { CStr::from_ptr(prototype.arguments_fmt) };
                    println!(
                        "{}{:?}({:#?}) -> {}",
                        "\t".repeat(depth),
                        identifier,
                        arguments,
                        ret
                    );
                }
            }
            OBJECT_TYPE_ARRAY => {
                println!("{}[A] {:?}", "\t".repeat(depth), identifier);
                let mut arr = unsafe { *(structure_ptr as *mut YR_OBJECT_ARRAY) };
                for (i, s) in arr.members().enumerate() {
                    let key = CString::new(format!("[{}]", i)).unwrap();
                    self.visit_structure_with_name(&key, s, depth + 1);
                }
            }
            OBJECT_TYPE_DICTIONARY => {
                println!("{}[D] {:?}", "\t".repeat(depth), identifier);
                for (key, object) in YR_DICT_ITERATOR::new(structure_ptr as *mut YR_OBJECT) {
                    let key = unsafe { CStr::from_ptr((*key).c_string.as_ptr()) };
                    self.visit_structure_with_name(key, object, depth + 1);
                }
            }
            OBJECT_TYPE_STRUCTURE => {
                let structure = structure_ptr as *mut YR_OBJECT_STRUCTURE;
                let structure = unsafe { *structure };

                println!("{}[S] {:?}", "\t".repeat(depth), identifier);
                for s in structure.members() {
                    self.visit_structure(s, depth + 1);
                }
            }
            OBJECT_TYPE_STRING => {
                let string = unsafe { YrValue::from(structure_ptr) };
                let value = if let YrValue::String(Some(s)) = string {
                    s
                } else if let YrValue::String(None) = string {
                    "NULL".to_string()
                } else {
                    panic!("Could not extract string from object")
                };
                println!("{}[STR] {:?} = {}", "\t".repeat(depth), identifier, value);
            }
            #[cfg(feature = "avast")]
            OBJECT_TYPE_REFERENCE => {
                let structure = unsafe { *(structure_ptr as *mut YR_OBJECT_REFERENCE) };

                let mut target_obj_identifier = "NULL";
                if !structure.target_obj.is_null() {
                    let target_obj = unsafe { *structure.target_obj };
                    target_obj_identifier =
                        unsafe { CStr::from_ptr(target_obj.identifier).to_str().unwrap() };
                }

                println!(
                    "{}[REF] {:?} reference to {}",
                    "\t".repeat(depth),
                    identifier,
                    target_obj_identifier
                );
            }
            _ => {
                println!(
                    "{}[U] {:?} with type '{}'",
                    "\t".repeat(depth),
                    identifier,
                    object_type_to_string(structure.type_)
                );
            }
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        debug!("Dropping context");

        let rules = self.context.rules;

        if !self.context.matches_notebook.is_null() {
            unsafe {
                yr_notebook_destroy(self.context.matches_notebook);
            }
        }

        // Drop all created filemaps (this should close all opened FDs)
        for file in self.yr_mapped_files.iter_mut() {
            unsafe { yr_filemap_unmap(file) };
        }

        unsafe { yr_compiler_destroy(self.compiler) };

        if !self.fallback_scanner.is_null() {
            unsafe { yr_scanner_destroy(self.fallback_scanner) };
        }

        #[allow(clippy::if_same_then_else)]
        if self.use_fallback_eval {
            #[cfg(not(target_os = "windows"))]
            unsafe {
                yr_scanner_destroy(&mut **self.context)
            };
        } else {
            unsafe { yr_scanner_destroy(&mut **self.context) };
        }

        if !rules.is_null() {
            unsafe { yr_rules_destroy(rules) };
        }

        unsafe { yr_finalize() };
    }
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}
