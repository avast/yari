use crate::bindings::OBJECT_TYPE_ARRAY;
use crate::bindings::OBJECT_TYPE_DICTIONARY;
use crate::bindings::OBJECT_TYPE_FLOAT;
use crate::bindings::OBJECT_TYPE_INTEGER;
use crate::bindings::OBJECT_TYPE_STRING;
use crate::bindings::OBJECT_TYPE_STRUCTURE;
use crate::bindings::SIZED_STRING;
use crate::bindings::YR_DICT_ITERATOR;
use crate::bindings::YR_OBJECT;
use crate::bindings::YR_OBJECT_ARRAY;
use crate::bindings::YR_OBJECT_STRUCTURE;
use crate::error::YariError;
use std::collections::HashMap;
use std::ffi::CStr;

/// Result of evalutaion.
#[derive(Debug, PartialEq)]
pub enum YrValue {
    Integer(i64),
    Float(f64),
    String(String),
    Dictionary(HashMap<String, YrValue>),
    Array(Vec<YrValue>),
    Structure(HashMap<String, YrValue>),
}

impl YrValue {
    fn sized_string_to_string(ss: *const SIZED_STRING) -> String {
        let string_slice_i8 = unsafe { (*ss).c_string.as_slice((*ss).length as usize) };
        let string_slice_u8 = unsafe { &*(string_slice_i8 as *const _ as *const [u8]) };
        string_slice_u8
            .iter()
            .map(|c| std::ascii::escape_default(*c).to_string())
            .collect::<Vec<_>>()
            .join("")
    }

    /// # Safety
    /// Caller must ensure that the block is a valid.
    pub(crate) unsafe fn from(object: *const YR_OBJECT) -> Self {
        match (*object).type_ as u32 {
            OBJECT_TYPE_STRING => {
                let sized_string_ptr = (*object).value.ss;
                if sized_string_ptr.is_null() {
                    // TODO: This should be YR_UNDEFINED string, handle it better
                    YrValue::String("".to_string())
                } else {
                    let owned_string = YrValue::sized_string_to_string((*object).value.ss);
                    YrValue::String(owned_string)
                }
            }
            OBJECT_TYPE_FLOAT => YrValue::Float((*object).value.d),
            OBJECT_TYPE_INTEGER => YrValue::Integer((*object).value.i),
            OBJECT_TYPE_DICTIONARY => {
                let mut map = HashMap::new();
                let iter = YR_DICT_ITERATOR::new(object as *mut YR_OBJECT);

                for (key, obj_ptr) in iter {
                    let key_string = YrValue::sized_string_to_string(key);
                    map.insert(key_string, YrValue::from(obj_ptr));
                }

                YrValue::Dictionary(map)
            }
            OBJECT_TYPE_ARRAY => {
                let mut vec = Vec::new();
                let arr = object as *mut YR_OBJECT_ARRAY;

                for obj in (*arr).members() {
                    if obj.is_null() {
                        continue;
                    }

                    vec.push(YrValue::from(obj));
                }

                YrValue::Array(vec)
            }
            OBJECT_TYPE_STRUCTURE => {
                let mut map = HashMap::new();
                let structure = object.cast::<YR_OBJECT_STRUCTURE>();

                for obj in (*structure).members() {
                    let key_string = CStr::from_ptr((*obj).identifier)
                        .to_str()
                        .unwrap()
                        .to_string();
                    map.insert(key_string, YrValue::from(obj));
                }

                YrValue::Structure(map)
            }
            _ => unreachable!(),
        }
    }
}

impl TryFrom<YrValue> for bool {
    type Error = YariError;

    /// ```rust
    /// # use yari_sys::YrValue;
    /// use std::collections::HashMap;
    ///
    /// assert!(bool::try_from(YrValue::Integer(1)).unwrap());
    /// assert!(!bool::try_from(YrValue::Integer(0)).unwrap());
    ///
    /// assert!(bool::try_from(YrValue::Float(1.1)).unwrap());
    /// assert!(!bool::try_from(YrValue::Float(0.0)).unwrap());
    ///
    /// assert!(bool::try_from(YrValue::String("not empty".to_string())).unwrap());
    /// assert!(!bool::try_from(YrValue::String("".to_string())).unwrap());
    ///
    /// assert!(bool::try_from(YrValue::Dictionary(HashMap::new())).is_err());
    /// assert!(bool::try_from(YrValue::Array(Vec::new())).is_err());
    /// assert!(bool::try_from(YrValue::Structure(HashMap::new())).is_err());
    /// ```
    fn try_from(value: YrValue) -> Result<Self, Self::Error> {
        match value {
            YrValue::Integer(i) => Ok(i != 0),
            YrValue::Float(f) => Ok(f != 0f64),
            YrValue::String(s) => Ok(!s.is_empty()),
            YrValue::Dictionary(_) => Err(YariError::BoolConversionError),
            YrValue::Array(_) => Err(YariError::BoolConversionError),
            YrValue::Structure(_) => Err(YariError::BoolConversionError),
        }
    }
}
