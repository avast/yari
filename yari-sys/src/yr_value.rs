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
use crate::bindings::YR_UNDEFINED;
use crate::error::YariError;
use std::collections::HashMap;
use std::ffi::CStr;

#[cfg(feature = "avast")]
use crate::bindings::OBJECT_TYPE_REFERENCE;

#[cfg(feature = "avast")]
use crate::bindings::YR_OBJECT_REFERENCE;

/// Result of evalutaion.
#[derive(Debug, PartialEq)]
pub enum YrValue {
    Integer(i64),
    Float(f64),
    String(Option<String>),
    Dictionary(HashMap<String, YrValue>),
    Array(Vec<YrValue>),
    Structure(Option<HashMap<String, YrValue>>),
}

impl YrValue {
    /// Check if the `YrValue` is considered undefined.
    ///
    /// ```rust
    /// # use yari_sys::YrValue;
    /// use std::collections::HashMap;
    /// use yari_sys::YR_UNDEFINED;
    ///
    /// assert!(!YrValue::Integer(1).is_undefined());
    /// assert!(!YrValue::Integer(0).is_undefined());
    /// assert!(YrValue::Integer(YR_UNDEFINED).is_undefined());
    ///
    /// assert!(!YrValue::Float(1.234).is_undefined());
    /// assert!(!YrValue::Float(0.0).is_undefined());
    /// assert!(YrValue::Float(f64::NAN).is_undefined());
    ///
    /// assert!(!YrValue::String(Some("not empty".to_string())).is_undefined());
    /// assert!(!YrValue::String(Some("".to_string())).is_undefined());
    /// assert!(YrValue::String(None).is_undefined());
    ///
    /// assert!(!YrValue::Dictionary(HashMap::new()).is_undefined());
    /// assert!(!YrValue::Array(Vec::new()).is_undefined());
    ///
    /// assert!(!YrValue::Structure(Some(HashMap::new())).is_undefined());
    /// assert!(YrValue::Structure(None).is_undefined());
    /// ```
    pub fn is_undefined(&self) -> bool {
        match self {
            YrValue::Integer(i) => *i == YR_UNDEFINED,
            YrValue::Float(f) => f.is_nan(),
            YrValue::String(s) => s.is_none(),
            YrValue::Dictionary(_) => false,
            YrValue::Array(_) => false,
            YrValue::Structure(s) => s.is_none(),
        }
    }

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
    unsafe fn from_inner(object: *const YR_OBJECT, include_references: bool) -> Self {
        match (*object).type_ as u32 {
            OBJECT_TYPE_STRING => {
                let sized_string_ptr = (*object).value.ss;
                if sized_string_ptr.is_null() {
                    YrValue::String(None)
                } else {
                    let owned_string = YrValue::sized_string_to_string((*object).value.ss);
                    YrValue::String(Some(owned_string))
                }
            }
            OBJECT_TYPE_FLOAT => YrValue::Float((*object).value.d),
            OBJECT_TYPE_INTEGER => YrValue::Integer((*object).value.i),
            OBJECT_TYPE_DICTIONARY => {
                let mut map = HashMap::new();
                let iter = YR_DICT_ITERATOR::new(object as *mut YR_OBJECT);

                for (key, obj_ptr) in iter {
                    let key_string = YrValue::sized_string_to_string(key);
                    map.insert(key_string, YrValue::from_inner(obj_ptr, include_references));
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

                    vec.push(YrValue::from_inner(obj, include_references));
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
                    map.insert(key_string, YrValue::from_inner(obj, include_references));
                }

                YrValue::Structure(Some(map))
            }
            #[cfg(feature = "avast")]
            OBJECT_TYPE_REFERENCE => {
                let target_ptr = (*object.cast::<YR_OBJECT_REFERENCE>()).target_obj;
                if target_ptr.is_null() || !include_references {
                    YrValue::Structure(None)
                } else {
                    // References allow circular dependencies. To avoid that, make unpacking references down the hierarchy illegal.
                    YrValue::from_inner(target_ptr, false)
                }
            }
            _ => unreachable!(),
        }
    }

    pub(crate) unsafe fn from(object: *const YR_OBJECT) -> Self {
        YrValue::from_inner(object, true)
    }
}

impl TryFrom<YrValue> for bool {
    type Error = YariError;

    /// ```rust
    /// # use yari_sys::YrValue;
    /// use yari_sys::YR_UNDEFINED;
    /// use std::collections::HashMap;
    ///
    /// assert!(bool::try_from(YrValue::Integer(1)).unwrap());
    /// assert!(!bool::try_from(YrValue::Integer(0)).unwrap());
    /// assert!(!bool::try_from(YrValue::Integer(YR_UNDEFINED)).unwrap());
    ///
    /// assert!(bool::try_from(YrValue::Float(1.1)).unwrap());
    /// assert!(!bool::try_from(YrValue::Float(0.0)).unwrap());
    /// assert!(!bool::try_from(YrValue::Float(f64::NAN)).unwrap());
    ///
    /// assert!(bool::try_from(YrValue::String(Some("not empty".to_string()))).unwrap());
    /// assert!(!bool::try_from(YrValue::String(Some("".to_string()))).unwrap());
    /// assert!(!bool::try_from(YrValue::String(None)).unwrap());
    ///
    /// assert!(bool::try_from(YrValue::Dictionary(HashMap::new())).is_err());
    /// assert!(bool::try_from(YrValue::Array(Vec::new())).is_err());
    /// 
    /// assert!(!bool::try_from(YrValue::Structure(None)).unwrap());
    /// assert!(bool::try_from(YrValue::Structure(Some(HashMap::new()))).unwrap());
    /// ```
    fn try_from(value: YrValue) -> Result<Self, Self::Error> {
        match value {
            YrValue::Integer(i) => Ok(!value.is_undefined() && i != 0),
            YrValue::Float(f) => Ok(!value.is_undefined() && f != 0f64),
            YrValue::String(ref s) => {
                Ok(!value.is_undefined() && s.as_ref().map(|s| !s.is_empty()).unwrap_or(false))
            }
            YrValue::Dictionary(_) => Err(YariError::BoolConversionError),
            YrValue::Array(_) => Err(YariError::BoolConversionError),
            YrValue::Structure(_) => Ok(!value.is_undefined()),
        }
    }
}
