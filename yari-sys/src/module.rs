use crate::error::YariError;
use std::fmt::Display;

/// Reference to a list of all currently active modules.
pub static MODULES: &[Module] = &[
    #[cfg(feature = "all_modules")]
    Module::Androguard,
    Module::Cuckoo,
    Module::Dotnet,
    Module::Elf,
    Module::Hash,
    Module::Magic,
    #[cfg(feature = "all_modules")]
    Module::Metadata,
    Module::Math,
    Module::Pe,
    #[cfg(feature = "all_modules")]
    Module::Phish,
    Module::Time,
];

/// One of the supported YARA modules.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Module {
    #[cfg(feature = "all_modules")]
    Androguard,
    Cuckoo,
    Dotnet,
    Elf,
    Hash,
    Magic,
    #[cfg(feature = "all_modules")]
    Metadata,
    Math,
    Pe,
    #[cfg(feature = "all_modules")]
    Phish,
    Time,
}

impl std::str::FromStr for Module {
    type Err = YariError;

    /// ```
    /// use yari_sys::Module;
    /// use yari_sys::YariError;
    ///
    /// assert_eq!("cuckoo".parse(), Ok(Module::Cuckoo));
    /// assert_eq!("time".parse(), Ok(Module::Time));
    /// assert_eq!("".parse::<yari_sys::Module>(), Err(YariError::UnknownModule("".to_string())));
    /// assert_eq!("unknown".parse::<yari_sys::Module>(), Err(YariError::UnknownModule("unknown".to_string())));
    /// ```
    fn from_str(s: &str) -> std::result::Result<Self, YariError> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "all_modules")]
            "androguard" => Ok(Module::Androguard),
            "cuckoo" => Ok(Module::Cuckoo),
            "dotnet" => Ok(Module::Dotnet),
            "elf" => Ok(Module::Elf),
            "hash" => Ok(Module::Hash),
            "magic" => Ok(Module::Magic),
            "math" => Ok(Module::Math),
            #[cfg(feature = "all_modules")]
            "metadata" => Ok(Module::Metadata),
            "pe" => Ok(Module::Pe),
            #[cfg(feature = "all_modules")]
            "phish" => Ok(Module::Phish),
            "time" => Ok(Module::Time),
            _ => Err(YariError::UnknownModule(s.to_string())),
        }
    }
}

impl AsRef<str> for Module {
    fn as_ref(&self) -> &str {
        match *self {
            #[cfg(feature = "all_modules")]
            Module::Androguard => "androguard",
            Module::Cuckoo => "cuckoo",
            Module::Dotnet => "dotnet",
            Module::Elf => "elf",
            Module::Hash => "hash",
            Module::Magic => "magic",
            Module::Math => "math",
            #[cfg(feature = "all_modules")]
            Module::Metadata => "metadata",
            Module::Pe => "pe",
            #[cfg(feature = "all_modules")]
            Module::Phish => "phish",
            Module::Time => "time",
        }
    }
}

impl Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.as_ref())
    }
}
