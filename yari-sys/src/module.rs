use crate::error::YariError;
use std::fmt::Display;

/// One of the supported YARA modules.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Module {
    Cuckoo,
    Dotnet,
    Elf,
    Hash,
    Magic,
    Math,
    Pe,
    Time,
}

impl Module {
    pub const ALL_MODULES: [Self; 8] = [
        Self::Cuckoo,
        Self::Dotnet,
        Self::Elf,
        Self::Hash,
        Self::Magic,
        Self::Math,
        Self::Pe,
        Self::Time,
    ];
}

impl std::str::FromStr for Module {
    type Err = YariError;

    fn from_str(s: &str) -> std::result::Result<Self, YariError> {
        match s.to_lowercase().as_str() {
            "cuckoo" => Ok(Module::Cuckoo),
            "dotnet" => Ok(Module::Dotnet),
            "elf" => Ok(Module::Elf),
            "hash" => Ok(Module::Hash),
            "magic" => Ok(Module::Magic),
            "math" => Ok(Module::Math),
            "pe" => Ok(Module::Pe),
            "time" => Ok(Module::Time),
            _ => Err(YariError::UnknownModule),
        }
    }
}

impl AsRef<str> for Module {
    fn as_ref(&self) -> &str {
        match *self {
            Module::Cuckoo => "cuckoo",
            Module::Dotnet => "dotnet",
            Module::Elf => "elf",
            Module::Hash => "hash",
            Module::Magic => "magic",
            Module::Math => "math",
            Module::Pe => "pe",
            Module::Time => "time",
        }
    }
}

impl Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.as_ref())
    }
}
