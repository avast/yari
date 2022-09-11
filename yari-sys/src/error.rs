use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum YariError {
    #[error("cannot parse the expression")]
    ParserError,

    #[error("cannot evaluate the expression")]
    EvalError,

    #[error("cannot find symbol '{}'", .0)]
    SymbolNotFound(String),

    #[error("module data expected in format 'MODULE=DATA'")]
    ModuleDataError,

    #[error("unknown module")]
    UnknownModule,

    #[error("context builder error: '{}'", .0)]
    ContextBuilderError(String),

    #[error("cannot evaluate expression because of missing rule context")]
    RuleMissingError,

    #[error("cannot evaluate undeclared string")]
    UndeclaredStringError,

    #[error("index out of bounds")]
    IndexOutOfBounds,

    #[error("this type cannot be used as bool")]
    BoolConversionError,

    #[error("unknown data store error")]
    Unknown,
}
