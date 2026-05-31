use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ApiArgKind {
    Int32,
    UInt32,
    Hex32,
    Bool,
    Ptr,
    LpStr,
    LpWStr,
    ProcName,
    Module,
    UnicodeStringPtr,
    AnsiStringPtr,
}

mod api_format;
mod event_log;
mod pointer_desc;
mod runtime_event_log;

pub use pointer_desc::trim_trailing_nul;

impl ApiArgKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Int32 => "int32",
            Self::UInt32 => "uint32",
            Self::Hex32 => "hex32",
            Self::Bool => "bool",
            Self::Ptr => "ptr",
            Self::LpStr => "lpstr",
            Self::LpWStr => "lpwstr",
            Self::ProcName => "proc_name",
            Self::Module => "module",
            Self::UnicodeStringPtr => "unicode_string_ptr",
            Self::AnsiStringPtr => "ansi_string_ptr",
        }
    }
}
