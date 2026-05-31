use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("PathFileExistsW", LogicalAbi::WinApi),
    ("PathAppendW", LogicalAbi::WinApi),
    ("PathAddBackslashW", LogicalAbi::WinApi),
    ("PathCombineW", LogicalAbi::WinApi),
    ("PathFindFileNameW", LogicalAbi::WinApi),
    ("PathFindExtensionW", LogicalAbi::WinApi),
    ("PathIsUNCW", LogicalAbi::WinApi),
    ("PathRemoveFileSpecW", LogicalAbi::WinApi),
    ("PathStripToRootW", LogicalAbi::WinApi),
    ("PathMatchSpecA", LogicalAbi::WinApi),
    ("StrCmpIW", LogicalAbi::WinApi),
    ("StrCmpNIW", LogicalAbi::WinApi),
    ("StrStrIW", LogicalAbi::WinApi),
    ("StrStrIA", LogicalAbi::WinApi),
    ("StrRChrW", LogicalAbi::WinApi),
    ("StrTrimA", LogicalAbi::WinApi),
    ("HashData", LogicalAbi::WinApi),
    ("SHGetValueW", LogicalAbi::WinApi),
    ("SHGetValueA", LogicalAbi::WinApi),
    ("SHSetValueW", LogicalAbi::WinApi),
    ("SHSetValueA", LogicalAbi::WinApi),
    ("SHCreateStreamOnFileW", LogicalAbi::WinApi),
    ("StrFormatKBSizeW", LogicalAbi::WinApi),
    ("ordinal_12", LogicalAbi::WinApi),
    ("ordinal_158", LogicalAbi::WinApi),
    ("PathIsFileSpecW", LogicalAbi::WinApi),
    ("SHCreateStreamOnFileEx", LogicalAbi::WinApi),
    ("SHStrDupW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_shlwapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("shlwapi.dll", &FUNCTIONS);
}
