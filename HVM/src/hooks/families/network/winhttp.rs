use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "winhttp.dll",
        "WinHttpOpen",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpConnect",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpOpenRequest",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpAddRequestHeaders",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpSendRequest",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpWriteData",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpReceiveResponse",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpReadData",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpQueryDataAvailable",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpQueryHeaders",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpSetOption",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpQueryOption",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpSetTimeouts",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpGetIEProxyConfigForCurrentUser",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpGetProxyForUrl",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winhttp.dll",
        "WinHttpCloseHandle",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinhttpHookLibrary;

impl HookLibrary for WinhttpHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_winhttp_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WinhttpHookLibrary);
}
