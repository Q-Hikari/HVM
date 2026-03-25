use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "wtsapi32.dll",
        "WTSOpenServerA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSOpenServerW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSCloseServer",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSEnumerateSessionsA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSEnumerateSessionsW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSQuerySessionInformationA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSQuerySessionInformationW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSFreeMemory",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSQueryUserToken",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSSendMessageA",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSSendMessageW",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSRegisterSessionNotification",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSUnRegisterSessionNotification",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSDisconnectSession",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSLogoffSession",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSEnumerateProcessesA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSEnumerateProcessesW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSEnumerateProcessesExA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSEnumerateProcessesExW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSFreeMemoryExA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wtsapi32.dll",
        "WTSFreeMemoryExW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Wtsapi32HookLibrary;

impl HookLibrary for Wtsapi32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_wtsapi32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Wtsapi32HookLibrary);
}
