use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "rasapi32.dll",
        "RasDialA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasDialW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasEnumConnectionsA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasEnumConnectionsW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasEnumEntriesA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasEnumEntriesW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasGetConnectStatusA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasGetConnectStatusW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasGetErrorStringA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasGetErrorStringW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasHangUpA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "rasapi32.dll",
        "RasHangUpW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Rasapi32HookLibrary;

impl HookLibrary for Rasapi32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_rasapi32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Rasapi32HookLibrary);
}
