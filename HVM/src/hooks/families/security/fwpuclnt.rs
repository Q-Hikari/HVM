use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "fwpuclnt.dll",
        "FwpmEngineOpen0",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "fwpuclnt.dll",
        "FwpmEngineClose0",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "fwpuclnt.dll",
        "FwpmTransactionBegin0",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "fwpuclnt.dll",
        "FwpmTransactionCommit0",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "fwpuclnt.dll",
        "FwpmSubLayerAdd0",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "fwpuclnt.dll",
        "FwpmCalloutAdd0",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "fwpuclnt.dll",
        "FwpmFilterAdd0",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct FwpuclntHookLibrary;

impl HookLibrary for FwpuclntHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_fwpuclnt_hooks(registry: &mut HookRegistry) {
    registry.register_library(&FwpuclntHookLibrary);
}
