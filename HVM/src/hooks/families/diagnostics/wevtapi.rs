use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "wevtapi.dll",
        "EvtOpenSession",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wevtapi.dll",
        "EvtQuery",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wevtapi.dll",
        "EvtCreateRenderContext",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wevtapi.dll",
        "EvtNext",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wevtapi.dll",
        "EvtRender",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wevtapi.dll",
        "EvtFormatMessage",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wevtapi.dll",
        "EvtClose",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WevtapiHookLibrary;

impl HookLibrary for WevtapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_wevtapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WevtapiHookLibrary);
}
