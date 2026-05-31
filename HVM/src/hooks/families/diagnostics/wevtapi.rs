use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("EvtOpenSession", LogicalAbi::WinApi),
    ("EvtQuery", LogicalAbi::WinApi),
    ("EvtCreateRenderContext", LogicalAbi::WinApi),
    ("EvtNext", LogicalAbi::WinApi),
    ("EvtRender", LogicalAbi::WinApi),
    ("EvtFormatMessage", LogicalAbi::WinApi),
    ("EvtClose", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wevtapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wevtapi.dll", &FUNCTIONS);
}
