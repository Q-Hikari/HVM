use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "taskschd.dll",
        "DllCanUnloadNow",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "taskschd.dll",
        "DllGetClassObject",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "taskschd.dll",
        "DllRegisterServer",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "taskschd.dll",
        "DllUnregisterServer",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "taskschd.dll",
        "DllInstall",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskschdHookLibrary;

impl HookLibrary for TaskschdHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_taskschd_hooks(registry: &mut HookRegistry) {
    registry.register_library(&TaskschdHookLibrary);
}
