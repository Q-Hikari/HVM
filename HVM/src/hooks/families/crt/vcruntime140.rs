use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "vcruntime140.dll",
        "__std_exception_copy",
        2,
        crate::hooks::base::CallConv::Cdecl,
    ),
    (
        "vcruntime140.dll",
        "__std_exception_destroy",
        1,
        crate::hooks::base::CallConv::Cdecl,
    ),
    (
        "vcruntime140.dll",
        "__std_terminate",
        0,
        crate::hooks::base::CallConv::Cdecl,
    ),
    (
        "vcruntime140.dll",
        "__std_type_info_destroy_list",
        1,
        crate::hooks::base::CallConv::Cdecl,
    ),
    (
        "vcruntime140.dll",
        "_purecall",
        0,
        crate::hooks::base::CallConv::Cdecl,
    ),
    (
        "vcruntime140.dll",
        "memchr",
        3,
        crate::hooks::base::CallConv::Cdecl,
    ),
    (
        "vcruntime140.dll",
        "memcpy",
        3,
        crate::hooks::base::CallConv::Cdecl,
    ),
];

#[derive(Debug, Default, Clone, Copy)]
pub struct Vcruntime140HookLibrary;

impl HookLibrary for Vcruntime140HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

pub fn register_vcruntime140_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Vcruntime140HookLibrary);
}
