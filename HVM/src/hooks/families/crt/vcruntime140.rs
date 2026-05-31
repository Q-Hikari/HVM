use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("__std_exception_copy", LogicalAbi::Cdecl),
    ("__std_exception_destroy", LogicalAbi::Cdecl),
    ("__std_terminate", LogicalAbi::Cdecl),
    ("__std_type_info_destroy_list", LogicalAbi::Cdecl),
    ("_purecall", LogicalAbi::Cdecl),
    ("memchr", LogicalAbi::Cdecl),
    ("memcpy", LogicalAbi::Cdecl),
];

pub fn register_vcruntime140_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("vcruntime140.dll", &FUNCTIONS);
}
