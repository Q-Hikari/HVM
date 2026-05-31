use crate::hooks::registry::HookRegistry;

mod exports;
mod user32_signatures;

/// Registers the generated hook definitions for this DLL family.
pub fn register_user32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("user32.dll", &exports::STDCALL_EXPORTS);
    registry.register_function_stubs("user32.dll", &exports::CDECL_EXPORTS);
    user32_signatures::register_all(registry);
    registry
        .register_signatures(super::super::crt::variadic_signatures::USER32_VARIADIC_SIGNATURES);
}
