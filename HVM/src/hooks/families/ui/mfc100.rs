use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[("ordinal_1895", LogicalAbi::WinApi)];

pub fn register_mfc100_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("mfc100.dll", EXPORTS);
    registry.register_signatures(super::mfc100_signatures::MFC100_SIGNATURES);
}
