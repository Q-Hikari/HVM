use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[("SfcIsFileProtected", LogicalAbi::WinApi)];

pub fn register_sfc_os_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("sfc_os.dll", &FUNCTIONS);
}
