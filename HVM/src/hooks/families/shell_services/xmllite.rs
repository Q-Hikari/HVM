use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[("CreateXmlWriter", LogicalAbi::WinApi)];

/// Registers the generated hook definitions for this DLL family.
pub fn register_xmllite_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("xmllite.dll", &EXPORTS);
}
