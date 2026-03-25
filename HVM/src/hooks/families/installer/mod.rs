use crate::hooks::registry::HookRegistry;

pub mod msi;

/// Registers installer DLL families.
pub fn register(registry: &mut HookRegistry) {
    msi::register_msi_hooks(registry);
}
