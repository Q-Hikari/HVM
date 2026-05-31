use crate::hooks::registry::HookRegistry;

pub mod msi;
pub mod msi_signatures;

/// Registers installer DLL families.
pub fn register(registry: &mut HookRegistry) {
    msi::register_msi_hooks(registry);
    registry.register_signatures(msi_signatures::MSI_SIGNATURES);
}
