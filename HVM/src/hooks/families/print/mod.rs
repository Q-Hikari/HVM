use crate::hooks::registry::HookRegistry;

pub mod winspool;
pub mod winspool_drv;

/// Registers printing DLL families.
pub fn register(registry: &mut HookRegistry) {
    winspool::register_winspool_hooks(registry);
    winspool_drv::register_winspool_drv_hooks(registry);
}
