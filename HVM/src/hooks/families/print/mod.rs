use crate::hooks::registry::HookRegistry;

pub mod winspool;
pub mod winspool_drv;
pub mod winspool_drv_signatures;
pub mod winspool_signatures;

/// Registers printing DLL families.
pub fn register(registry: &mut HookRegistry) {
    winspool::register_winspool_hooks(registry);
    winspool_drv::register_winspool_drv_hooks(registry);
    registry.register_signatures(winspool_signatures::WINSPOOL_SIGNATURES);
    registry.register_signatures(winspool_drv_signatures::WINSPOOL_DRV_SIGNATURES);
}
