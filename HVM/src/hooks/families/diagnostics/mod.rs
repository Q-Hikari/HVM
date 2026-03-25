use crate::hooks::registry::HookRegistry;

pub mod apphelp;
pub mod dbgcore;
pub mod dbghelp;
pub mod wer;
pub mod wevtapi;

/// Registers diagnostics, telemetry, and crash-reporting DLL families.
pub fn register(registry: &mut HookRegistry) {
    apphelp::register_apphelp_hooks(registry);
    dbgcore::register_dbgcore_hooks(registry);
    dbghelp::register_dbghelp_hooks(registry);
    wer::register_wer_hooks(registry);
    wevtapi::register_wevtapi_hooks(registry);
}
