use crate::hooks::registry::HookRegistry;

pub mod apphelp;
pub mod apphelp_signatures;
pub mod dbgcore;
pub mod dbgcore_signatures;
pub mod dbghelp;
pub mod dbghelp_signatures;
pub mod wer;
pub mod wer_signatures;
pub mod wevtapi;
pub mod wevtapi_signatures;

/// Registers diagnostics, telemetry, and crash-reporting DLL families.
pub fn register(registry: &mut HookRegistry) {
    apphelp::register_apphelp_hooks(registry);
    dbgcore::register_dbgcore_hooks(registry);
    dbghelp::register_dbghelp_hooks(registry);
    wer::register_wer_hooks(registry);
    wevtapi::register_wevtapi_hooks(registry);
    registry.register_signatures(apphelp_signatures::APPHELP_SIGNATURES);
    registry.register_signatures(dbgcore_signatures::DBGCORE_SIGNATURES);
    registry.register_signatures(dbghelp_signatures::DBGHELP_SIGNATURES);
    registry.register_signatures(wer_signatures::WER_SIGNATURES);
    registry.register_signatures(wevtapi_signatures::WEVTAPI_SIGNATURES);
}
