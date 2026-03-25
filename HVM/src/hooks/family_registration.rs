use super::families;
use crate::hooks::registry::HookRegistry;

/// Registers all hook definition families.
pub fn register_all_family_hooks(registry: &mut HookRegistry) {
    families::core::register(registry);
    families::crt::register(registry);
    families::com::register(registry);
    families::ui::register(registry);
    families::graphics::register(registry);
    families::network::register(registry);
    families::security::register(registry);
    families::device::register(registry);
    families::shell_services::register(registry);
    families::diagnostics::register(registry);
    families::installer::register(registry);
    families::print::register(registry);
}
