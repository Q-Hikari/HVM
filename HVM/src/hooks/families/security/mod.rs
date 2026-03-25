use crate::hooks::registry::HookRegistry;

pub mod advapi32;
pub mod bcrypt;
pub mod crypt32;
pub mod cryptnet;
pub mod cryptui;
pub mod fwpuclnt;
pub mod ncrypt;
pub mod secur32;
pub mod wintrust;

/// Registers security, crypto, and policy DLL families.
pub fn register(registry: &mut HookRegistry) {
    advapi32::register_advapi32_hooks(registry);
    bcrypt::register_bcrypt_hooks(registry);
    crypt32::register_crypt32_hooks(registry);
    cryptnet::register_cryptnet_hooks(registry);
    cryptui::register_cryptui_hooks(registry);
    fwpuclnt::register_fwpuclnt_hooks(registry);
    ncrypt::register_ncrypt_hooks(registry);
    secur32::register_secur32_hooks(registry);
    wintrust::register_wintrust_hooks(registry);
}
