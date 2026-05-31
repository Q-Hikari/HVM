use crate::hooks::registry::HookRegistry;

pub mod advapi32;
pub mod advapi32_signatures;
pub mod bcrypt;
pub mod bcrypt_signatures;
pub mod crypt32;
pub mod crypt32_signatures;
pub mod cryptnet;
pub mod cryptnet_signatures;
pub mod cryptui;
pub mod cryptui_signatures;
pub mod eventing;
pub mod eventing_signatures;
pub mod fwpuclnt;
pub mod fwpuclnt_signatures;
pub mod ncrypt;
pub mod ncrypt_signatures;
pub mod secur32;
pub mod secur32_signatures;
pub mod sfc_os;
pub mod sfc_os_signatures;
pub mod wintrust;
pub mod wintrust_signatures;

/// Registers security, crypto, and policy DLL families.
pub fn register(registry: &mut HookRegistry) {
    advapi32::register_advapi32_hooks(registry);
    bcrypt::register_bcrypt_hooks(registry);
    crypt32::register_crypt32_hooks(registry);
    cryptnet::register_cryptnet_hooks(registry);
    cryptui::register_cryptui_hooks(registry);
    eventing::register_eventing_hooks(registry);
    fwpuclnt::register_fwpuclnt_hooks(registry);
    ncrypt::register_ncrypt_hooks(registry);
    secur32::register_secur32_hooks(registry);
    sfc_os::register_sfc_os_hooks(registry);
    wintrust::register_wintrust_hooks(registry);
    registry.register_signatures(bcrypt_signatures::BCRYPT_SIGNATURES);
    registry.register_signatures(crypt32_signatures::CRYPT32_SIGNATURES);
    registry.register_signatures(cryptnet_signatures::CRYPTNET_SIGNATURES);
    registry.register_signatures(cryptui_signatures::CRYPTUI_SIGNATURES);
    registry.register_signatures(eventing_signatures::EVENTING_SIGNATURES);
    registry.register_signatures(fwpuclnt_signatures::FWPUCLNT_SIGNATURES);
    registry.register_signatures(ncrypt_signatures::NCRYPT_SIGNATURES);
    registry.register_signatures(secur32_signatures::SECUR32_SIGNATURES);
    registry.register_signatures(sfc_os_signatures::SFC_OS_SIGNATURES);
    registry.register_signatures(wintrust_signatures::WINTRUST_SIGNATURES);
}
