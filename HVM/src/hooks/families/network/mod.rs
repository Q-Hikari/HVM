use crate::hooks::registry::HookRegistry;

pub mod dnsapi;
pub mod iphlpapi;
pub mod mpr;
pub mod mswsock;
pub mod netapi32;
pub mod netutils;
pub mod rasapi32;
pub mod winhttp;
pub mod wininet;
pub mod wlanapi;
pub mod wldap32;
pub mod ws2_32;

/// Registers networking and directory services DLL families.
pub fn register(registry: &mut HookRegistry) {
    dnsapi::register_dnsapi_hooks(registry);
    iphlpapi::register_iphlpapi_hooks(registry);
    mpr::register_mpr_hooks(registry);
    mswsock::register_mswsock_hooks(registry);
    netapi32::register_netapi32_hooks(registry);
    netutils::register_netutils_hooks(registry);
    rasapi32::register_rasapi32_hooks(registry);
    winhttp::register_winhttp_hooks(registry);
    wininet::register_wininet_hooks(registry);
    wlanapi::register_wlanapi_hooks(registry);
    wldap32::register_wldap32_hooks(registry);
    ws2_32::register_ws2_32_hooks(registry);
}
