use crate::hooks::registry::HookRegistry;

pub mod dnsapi;
pub mod dnsapi_signatures;
pub mod iphlpapi;
pub mod iphlpapi_signatures;
pub mod mpr;
pub mod mpr_signatures;
pub mod mswsock;
pub mod mswsock_signatures;
pub mod netapi32;
pub mod netapi32_signatures;
pub mod netutils;
pub mod netutils_signatures;
pub mod rasapi32;
pub mod rasapi32_signatures;
pub mod winhttp;
pub mod winhttp_signatures;
pub mod wininet;
pub mod wininet_signatures;
pub mod wlanapi;
pub mod wlanapi_signatures;
pub mod wldap32;
pub mod wldap32_signatures;
pub mod ws2_32;
pub mod ws2_32_signatures;

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
    registry.register_signatures(dnsapi_signatures::DNSAPI_SIGNATURES);
    registry.register_signatures(iphlpapi_signatures::IPHLPAPI_SIGNATURES);
    registry.register_signatures(mpr_signatures::MPR_SIGNATURES);
    registry.register_signatures(mswsock_signatures::MSWSOCK_SIGNATURES);
    registry.register_signatures(netapi32_signatures::NETAPI32_SIGNATURES);
    registry.register_signatures(netutils_signatures::NETUTILS_SIGNATURES);
    registry.register_signatures(rasapi32_signatures::RASAPI32_SIGNATURES);
    registry.register_signatures(winhttp_signatures::WINHTTP_SIGNATURES);
    registry.register_signatures(wininet_signatures::WININET_SIGNATURES);
    registry.register_signatures(wlanapi_signatures::WLANAPI_SIGNATURES);
    registry.register_signatures(wldap32_signatures::WLDAP32_SIGNATURES);
    registry.register_signatures(ws2_32_signatures::WS2_32_SIGNATURES);
}
