use crate::hooks::registry::HookRegistry;

pub mod com_dispatch;
pub mod combase;
pub mod combase_signatures;
pub mod ole32;
pub mod ole32_signatures;
pub mod oleacc;
pub mod oleacc_signatures;
pub mod oleaut32;
pub mod oleaut32_signatures;
pub mod oledlg;
pub mod oledlg_signatures;
pub mod rpcrt4;
pub mod rpcrt4_signatures;

/// Registers COM and RPC-related DLL families.
pub fn register(registry: &mut HookRegistry) {
    combase::register_combase_hooks(registry);
    com_dispatch::register_com_dispatch_hooks(registry);
    ole32::register_ole32_hooks(registry);
    oleacc::register_oleacc_hooks(registry);
    oleaut32::register_oleaut32_hooks(registry);
    oledlg::register_oledlg_hooks(registry);
    rpcrt4::register_rpcrt4_hooks(registry);
    registry.register_signatures(oleacc_signatures::OLEACC_SIGNATURES);
    registry.register_signatures(oledlg_signatures::OLEDLG_SIGNATURES);
}
