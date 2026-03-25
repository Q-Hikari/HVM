use crate::hooks::registry::HookRegistry;

pub mod combase;
pub mod ole32;
pub mod oleacc;
pub mod oleaut32;
pub mod oledlg;
pub mod rpcrt4;

/// Registers COM and RPC-related DLL families.
pub fn register(registry: &mut HookRegistry) {
    combase::register_combase_hooks(registry);
    ole32::register_ole32_hooks(registry);
    oleacc::register_oleacc_hooks(registry);
    oleaut32::register_oleaut32_hooks(registry);
    oledlg::register_oledlg_hooks(registry);
    rpcrt4::register_rpcrt4_hooks(registry);
}
