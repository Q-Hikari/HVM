use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_iphlpapi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("iphlpapi.dll", "GetBestInterface") => true,
            ("iphlpapi.dll", "GetNumberOfInterfaces") => true,
            ("iphlpapi.dll", "GetFriendlyIfIndex") => true,
            ("iphlpapi.dll", "GetAdaptersInfo") => true,
            ("iphlpapi.dll", "GetNetworkParams") => true,
            ("iphlpapi.dll", "GetAdaptersAddresses") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("iphlpapi.dll", "GetBestInterface") => {
                    let _ = ctx.raw(0);
                    self.iphlpapi_get_best_interface(ctx.raw(1))
                }
                ("iphlpapi.dll", "GetNumberOfInterfaces") => {
                    self.iphlpapi_get_number_of_interfaces(ctx.raw(0))
                }
                ("iphlpapi.dll", "GetFriendlyIfIndex") => {
                    Ok(self.iphlpapi_get_friendly_if_index(ctx.raw(0) as u32))
                }
                ("iphlpapi.dll", "GetAdaptersInfo") => {
                    self.iphlpapi_get_adapters_info(ctx.raw(0), ctx.raw(1))
                }
                ("iphlpapi.dll", "GetNetworkParams") => {
                    self.iphlpapi_get_network_params(ctx.raw(0), ctx.raw(1))
                }
                ("iphlpapi.dll", "GetAdaptersAddresses") => {
                    self.iphlpapi_get_adapters_addresses(ctx.raw(0), ctx.raw(3), ctx.raw(4))
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
