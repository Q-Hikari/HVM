use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_iphlpapi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
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
                    let _ = arg(args, 0);
                    self.iphlpapi_get_best_interface(arg(args, 1))
                }
                ("iphlpapi.dll", "GetNumberOfInterfaces") => {
                    self.iphlpapi_get_number_of_interfaces(arg(args, 0))
                }
                ("iphlpapi.dll", "GetFriendlyIfIndex") => {
                    Ok(self.iphlpapi_get_friendly_if_index(arg(args, 0) as u32))
                }
                ("iphlpapi.dll", "GetAdaptersInfo") => {
                    self.iphlpapi_get_adapters_info(arg(args, 0), arg(args, 1))
                }
                ("iphlpapi.dll", "GetNetworkParams") => {
                    self.iphlpapi_get_network_params(arg(args, 0), arg(args, 1))
                }
                ("iphlpapi.dll", "GetAdaptersAddresses") => {
                    self.iphlpapi_get_adapters_addresses(arg(args, 0), arg(args, 3), arg(args, 4))
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
