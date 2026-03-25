use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_rpcrt4_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("rpcrt4.dll", "UuidCreate") => true,
            ("rpcrt4.dll", "UuidCreateSequential") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("rpcrt4.dll", "UuidCreate") => {
                    let guid = self.next_guid_bytes_le(4);
                    if arg(args, 0) != 0 {
                        self.modules.memory_mut().write(arg(args, 0), &guid)?;
                    }
                    Ok(RPC_S_OK)
                }
                ("rpcrt4.dll", "UuidCreateSequential") => {
                    let guid = self.next_guid_bytes_le(1);
                    if arg(args, 0) != 0 {
                        self.modules.memory_mut().write(arg(args, 0), &guid)?;
                    }
                    Ok(RPC_S_UUID_LOCAL_ONLY)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
