use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_vcruntime140_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("vcruntime140.dll", "memcpy") => true,
            ("vcruntime140.dll", "memchr") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("vcruntime140.dll", "memcpy") => {
                    self.copy_memory_block(arg(args, 0), arg(args, 1), arg(args, 2) as usize)
                }
                ("vcruntime140.dll", "memchr") => {
                    let address = arg(args, 0);
                    let needle = arg(args, 1) as u8;
                    let size = arg(args, 2) as usize;
                    if address == 0 || size == 0 {
                        return Ok(0);
                    }
                    let Ok(bytes) = self.read_bytes_from_memory(address, size) else {
                        return Ok(0);
                    };
                    Ok(bytes
                        .iter()
                        .position(|byte| *byte == needle)
                        .map(|offset| address + offset as u64)
                        .unwrap_or(0))
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
