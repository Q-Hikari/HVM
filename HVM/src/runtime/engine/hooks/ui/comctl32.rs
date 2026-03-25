use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_comctl32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        _args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("comctl32.dll", "InitCommonControlsEx") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("comctl32.dll", "InitCommonControlsEx") => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
