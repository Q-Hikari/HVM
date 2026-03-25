use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_winmm_hook(
        &mut self,
        module_name: &str,
        function: &str,
        _args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("winmm.dll", "timeGetTime") => true,
            ("winmm.dll", "timeBeginPeriod") | ("winmm.dll", "timeEndPeriod") => true,
            ("winmm.dll", "timeSetEvent") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("winmm.dll", "timeGetTime") => Ok(self.time.current().tick_ms),
                ("winmm.dll", "timeBeginPeriod") | ("winmm.dll", "timeEndPeriod") => Ok(0),
                ("winmm.dll", "timeSetEvent") => Ok(1),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
