use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_mfc100_hook(
        &mut self,
        module_name: &str,
        function: &str,
        _ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        match (module_name, function) {
            ("mfc100.dll", "ordinal_1895") => Some(Ok(0)),
            _ => None,
        }
    }
}
