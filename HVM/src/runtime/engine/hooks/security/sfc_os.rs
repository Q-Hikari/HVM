use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_sfc_os_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        if module_name != "sfc_os.dll" {
            return None;
        }
        match function {
            "SfcIsFileProtected" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(1) != 0 {
                    let _ = self.read_wide_string_from_memory(ctx.raw(1))?;
                }
                Ok(0)
            })()),
            _ => None,
        }
    }
}
