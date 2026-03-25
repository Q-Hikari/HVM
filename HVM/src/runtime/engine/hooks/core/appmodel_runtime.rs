use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_appmodel_runtime_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("api-ms-win-appmodel-runtime-l1-1-2.dll", "AppPolicyGetProcessTerminationMethod")
            | ("api-ms-win-appmodel-runtime-l1-1-2.dll", "AppPolicyGetThreadInitializationType") => {
                true
            }
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                (
                    "api-ms-win-appmodel-runtime-l1-1-2.dll",
                    "AppPolicyGetProcessTerminationMethod",
                )
                | (
                    "api-ms-win-appmodel-runtime-l1-1-2.dll",
                    "AppPolicyGetThreadInitializationType",
                ) => {
                    if arg(args, 1) != 0 {
                        self.write_u32(arg(args, 1), 0)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
