use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_psapi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("psapi.dll", "EnumProcesses") => true,
            ("psapi.dll", "EnumProcessModules") | ("psapi.dll", "EnumProcessModulesEx") => true,
            ("psapi.dll", "GetModuleBaseNameA") => true,
            ("psapi.dll", "GetModuleBaseNameW") => true,
            ("psapi.dll", "GetModuleFileNameExA") => true,
            ("psapi.dll", "GetModuleFileNameExW") => true,
            ("psapi.dll", "GetModuleInformation") => true,
            ("psapi.dll", "GetProcessImageFileNameA") => true,
            ("psapi.dll", "GetProcessImageFileNameW") => true,
            ("psapi.dll", "GetMappedFileNameA") => true,
            ("psapi.dll", "GetMappedFileNameW") => true,
            ("psapi.dll", "EmptyWorkingSet") => true,
            ("psapi.dll", "GetProcessMemoryInfo") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("psapi.dll", "EnumProcesses") => {
                    self.enum_processes(ctx.raw(0), ctx.raw(1) as usize, ctx.raw(2))
                }
                ("psapi.dll", "EnumProcessModules") | ("psapi.dll", "EnumProcessModulesEx") => self
                    .enum_process_modules(ctx.raw(0), ctx.raw(1), ctx.raw(2) as usize, ctx.raw(3)),
                ("psapi.dll", "GetModuleBaseNameA") => self.get_module_base_name_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    false,
                ),
                ("psapi.dll", "GetModuleBaseNameW") => self.get_module_base_name_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    true,
                ),
                ("psapi.dll", "GetModuleFileNameExA") => self.get_module_file_name_ex_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    false,
                ),
                ("psapi.dll", "GetModuleFileNameExW") => self.get_module_file_name_ex_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    true,
                ),
                ("psapi.dll", "GetModuleInformation") => self.write_module_information(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                ),
                ("psapi.dll", "GetProcessImageFileNameA") => self
                    .get_process_image_file_name_result(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2) as usize,
                        false,
                    ),
                ("psapi.dll", "GetProcessImageFileNameW") => self
                    .get_process_image_file_name_result(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2) as usize,
                        true,
                    ),
                ("psapi.dll", "GetMappedFileNameA") => self.get_mapped_file_name_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    false,
                ),
                ("psapi.dll", "GetMappedFileNameW") => self.get_mapped_file_name_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    true,
                ),
                ("psapi.dll", "EmptyWorkingSet") => {
                    Ok(self.process_identity_for_handle(ctx.raw(0)).is_some() as u64)
                }
                ("psapi.dll", "GetProcessMemoryInfo") => {
                    self.write_process_memory_info(ctx.raw(0), ctx.raw(1), ctx.raw(2) as usize)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
