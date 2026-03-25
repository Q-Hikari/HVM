use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_ole32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("ole32.dll", "CoInitialize") | ("ole32.dll", "CoInitializeEx") => true,
            ("ole32.dll", "CoUninitialize") => true,
            ("ole32.dll", "CoCreateInstance") | ("ole32.dll", "CoGetClassObject") => true,
            ("ole32.dll", "CoCreateGuid") => true,
            ("ole32.dll", "CoCreateFreeThreadedMarshaler") => true,
            ("ole32.dll", "CoTaskMemRealloc") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("ole32.dll", "CoInitialize") | ("ole32.dll", "CoInitializeEx") => {
                    self.dispatch_com_initialize()
                }
                ("ole32.dll", "CoUninitialize") => self.dispatch_com_uninitialize(),
                ("ole32.dll", "CoCreateInstance") | ("ole32.dll", "CoGetClassObject") => {
                    self.dispatch_com_activation_not_registered(arg(args, 4))
                }
                ("ole32.dll", "CoCreateGuid") => self.dispatch_com_create_guid(arg(args, 0)),
                ("ole32.dll", "CoCreateFreeThreadedMarshaler") => {
                    if arg(args, 1) != 0 {
                        let marshaler = self.alloc_process_heap_block(
                            self.arch.pointer_size as u64 * 2,
                            "CoCreateFreeThreadedMarshaler",
                        )?;
                        self.write_pointer_value(arg(args, 1), marshaler)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("ole32.dll", "CoTaskMemRealloc") => {
                    self.dispatch_com_task_mem_realloc(arg(args, 0), arg(args, 1))
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
