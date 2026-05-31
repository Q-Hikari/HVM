use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_ole32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("ole32.dll", "CoInitialize")
            | ("ole32.dll", "CoInitializeEx")
            | ("ole32.dll", "OleInitialize") => true,
            ("ole32.dll", "CoUninitialize") => true,
            ("ole32.dll", "CoCreateInstance") | ("ole32.dll", "CoGetClassObject") => true,
            ("ole32.dll", "CoRegisterMessageFilter") => true,
            ("ole32.dll", "CoCreateGuid") => true,
            ("ole32.dll", "CoCreateFreeThreadedMarshaler") => true,
            ("ole32.dll", "CoTaskMemRealloc") => true,
            ("ole32.dll", "CLSIDFromProgID") => true,
            ("ole32.dll", "IIDFromString") => true,
            ("ole32.dll", "CoGetObject") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("ole32.dll", "CoInitialize")
                | ("ole32.dll", "CoInitializeEx")
                | ("ole32.dll", "OleInitialize") => self.dispatch_com_initialize(),
                ("ole32.dll", "CoUninitialize") => self.dispatch_com_uninitialize(),
                ("ole32.dll", "CoRegisterMessageFilter") => {
                    if ctx.raw(1) != 0 {
                        self.write_pointer_value(ctx.raw(1), self.dispatch.com_message_filter)?;
                    }
                    self.dispatch.com_message_filter = ctx.raw(0);
                    Ok(ERROR_SUCCESS)
                }
                ("ole32.dll", "CoCreateInstance") | ("ole32.dll", "CoGetClassObject") => {
                    let clsid_ptr = ctx.raw(0);
                    // Check if this is a known COM class before falling back
                    if clsid_ptr != 0 {
                        let clsid = self.read_bytes_from_memory(clsid_ptr, 16)?;
                        if clsid.as_slice() == super::common::CLSID_MMC20_APPLICATION {
                            return self.dispatch_com_create_instance(
                                clsid_ptr,
                                ctx.raw(1),
                                ctx.raw(2),
                                ctx.raw(3),
                                ctx.raw(4),
                            );
                        }
                    }
                    self.dispatch_com_activation_not_registered(ctx.raw(4))
                }
                ("ole32.dll", "CoCreateGuid") => self.dispatch_com_create_guid(ctx.raw(0)),
                ("ole32.dll", "CoCreateFreeThreadedMarshaler") => {
                    if ctx.raw(1) != 0 {
                        let marshaler = self.alloc_process_heap_block(
                            self.core.arch.pointer_size as u64 * 2,
                            "CoCreateFreeThreadedMarshaler",
                        )?;
                        self.write_pointer_value(ctx.raw(1), marshaler)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("ole32.dll", "CoTaskMemRealloc") => {
                    self.dispatch_com_task_mem_realloc(ctx.raw(0), ctx.raw(1))
                }
                ("ole32.dll", "CLSIDFromProgID") => {
                    self.dispatch_clsid_from_progid(ctx.raw(0), ctx.raw(1))
                }
                ("ole32.dll", "IIDFromString") => {
                    self.dispatch_iid_from_string(ctx.raw(0), ctx.raw(1))
                }
                ("ole32.dll", "CoGetObject") => {
                    self.dispatch_com_get_object(ctx.raw(0), ctx.raw(3))
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
