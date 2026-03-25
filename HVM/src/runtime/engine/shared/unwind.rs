use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn rtl_capture_context(
        &mut self,
        context_ptr: u64,
    ) -> Result<u64, VmError> {
        self.capture_current_context(context_ptr)
    }

    pub(in crate::runtime::engine) fn rtl_restore_context(
        &mut self,
        context_ptr: u64,
    ) -> Result<u64, VmError> {
        let _ = self.queue_current_context_restore(context_ptr)?;
        Ok(0)
    }

    pub(in crate::runtime::engine) fn rtl_lookup_function_entry(
        &mut self,
        control_pc: u64,
        image_base_ptr: u64,
    ) -> Result<u64, VmError> {
        let lookup = self.lookup_x64_runtime_function_entry(control_pc)?;
        let module_base = lookup.as_ref().map(|entry| entry.image_base).unwrap_or(0);
        if image_base_ptr != 0 {
            if self.arch.is_x86() {
                self.write_u32(image_base_ptr, module_base as u32)?;
            } else {
                self.write_pointer_value(image_base_ptr, module_base)?;
            }
        }
        Ok(lookup
            .map(|entry| entry.function_entry_address)
            .unwrap_or(0))
    }

    pub(in crate::runtime::engine) fn rtl_pc_to_file_header(
        &mut self,
        pc_value: u64,
        module_base_ptr: u64,
    ) -> Result<u64, VmError> {
        let module_base = self
            .modules
            .get_by_address(pc_value)
            .map(|module| module.base)
            .unwrap_or(0);
        if module_base_ptr != 0 {
            if self.arch.is_x86() {
                self.write_u32(module_base_ptr, module_base as u32)?;
            } else {
                self.write_pointer_value(module_base_ptr, module_base)?;
            }
        }
        Ok(module_base)
    }

    pub(in crate::runtime::engine) fn rtl_unwind(
        &mut self,
        exception_record: u64,
        target_frame: u64,
        target_ip: u64,
    ) -> Result<u64, VmError> {
        self.rtl_unwind_x86(exception_record, target_frame, target_ip, 4)
    }

    pub(in crate::runtime::engine) fn rtl_unwind_ex(
        &mut self,
        exception_record: u64,
        target_frame: u64,
        target_ip: u64,
    ) -> Result<u64, VmError> {
        self.rtl_unwind_x86(exception_record, target_frame, target_ip, 6)
    }
}
