use super::*;

impl VirtualExecutionEngine {
    pub(super) fn dispatch_com_initialize(&self) -> Result<u64, VmError> {
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn dispatch_com_uninitialize(&self) -> Result<u64, VmError> {
        Ok(0)
    }

    pub(super) fn dispatch_com_activation_not_registered(
        &mut self,
        result_ptr: u64,
    ) -> Result<u64, VmError> {
        if result_ptr != 0 {
            self.write_pointer_value(result_ptr, 0)?;
        }
        Ok(REGDB_E_CLASSNOTREG_HRESULT)
    }

    pub(super) fn dispatch_com_create_guid(&mut self, buffer: u64) -> Result<u64, VmError> {
        if buffer == 0 {
            Ok(E_INVALIDARG_HRESULT)
        } else {
            let guid = self.next_guid_bytes_le(4);
            self.modules.memory_mut().write(buffer, &guid)?;
            Ok(ERROR_SUCCESS)
        }
    }

    pub(super) fn dispatch_com_task_mem_realloc(
        &mut self,
        old_address: u64,
        new_size: u64,
    ) -> Result<u64, VmError> {
        if old_address == 0 {
            return self.alloc_process_heap_block(new_size.max(1), "CoTaskMemRealloc");
        }
        if new_size == 0 {
            let _ = self.heaps.free(self.heaps.process_heap(), old_address);
            return Ok(0);
        }
        let old_size = self.heaps.size(self.heaps.process_heap(), old_address);
        if old_size == u32::MAX as u64 {
            return Ok(0);
        }
        let new_address = self.alloc_process_heap_block(new_size, "CoTaskMemRealloc")?;
        let bytes = self.read_bytes_from_memory(old_address, old_size.min(new_size) as usize)?;
        self.modules.memory_mut().write(new_address, &bytes)?;
        let _ = self.heaps.free(self.heaps.process_heap(), old_address);
        Ok(new_address)
    }
}
