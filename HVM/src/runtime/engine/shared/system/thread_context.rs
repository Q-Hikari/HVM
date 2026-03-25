use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn current_thread_snapshot(
        &self,
    ) -> Option<crate::runtime::scheduler::ThreadRecord> {
        self.scheduler
            .current_tid()
            .and_then(|tid| self.scheduler.thread_snapshot(tid))
            .or_else(|| {
                self.main_thread_tid
                    .and_then(|tid| self.scheduler.thread_snapshot(tid))
            })
    }

    pub(in crate::runtime::engine) fn capture_current_context(
        &mut self,
        address: u64,
    ) -> Result<u64, VmError> {
        if address == 0 {
            return Ok(0);
        }
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(0);
        };
        serialize_register_context(
            self.modules.memory_mut(),
            self.arch,
            address,
            &thread.registers,
        )?;
        Ok(1)
    }

    pub(in crate::runtime::engine) fn queue_current_context_restore(
        &mut self,
        address: u64,
    ) -> Result<bool, VmError> {
        if address == 0 {
            return Ok(false);
        }
        let registers = deserialize_register_context(self.modules.memory(), self.arch, address)?;
        let Some(tid) = self.scheduler.current_tid().or(self.main_thread_tid) else {
            return Ok(false);
        };
        self.scheduler
            .set_thread_registers(tid, registers.clone())
            .ok_or(VmError::RuntimeInvariant(
                "failed to stage thread register context restore",
            ))?;
        self.pending_context_restore = Some(PendingContextRestore {
            context_address: address,
            registers,
        });
        self.defer_api_return = true;
        Ok(true)
    }
}
