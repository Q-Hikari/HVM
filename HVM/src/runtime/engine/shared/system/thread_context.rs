use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn is_current_thread_handle(&self, handle: u64) -> bool {
        let handle32 = (handle & 0xFFFF_FFFF) as u32;
        handle32 == 0
            || handle32 == 0xFFFF_FFFE
            || self
                .current_thread_snapshot()
                .map(|thread| thread.handle == handle32)
                .unwrap_or(false)
    }

    pub(in crate::runtime::engine) fn current_thread_snapshot(
        &self,
    ) -> Option<crate::runtime::scheduler::ThreadRecord> {
        self.core
            .scheduler
            .current_tid()
            .and_then(|tid| self.core.scheduler.thread_snapshot(tid))
            .or_else(|| {
                self.core
                    .main_thread_tid
                    .and_then(|tid| self.core.scheduler.thread_snapshot(tid))
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
            self.core.modules.memory_mut(),
            self.core.arch,
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
        let registers =
            deserialize_register_context(self.core.modules.memory(), self.core.arch, address)?;
        let Some(tid) = self
            .core
            .scheduler
            .current_tid()
            .or(self.core.main_thread_tid)
        else {
            return Ok(false);
        };
        self.core
            .scheduler
            .set_thread_registers(tid, registers.clone())
            .ok_or(VmError::RuntimeInvariant(
                "failed to stage thread register context restore",
            ))?;
        self.exception.pending_context_restore = Some(PendingContextRestore {
            context_address: address,
            registers,
        });
        self.dispatch.request_resume_at_updated_pc();
        Ok(true)
    }
}
