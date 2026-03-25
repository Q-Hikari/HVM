use super::*;

impl VirtualExecutionEngine {
    pub(super) fn run_loaded_module_initializers(
        &mut self,
        skip_bases: &[u64],
    ) -> Result<(), VmError> {
        for module in self.current_process_modules() {
            if skip_bases.contains(&module.base) || self.module_process_attach_completed(&module) {
                continue;
            }
            self.run_module_initializers(&module, "startup")?;
        }
        Ok(())
    }

    pub(super) fn run_module_initializers(
        &mut self,
        module: &ModuleRecord,
        phase: &str,
    ) -> Result<(), VmError> {
        self.run_module_notification(module, DLL_PROCESS_ATTACH, phase)?;
        self.modules.mark_initialized(module.base);
        self.attached_process_modules.insert(module.base);
        Ok(())
    }

    pub(super) fn call_native_for_runtime(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let _ = self.entry_invocation;
        self.call_native_with_entry_frame(address, args)
    }

    pub(super) fn run_module_notification(
        &mut self,
        module: &ModuleRecord,
        reason: u64,
        phase: &str,
    ) -> Result<(), VmError> {
        self.log_module_notification(module, reason, phase)?;
        if module.synthetic {
            return Ok(());
        }
        self.ensure_supported_execution_architecture(module, "run")?;
        self.run_tls_callbacks(module, reason, phase)?;
        if module.entrypoint != 0 {
            let _ = self.call_native_for_runtime(module.entrypoint, &[module.base, reason, 0])?;
        }
        Ok(())
    }

    pub(super) fn run_tls_callbacks(
        &mut self,
        module: &ModuleRecord,
        reason: u64,
        phase: &str,
    ) -> Result<(), VmError> {
        for callback in &module.tls_callbacks {
            self.log_tls_callback_event(module, *callback, reason, phase)?;
            let _ = self.call_native_for_runtime(*callback, &[module.base, reason, 0])?;
        }
        Ok(())
    }

    pub(super) fn run_dynamic_library_attach(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<(), VmError> {
        if Self::module_looks_like_dll(module) && !self.module_process_attach_completed(module) {
            if unicorn_context_active() && !module.synthetic {
                self.ensure_supported_execution_architecture(module, "load")?;
                self.modules.mark_initialized(module.base);
                self.attached_process_modules.insert(module.base);
            } else {
                self.run_module_initializers(module, "load_library")?;
            }
        }
        if self.startup_sequence_completed {
            self.capture_current_process_image_hash_baseline(module)?;
        }
        Ok(())
    }

    pub(super) fn run_dynamic_library_detach(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<(), VmError> {
        if Self::module_looks_like_dll(module) && self.module_process_attach_completed(module) {
            if !unicorn_context_active() {
                self.run_module_notification(module, DLL_PROCESS_DETACH, "free_library")?;
            }
            self.attached_process_modules.remove(&module.base);
        }
        Ok(())
    }

    pub(super) fn dispatch_thread_notification(
        &mut self,
        tid: u32,
        reason: u64,
    ) -> Result<(), VmError> {
        if tid == self.main_thread_tid.unwrap_or(0) {
            return Ok(());
        }
        if unicorn_context_active() {
            return Ok(());
        }
        let previous_tid = self.scheduler.current_tid().or(self.main_thread_tid);
        if previous_tid.is_none() {
            let _ = self.scheduler.switch_to(tid, &mut self.process_env);
            self.sync_native_support_state()?;
            self.run_loaded_dll_thread_notifications(reason)?;
            return Ok(());
        }
        let previous_tid = previous_tid.unwrap();
        let _ = self.scheduler.switch_to(tid, &mut self.process_env);
        self.sync_native_support_state()?;
        let result = self.run_loaded_dll_thread_notifications(reason);
        let _ = self
            .scheduler
            .switch_to(previous_tid, &mut self.process_env);
        let _ = self.sync_native_support_state();
        result
    }

    pub(super) fn run_loaded_dll_thread_notifications(
        &mut self,
        reason: u64,
    ) -> Result<(), VmError> {
        for module in self.current_process_modules() {
            if !self.module_process_attach_completed(&module)
                || !Self::module_looks_like_dll(&module)
            {
                continue;
            }
            self.run_module_notification(&module, reason, "thread")?;
        }
        Ok(())
    }

    pub(super) fn complete_process_startup_sequence(&mut self) -> Result<(), VmError> {
        if self.startup_sequence_completed {
            return Ok(());
        }
        let main_tid = self
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let _ = self.scheduler.switch_to(main_tid, &mut self.process_env);
        self.sync_native_support_state()?;
        self.emit_startup_resume_chain()?;
        self.startup_sequence_completed = true;
        self.capture_current_process_image_hash_baselines()?;
        Ok(())
    }

    pub(super) fn initialize_virtual_thread(
        &mut self,
        tid: u32,
        _parameter: u64,
    ) -> Result<(), VmError> {
        let (stack_limit, stack_top, stack_base) = {
            let memory = self.modules.memory_mut();
            let (stack_allocation_base, stack_top) = memory.allocate_stack()?;
            let stack_base = stack_allocation_base + memory.layout().stack_size;
            (stack_allocation_base, stack_top, stack_base)
        };
        let stack_limit = self.register_initial_thread_stack_allocation(
            self.current_process_space_key(),
            stack_limit,
            stack_base,
            stack_top,
        )?;
        let thread_context = self
            .process_env
            .allocate_thread_teb(stack_base, stack_limit)?;
        self.process_env.sync_teb_client_id(
            thread_context.teb_base,
            self.current_process_id(),
            tid,
        );
        self.initialize_scheduler_thread_context(tid, thread_context, stack_top)?;
        self.sync_native_support_state()?;
        Ok(())
    }

    pub(super) fn initialize_scheduler_thread_context(
        &mut self,
        tid: u32,
        thread_context: crate::runtime::thread_context::ThreadContext,
        stack_top: u64,
    ) -> Result<(), VmError> {
        if self.arch.is_x86() {
            const X86_ENTRY_BOOTSTRAP_SIZE: usize = 0x80;
            let stack_pointer = stack_top
                .checked_sub(X86_ENTRY_BOOTSTRAP_SIZE as u64)
                .ok_or(crate::error::MemoryError::OutOfMemory {
                    size: X86_ENTRY_BOOTSTRAP_SIZE as u64,
                })?;
            let thread = self
                .scheduler
                .thread_snapshot(tid)
                .ok_or(VmError::RuntimeInvariant("thread snapshot missing"))?;
            let mut frame = vec![0u8; X86_ENTRY_BOOTSTRAP_SIZE];
            if Some(tid) != self.scheduler.main_tid() {
                frame[0..4].copy_from_slice(&(self.native_return_sentinel as u32).to_le_bytes());
                frame[4..8].copy_from_slice(&(thread.parameter as u32).to_le_bytes());
            }
            self.modules.memory_mut().write(stack_pointer, &frame)?;
            self.scheduler
                .initialize_x86_thread_context(
                    tid,
                    thread_context,
                    stack_top,
                    self.native_return_sentinel,
                )
                .ok_or(VmError::RuntimeInvariant(
                    "failed to initialize x86 thread scheduler context",
                ))?;
            self.scheduler
                .set_thread_registers(
                    tid,
                    BTreeMap::from([
                        ("eax".to_string(), 0),
                        ("ebx".to_string(), 0),
                        ("ecx".to_string(), 0),
                        ("edx".to_string(), 0),
                        ("esi".to_string(), 0),
                        ("edi".to_string(), 0),
                        ("ebp".to_string(), 0),
                        ("esp".to_string(), stack_pointer),
                        ("eip".to_string(), thread.start_address),
                        ("eflags".to_string(), 0x202),
                    ]),
                )
                .ok_or(VmError::RuntimeInvariant(
                    "failed to seed x86 runtime bootstrap registers",
                ))?;
        } else {
            let stack_pointer = stack_top
                .checked_sub(0x28)
                .ok_or(crate::error::MemoryError::OutOfMemory { size: 0x28 })?;
            let mut frame = vec![0u8; 0x28];
            frame[0..8].copy_from_slice(&self.native_return_sentinel.to_le_bytes());
            self.modules.memory_mut().write(stack_pointer, &frame)?;
            self.scheduler
                .initialize_x64_thread_context(
                    tid,
                    thread_context,
                    stack_top,
                    self.native_return_sentinel,
                )
                .ok_or(VmError::RuntimeInvariant(
                    "failed to initialize x64 thread scheduler context",
                ))?;
        }
        Ok(())
    }

    pub(super) fn create_runtime_thread(
        &mut self,
        start_address: u64,
        parameter: u64,
        creation_flags: u64,
        tid_ptr: u64,
    ) -> Result<u64, VmError> {
        self.load()?;
        let suspended = creation_flags & 0x4 != 0;
        let thread = self
            .scheduler
            .create_virtual_thread(start_address, parameter, suspended)
            .ok_or(VmError::RuntimeInvariant(
                "failed to register virtual thread",
            ))?;
        self.initialize_virtual_thread(thread.tid, parameter)?;
        if tid_ptr != 0 {
            self.write_u32(tid_ptr, thread.tid)?;
        }
        if suspended {
            self.pending_thread_attach.insert(thread.tid);
        } else {
            self.dispatch_thread_notification(thread.tid, DLL_THREAD_ATTACH)?;
            self.started_threads.insert(thread.tid);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        self.log_thread_event(
            "THREAD_CREATE",
            thread.tid,
            thread.handle,
            start_address,
            parameter,
            if suspended { "suspended" } else { "ready" },
        )?;
        self.log_thread_entry_dump_if_dynamic(
            "THREAD_START_DUMP",
            "THREAD_CREATE",
            thread.tid,
            thread.handle,
            start_address,
            parameter,
            if suspended { "suspended" } else { "ready" },
        )?;
        Ok(thread.handle as u64)
    }
}
