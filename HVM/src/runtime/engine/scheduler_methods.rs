//! Scheduler and main loop methods for VirtualExecutionEngine.
//!
//! Contains the scheduler loop, native/unicorn main entry points,
//! and thread preparation methods.

use super::VirtualExecutionEngine;
use super::*;
use crate::error::VmError;
use crate::models::RunStopReason;

impl VirtualExecutionEngine {
    /// Advances the scaffold scheduler until no runnable work remains or the instruction cap is spent.
    pub(super) fn run_scheduler_loop(&mut self) -> Result<(), VmError> {
        let mut remaining = self.remaining_run_budget();
        if remaining == 0 {
            self.core.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
            return Ok(());
        }
        while remaining > 0 {
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("scheduler.poll_blocked_threads");
                self.core
                    .scheduler
                    .poll_blocked_threads(self.dispatch.time.current().tick_ms);
            }
            let Some(tid) = self.core.scheduler.next_ready_tid() else {
                let _ = self.log_scheduler_event("SCHED_IDLE", None, None, None);
                if !self.core.scheduler.has_live_threads() {
                    break;
                }
                if let Some(next_tick) = self.core.scheduler.next_wake_tick() {
                    let current_tick = self.dispatch.time.current().tick_ms;
                    if next_tick > current_tick {
                        self.dispatch.time.advance(next_tick - current_tick);
                        continue;
                    }
                }
                break;
            };
            self.prepare_remote_shellcode_thread_if_needed(tid)?;
            if self.core.scheduler.thread_state(tid) != Some("running") {
                continue;
            }
            let _ = self.log_scheduler_event("SCHED_SELECT", Some(tid), None, None);
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("scheduler.switch_to");
                let _ = self
                    .core
                    .scheduler
                    .switch_to(tid, &mut self.core.process_env);
            }
            let budget = remaining.min(self.core.scheduler.time_slice_instructions());
            let before = self.core.instruction_count;
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("interpreter.thread_slice_total");
                self.run_interpreter_thread_slice(tid, budget)?;
            }
            let consumed = self.core.instruction_count.saturating_sub(before).max(1);
            let _ =
                self.log_scheduler_event("SCHED_SLICE", Some(tid), Some(budget), Some(consumed));
            if self.core.scheduler.thread_state(tid) == Some("terminated") {
                self.finalize_terminated_thread(tid)?;
            }
            remaining = remaining.saturating_sub(consumed);
            self.check_observation_checkpoints()?;
            if Some(tid) == self.core.main_thread_tid
                && self.core.scheduler.thread_state(tid) == Some("terminated")
            {
                self.core.exit_code = self
                    .core
                    .scheduler
                    .thread_exit_code(tid)
                    .flatten()
                    .or(self.core.exit_code);
                if self.core.process_exit_requested || !self.core.scheduler.has_live_threads() {
                    break;
                }
            }
            self.dispatch
                .time
                .advance(self.core.scheduler.time_slice_ms());
        }
        self.core.stop_reason = Some(if remaining == 0 {
            RunStopReason::InstructionBudgetExhausted
        } else if self.core.process_exit_requested {
            RunStopReason::ProcessExit
        } else if !self.core.scheduler.has_live_threads() {
            RunStopReason::AllThreadsTerminated
        } else if self
            .core
            .main_thread_tid
            .and_then(|tid| self.core.scheduler.thread_state(tid))
            == Some("terminated")
        {
            RunStopReason::MainThreadTerminated
        } else {
            RunStopReason::SchedulerIdle
        });
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn run_native_scheduler_main(&mut self) -> Result<(), VmError> {
        let main_module = self.load()?.clone();
        let entry_module = self
            .core
            .entry_module
            .as_ref()
            .cloned()
            .unwrap_or_else(|| main_module.clone());
        let entry_address = self.core.entry_address.unwrap_or(entry_module.entrypoint);
        let entry_arguments = self.core.entry_arguments.clone();
        let mut skipped_bases = vec![main_module.base];
        if entry_module.base != main_module.base {
            skipped_bases.push(entry_module.base);
        }
        self.run_loaded_module_initializers(&skipped_bases)?;
        self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
        self.prepare_scheduler_main_thread(entry_address, &entry_arguments)?;
        self.complete_process_startup_sequence()?;
        self.log_entry_invoke(&entry_module, entry_address, &entry_arguments)?;
        self.run_unicorn_scheduler_loop()
    }

    pub(super) fn run_interpreter_scheduler_main(&mut self) -> Result<(), VmError> {
        let main_module = self.load()?.clone();
        let entry_module = self
            .core
            .entry_module
            .as_ref()
            .cloned()
            .unwrap_or_else(|| main_module.clone());
        let entry_address = self.core.entry_address.unwrap_or(entry_module.entrypoint);
        let entry_arguments = self.core.entry_arguments.clone();
        let mut skipped_bases = vec![main_module.base];
        if entry_module.base != main_module.base {
            skipped_bases.push(entry_module.base);
        }
        self.run_loaded_module_initializers(&skipped_bases)?;
        match self.core.entry_invocation {
            EntryInvocation::NativeEntrypoint => {
                self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
            }
            EntryInvocation::Export => {
                if self.core.entry_module_requires_attach {
                    self.run_module_initializers(&entry_module, "entry")?;
                } else {
                    self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
                }
            }
        }
        self.prepare_scheduler_main_thread(entry_address, &entry_arguments)?;
        self.complete_process_startup_sequence()?;
        self.log_entry_invoke(&entry_module, entry_address, &entry_arguments)?;
        self.run_scheduler_loop()
    }

    #[allow(dead_code)]
    pub(super) fn prepare_scheduler_main_thread(
        &mut self,
        start_address: u64,
        arguments: &[u64],
    ) -> Result<(), VmError> {
        let main_tid = self
            .core
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let thread = self
            .core
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?;
        self.core
            .scheduler
            .set_thread_start_address(main_tid, start_address)
            .ok_or(VmError::RuntimeInvariant(
                "failed to set main thread entrypoint",
            ))?;
        self.core
            .scheduler
            .set_thread_parameter(main_tid, arguments.first().copied().unwrap_or(0))
            .ok_or(VmError::RuntimeInvariant(
                "failed to set main thread parameter",
            ))?;
        self.core
            .scheduler
            .set_thread_exit_address(main_tid, self.core.native_return_sentinel)
            .ok_or(VmError::RuntimeInvariant(
                "failed to set main thread exit address",
            ))?;
        let stack_top = thread.stack_top;
        let thread_context = crate::runtime::thread_context::ThreadContext {
            teb_base: thread.teb_base,
            stack_base: thread.stack_base,
            stack_limit: thread.stack_limit,
        };
        self.initialize_scheduler_thread_context(main_tid, thread_context, stack_top)?;
        let mut registers = self
            .core
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?
            .registers;
        if self.core.arch.is_x86() {
            let saved_esp = registers.esp;
            let mut frame = Vec::with_capacity((arguments.len() + 1) * 4);
            frame.extend_from_slice(&(self.core.native_return_sentinel as u32).to_le_bytes());
            for value in arguments {
                frame.extend_from_slice(&(*value as u32).to_le_bytes());
            }
            let new_esp = saved_esp
                .checked_sub(frame.len() as u64)
                .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
            self.core.modules.memory_mut().write(new_esp, &frame)?;
            registers.esp = new_esp;
            registers.eip = start_address;
        } else {
            let saved_rsp = registers.rsp;
            let stack_arg_count = arguments.len().saturating_sub(4);
            let frame_size = 0x28 + stack_arg_count * 8;
            let new_rsp = saved_rsp
                .checked_sub(frame_size as u64)
                .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
            let mut frame = vec![0u8; frame_size];
            frame[0..8].copy_from_slice(&self.core.native_return_sentinel.to_le_bytes());
            for (index, value) in arguments.iter().skip(4).enumerate() {
                let offset = 0x28 + index * 8;
                frame[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            self.core.modules.memory_mut().write(new_rsp, &frame)?;
            registers.rcx = arguments.first().copied().unwrap_or(0);
            registers.rdx = arguments.get(1).copied().unwrap_or(0);
            registers.r8 = arguments.get(2).copied().unwrap_or(0);
            registers.r9 = arguments.get(3).copied().unwrap_or(0);
            registers.rsp = new_rsp;
            registers.rip = start_address;
        }
        self.core
            .scheduler
            .set_thread_registers(main_tid, registers)
            .ok_or(VmError::RuntimeInvariant(
                "failed to seed main thread entry frame",
            ))?;
        self.core
            .scheduler
            .mark_thread_ready(main_tid)
            .ok_or(VmError::RuntimeInvariant("failed to ready main thread"))?;
        self.core
            .scheduler
            .switch_to(main_tid, &mut self.core.process_env)
            .ok_or(VmError::RuntimeInvariant("failed to bind main thread"))?;
        self.sync_native_support_state()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn run_unicorn_scheduler_loop(&mut self) -> Result<(), VmError> {
        let mut remaining = self.remaining_run_budget();
        if remaining == 0 {
            self.core.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
            return Ok(());
        }
        while remaining > 0 {
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("scheduler.poll_blocked_threads");
                self.core
                    .scheduler
                    .poll_blocked_threads(self.dispatch.time.current().tick_ms);
            }
            let Some(tid) = self.core.scheduler.next_ready_tid() else {
                let _ = self.log_scheduler_event("SCHED_IDLE", None, None, None);
                if !self.core.scheduler.has_live_threads() {
                    break;
                }
                if let Some(next_tick) = self.core.scheduler.next_wake_tick() {
                    let current_tick = self.dispatch.time.current().tick_ms;
                    if next_tick > current_tick {
                        self.dispatch.time.advance(next_tick - current_tick);
                        continue;
                    }
                }
                break;
            };
            self.prepare_remote_shellcode_thread_if_needed(tid)?;
            if self.core.scheduler.thread_state(tid) != Some("running") {
                continue;
            }
            let _ = self.log_scheduler_event("SCHED_SELECT", Some(tid), None, None);
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("scheduler.switch_to");
                self.core
                    .scheduler
                    .switch_to(tid, &mut self.core.process_env)
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to switch scheduler thread",
                    ))?;
            }
            self.sync_native_support_state()?;
            let budget = remaining.min(self.core.scheduler.time_slice_instructions());
            let before = self.core.instruction_count;
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("unicorn.thread_slice_total");
                self.run_unicorn_thread_slice(tid, budget)?;
            }
            let consumed = self.core.instruction_count.saturating_sub(before).max(1);
            let _ =
                self.log_scheduler_event("SCHED_SLICE", Some(tid), Some(budget), Some(consumed));
            remaining = remaining.saturating_sub(consumed);
            self.check_observation_checkpoints()?;

            if self.core.scheduler.thread_state(tid) == Some("terminated") {
                self.finalize_terminated_thread(tid)?;
            }
            if Some(tid) == self.core.main_thread_tid
                && self.core.scheduler.thread_state(tid) == Some("terminated")
            {
                self.core.exit_code = self
                    .core
                    .scheduler
                    .thread_exit_code(tid)
                    .flatten()
                    .or(self.core.exit_code);
                if self.core.process_exit_requested || !self.core.scheduler.has_live_threads() {
                    break;
                }
            }

            self.dispatch
                .time
                .advance(self.core.scheduler.time_slice_ms());
        }
        self.core.stop_reason = Some(if remaining == 0 {
            RunStopReason::InstructionBudgetExhausted
        } else if self.core.process_exit_requested {
            RunStopReason::ProcessExit
        } else if !self.core.scheduler.has_live_threads() {
            RunStopReason::AllThreadsTerminated
        } else if self
            .core
            .main_thread_tid
            .and_then(|tid| self.core.scheduler.thread_state(tid))
            == Some("terminated")
        {
            RunStopReason::MainThreadTerminated
        } else {
            RunStopReason::SchedulerIdle
        });
        Ok(())
    }

    pub(super) fn run_native_main(&mut self) -> Result<(), VmError> {
        self.debug_load_stage("run_native:start");
        let main_module = self.load()?.clone();
        let entry_module = self
            .core
            .entry_module
            .as_ref()
            .cloned()
            .unwrap_or_else(|| main_module.clone());
        let entry_address = self.core.entry_address.unwrap_or(entry_module.entrypoint);
        let entry_arguments = self.core.entry_arguments.clone();
        let mut skipped_bases = vec![main_module.base];
        if entry_module.base != main_module.base {
            skipped_bases.push(entry_module.base);
        }
        self.run_loaded_module_initializers(&skipped_bases)?;
        self.debug_load_stage("run_native:module_initializers_done");
        match self.core.entry_invocation {
            EntryInvocation::NativeEntrypoint => {
                self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
            }
            EntryInvocation::Export => {
                if self.core.entry_module_requires_attach {
                    self.run_module_initializers(&entry_module, "entry")?;
                } else {
                    self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
                }
            }
        }
        self.debug_load_stage("run_native:entry_tls_or_attach_done");
        self.prepare_scheduler_main_thread(entry_address, &entry_arguments)?;
        self.debug_load_stage("run_native:main_thread_prepared");
        self.complete_process_startup_sequence()?;
        self.debug_load_stage("run_native:startup_sequence_completed");
        self.log_entry_invoke(&entry_module, entry_address, &entry_arguments)?;
        self.debug_load_stage("run_native:entry_logged");
        self.dispatch.force_native_return = false;
        if self.core.arch.is_x64() {
            self.debug_load_stage("run_native:before_unicorn_loop");
            return self.run_unicorn_scheduler_loop();
        }
        let retval = self.call_native_with_entry_frame(entry_address, &entry_arguments)? as u32;
        if self.core.stop_reason == Some(RunStopReason::InstructionBudgetExhausted) {
            return Ok(());
        }
        let main_thread_state = self
            .core
            .main_thread_tid
            .and_then(|tid| self.core.scheduler.thread_state(tid));
        if matches!(main_thread_state, Some("waiting" | "sleeping" | "ready")) {
            return if self.unicorn_state.unicorn.is_some() {
                self.run_unicorn_scheduler_loop()
            } else {
                self.run_scheduler_loop()
            };
        }
        if self.core.exit_code.is_none() {
            self.core.exit_code = Some(retval);
        }
        if let Some(main_tid) = self.core.main_thread_tid {
            let _ = self
                .core
                .scheduler
                .switch_to(main_tid, &mut self.core.process_env);
            let _ = self.terminate_current_thread(self.core.exit_code.unwrap_or(retval));
            self.release_terminated_thread_stack(main_tid)?;
        }
        if self.core.process_exit_requested || !self.core.scheduler.has_live_threads() {
            self.core.stop_reason = Some(if self.core.process_exit_requested {
                RunStopReason::ProcessExit
            } else {
                RunStopReason::AllThreadsTerminated
            });
            return Ok(());
        }
        self.run_unicorn_scheduler_loop()
    }
}
