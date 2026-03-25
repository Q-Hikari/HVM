use super::*;

impl VirtualExecutionEngine {
    fn user32_timer_next_due_tick(next_due_tick: u64, elapse_ms: u32, now_tick: u64) -> u64 {
        let interval = elapse_ms.max(1) as u64;
        if next_due_tick > now_tick {
            return next_due_tick;
        }
        let missed_intervals = now_tick.saturating_sub(next_due_tick) / interval + 1;
        next_due_tick.saturating_add(missed_intervals.saturating_mul(interval))
    }

    pub(super) fn user32_purge_timer_messages(&mut self, thread_id: u32, timer_ids: &[u32]) {
        if timer_ids.is_empty() {
            return;
        }
        if let Some(queue) = self.user32_state.thread_messages.get_mut(&thread_id) {
            queue.retain(|message| {
                !(message.message == WM_TIMER && timer_ids.contains(&(message.w_param as u32)))
            });
        }
        if let Some(queue) = self.user32_state.pending_hook_messages.get_mut(&thread_id) {
            queue.retain(|message| {
                !(message.message == WM_TIMER && timer_ids.contains(&(message.w_param as u32)))
            });
        }
    }

    pub(super) fn user32_inject_due_timer_messages(
        &mut self,
        thread_id: u32,
        max_messages: usize,
    ) -> usize {
        let now_tick = self.time.current().tick_ms;
        let due_timers: Vec<User32TimerRecord> = self
            .user32_state
            .timers
            .values()
            .filter(|timer| timer.thread_id == thread_id && timer.next_due_tick <= now_tick)
            .cloned()
            .collect();
        let mut injected = 0usize;
        for timer in due_timers {
            let next_due_tick =
                Self::user32_timer_next_due_tick(timer.next_due_tick, timer.elapse_ms, now_tick);
            if let Some(live_timer) = self.user32_state.timers.get_mut(&timer.timer_id) {
                live_timer.next_due_tick = next_due_tick;
            }
            if injected >= max_messages.max(1) {
                continue;
            }
            let already_queued = self
                .user32_state
                .thread_messages
                .get(&thread_id)
                .map(|queue| {
                    queue.iter().any(|message| {
                        message.message == WM_TIMER && message.w_param == timer.timer_id as u64
                    })
                })
                .unwrap_or(false);
            if already_queued {
                continue;
            }
            let message = self.user32_timer_message(
                thread_id,
                timer.hwnd as u64,
                timer.timer_id,
                timer.callback,
            );
            self.user32_state.synthetic_timer_messages =
                self.user32_state.synthetic_timer_messages.saturating_add(1);
            Self::user32_queue_message(&mut self.user32_state.thread_messages, message.clone());
            Self::user32_queue_message(&mut self.user32_state.pending_hook_messages, message);
            injected = injected.saturating_add(1);
        }
        injected
    }

    pub(super) fn user32_message_wait_delay_ms(&self, thread_id: u32) -> u32 {
        let now_tick = self.time.current().tick_ms;
        self.user32_state
            .timers
            .values()
            .filter(|timer| timer.thread_id == thread_id)
            .map(|timer| {
                timer
                    .next_due_tick
                    .saturating_sub(now_tick)
                    .clamp(1, USER32_MESSAGE_WAIT_POLL_MS as u64) as u32
            })
            .min()
            .unwrap_or(USER32_MESSAGE_WAIT_POLL_MS)
    }

    pub(super) fn user32_invoke_timer_callback(
        &mut self,
        message: &User32MessageRecord,
    ) -> Result<u64, VmError> {
        if message.message != WM_TIMER || message.l_param == 0 {
            return Ok(0);
        }
        if self.arch.is_x64() && unicorn_context_active() {
            self.schedule_active_x64_user32_timer_callback(
                message.l_param,
                message.hwnd,
                message.message,
                message.w_param,
                self.time.current().tick_ms,
            )?;
            return Ok(0);
        }
        self.call_native_with_entry_frame(
            message.l_param,
            &[
                message.hwnd,
                message.message as u64,
                message.w_param,
                self.time.current().tick_ms,
            ],
        )
    }

    pub(in crate::runtime::engine) fn user32_register_timer(
        &mut self,
        hwnd: u32,
        requested_id: u32,
        elapse_ms: u32,
        callback: u64,
    ) -> Result<u64, VmError> {
        let _profile = self.runtime_profiler.start_scope("user32.set_timer");
        self.user32_state.set_timer_calls = self.user32_state.set_timer_calls.saturating_add(1);
        let thread_id = self.user32_current_thread_id();
        let interval_ms = elapse_ms.max(1);
        let timer_id = if requested_id != 0 {
            requested_id
        } else {
            let next = self.user32_state.next_timer_id.max(1);
            self.user32_state.next_timer_id = self.user32_state.next_timer_id.saturating_add(1);
            next
        };
        self.user32_state.timers.insert(
            timer_id,
            User32TimerRecord {
                hwnd,
                timer_id,
                elapse_ms: interval_ms,
                callback,
                thread_id,
                next_due_tick: self
                    .time
                    .current()
                    .tick_ms
                    .saturating_add(interval_ms as u64),
            },
        );
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(timer_id as u64)
    }

    pub(super) fn user32_kill_timer(&mut self, hwnd: u32, timer_id: u32) -> bool {
        self.user32_state.kill_timer_calls = self.user32_state.kill_timer_calls.saturating_add(1);
        let thread_id = self.user32_current_thread_id();
        let timer_ids: Vec<u32> = self
            .user32_state
            .timers
            .iter()
            .filter_map(|(id, timer)| {
                let hwnd_matches = hwnd == 0 || timer.hwnd == hwnd;
                let id_matches = timer_id == 0 || *id == timer_id;
                let thread_matches = timer.thread_id == thread_id;
                (hwnd_matches && id_matches && thread_matches).then_some(*id)
            })
            .collect();
        for id in &timer_ids {
            let _ = self.user32_state.timers.remove(id);
        }
        self.user32_purge_timer_messages(thread_id, &timer_ids);
        !timer_ids.is_empty()
    }

    fn ensure_user32_timerproc_continue_stub(&mut self) -> u64 {
        self.hooks
            .binding_address("user32.dll", "__vm_timerproc_continue")
            .unwrap_or_else(|| self.bind_hook_for_test("user32.dll", "__vm_timerproc_continue"))
    }

    pub(super) fn schedule_active_x64_user32_timer_callback(
        &mut self,
        callback: u64,
        hwnd: u64,
        message: u32,
        timer_id: u64,
        timer_tick: u64,
    ) -> Result<(), VmError> {
        let continuation = self.ensure_user32_timerproc_continue_stub();
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let entry_rsp = unsafe { api.reg_read_raw(uc, UC_X86_REG_RSP) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_read(rsp)",
                detail,
            }
        })?;
        let return_address = unsafe { api.mem_read_raw(uc, entry_rsp, 8) }
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_mem_read(stack)",
                detail,
            })
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))?;
        let resume_rsp = entry_rsp.checked_add(8).ok_or(VmError::RuntimeInvariant(
            "user32 timer callback resume stack overflow",
        ))?;
        let call_rsp = entry_rsp
            .checked_sub(0x28)
            .ok_or(VmError::RuntimeInvariant(
                "user32 timer callback stack underflow",
            ))?;
        let mut frame = [0u8; 0x28];
        frame[..8].copy_from_slice(&continuation.to_le_bytes());
        self.modules.memory_mut().write(call_rsp, &frame)?;
        unsafe { api.mem_write_raw(uc, call_rsp, &frame) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_mem_write(user32_timerproc_continuation)",
                detail,
            }
        })?;
        for (regid, value, op) in [
            (UC_X86_REG_RIP, callback, "uc_reg_write(rip)"),
            (UC_X86_REG_RSP, call_rsp, "uc_reg_write(rsp)"),
            (UC_X86_REG_RCX, hwnd, "uc_reg_write(rcx)"),
            (UC_X86_REG_RDX, message as u64, "uc_reg_write(rdx)"),
            (UC_X86_REG_R8, timer_id, "uc_reg_write(r8)"),
            (UC_X86_REG_R9, timer_tick, "uc_reg_write(r9)"),
        ] {
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        self.pending_user32_timer_callbacks
            .push(PendingUser32TimerCallback {
                entry_rsp,
                resume_rsp,
                return_address,
            });
        self.defer_api_return = true;
        Ok(())
    }

    fn complete_active_x64_user32_timer_callback(
        &mut self,
        state: PendingUser32TimerCallback,
        retval: u64,
    ) -> Result<(), VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        for (regid, value, op) in [
            (UC_X86_REG_RAX, retval, "uc_reg_write(rax)"),
            (UC_X86_REG_RSP, state.resume_rsp, "uc_reg_write(rsp)"),
            (UC_X86_REG_RIP, state.return_address, "uc_reg_write(rip)"),
        ] {
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        self.defer_api_return = true;
        Ok(())
    }

    pub(super) fn resume_pending_user32_timer_callback(&mut self) -> Result<u64, VmError> {
        let callback_result = if self.arch.is_x64() && unicorn_context_active() {
            self.active_unicorn_return_value()?
        } else {
            0
        };
        let Some(state) = self.pending_user32_timer_callbacks.pop() else {
            return Ok(callback_result);
        };
        if self.arch.is_x64() && unicorn_context_active() {
            self.complete_active_x64_user32_timer_callback(state, callback_result)?;
        }
        Ok(callback_result)
    }
}
