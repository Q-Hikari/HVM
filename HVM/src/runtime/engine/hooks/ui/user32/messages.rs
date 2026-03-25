use super::*;

impl VirtualExecutionEngine {
    fn ensure_user32_sendmessage_continue_stub(&mut self) -> u64 {
        self.hooks
            .binding_address("user32.dll", "__vm_sendmessage_continue")
            .unwrap_or_else(|| self.bind_hook_for_test("user32.dll", "__vm_sendmessage_continue"))
    }

    fn schedule_active_x64_user32_sendmessage_callback(
        &mut self,
        wnd_proc: u64,
        hwnd: u64,
        message: u32,
        w_param: u64,
        l_param: u64,
    ) -> Result<(), VmError> {
        let continuation = self.ensure_user32_sendmessage_continue_stub();
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
            "user32 sendmessage resume stack overflow",
        ))?;
        let call_rsp = entry_rsp
            .checked_sub(0x28)
            .ok_or(VmError::RuntimeInvariant(
                "user32 sendmessage stack underflow",
            ))?;
        let mut frame = [0u8; 0x28];
        frame[..8].copy_from_slice(&continuation.to_le_bytes());
        self.modules.memory_mut().write(call_rsp, &frame)?;
        unsafe { api.mem_write_raw(uc, call_rsp, &frame) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_mem_write(user32_sendmessage_continuation)",
                detail,
            }
        })?;
        for (regid, value, op) in [
            (UC_X86_REG_RIP, wnd_proc, "uc_reg_write(rip)"),
            (UC_X86_REG_RSP, call_rsp, "uc_reg_write(rsp)"),
            (UC_X86_REG_RCX, hwnd, "uc_reg_write(rcx)"),
            (UC_X86_REG_RDX, message as u64, "uc_reg_write(rdx)"),
            (UC_X86_REG_R8, w_param, "uc_reg_write(r8)"),
            (UC_X86_REG_R9, l_param, "uc_reg_write(r9)"),
        ] {
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        self.pending_user32_sendmessage_callbacks
            .push(PendingUser32SendMessageCallback {
                entry_rsp,
                resume_rsp,
                return_address,
            });
        self.defer_api_return = true;
        Ok(())
    }

    fn complete_active_x64_user32_sendmessage_callback(
        &mut self,
        state: PendingUser32SendMessageCallback,
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

    pub(super) fn resume_pending_user32_sendmessage_callback(&mut self) -> Result<u64, VmError> {
        let callback_result = if self.arch.is_x64() && unicorn_context_active() {
            self.active_unicorn_return_value()?
        } else {
            0
        };
        let Some(state) = self.pending_user32_sendmessage_callbacks.pop() else {
            return Ok(callback_result);
        };
        if self.arch.is_x64() && unicorn_context_active() {
            self.complete_active_x64_user32_sendmessage_callback(state, callback_result)?;
        }
        Ok(callback_result)
    }

    pub(super) fn user32_queue_message(
        queue_map: &mut BTreeMap<u32, VecDeque<User32MessageRecord>>,
        record: User32MessageRecord,
    ) {
        let queue = queue_map.entry(record.thread_id).or_default();
        if queue.len() >= 32 {
            let _ = queue.pop_front();
        }
        queue.push_back(record);
    }

    fn user32_message_record(
        &mut self,
        thread_id: u32,
        hwnd: u64,
        message: u32,
        w_param: u64,
        l_param: u64,
        hook_code: i32,
    ) -> User32MessageRecord {
        let packed = self.user32_message_pos();
        let x = packed as u16 as i16 as i32;
        let y = (packed >> 16) as u16 as i16 as i32;
        User32MessageRecord {
            thread_id,
            hwnd,
            message,
            w_param,
            l_param,
            time: self.time.current().tick_ms.min(u32::MAX as u64) as u32,
            point_x: x,
            point_y: y,
            hook_code,
        }
    }

    pub(super) fn user32_seed_msgfilter_message(&mut self, thread_id: u32) -> User32MessageRecord {
        let active_window = self.user32_window_handle("active");
        self.user32_message_record(
            thread_id,
            active_window as u64,
            WM_KEYDOWN,
            VK_RETURN as u64,
            1,
            MSGF_DIALOGBOX,
        )
    }

    pub(super) fn user32_timer_message(
        &mut self,
        thread_id: u32,
        hwnd: u64,
        timer_id: u32,
        callback: u64,
    ) -> User32MessageRecord {
        self.user32_message_record(
            thread_id,
            hwnd,
            WM_TIMER,
            timer_id as u64,
            callback,
            MSGF_DIALOGBOX,
        )
    }

    fn user32_idle_message(&mut self, thread_id: u32) -> User32MessageRecord {
        let active_window = self.user32_window_handle("active");
        self.user32_message_record(
            thread_id,
            active_window as u64,
            WM_NULL,
            0,
            0,
            MSGF_DIALOGBOX,
        )
    }

    fn user32_message_matches(
        message: &User32MessageRecord,
        hwnd_filter: u32,
        min_filter: u32,
        max_filter: u32,
    ) -> bool {
        let upper = if min_filter == 0 && max_filter == 0 {
            u32::MAX
        } else if max_filter == 0 {
            min_filter
        } else {
            max_filter
        };
        let hwnd_matches = hwnd_filter == 0 || message.hwnd == hwnd_filter as u64;
        let range_matches = message.message >= min_filter && message.message <= upper;
        hwnd_matches && range_matches
    }

    fn user32_read_message_from_memory(
        &self,
        address: u64,
    ) -> Result<Option<User32MessageRecord>, VmError> {
        if address == 0 {
            return Ok(None);
        }
        let message = if self.arch.is_x86() {
            User32MessageRecord {
                thread_id: self.user32_current_thread_id(),
                hwnd: self.read_u32(address)? as u64,
                message: self.read_u32(address + 4)?,
                w_param: self.read_u32(address + 8)? as u64,
                l_param: self.read_u32(address + 12)? as u64,
                time: self.read_u32(address + 16)?,
                point_x: self.read_i32(address + 20)?,
                point_y: self.read_i32(address + 24)?,
                hook_code: MSGF_DIALOGBOX,
            }
        } else {
            User32MessageRecord {
                thread_id: self.user32_current_thread_id(),
                hwnd: self.read_pointer_value(address)?,
                message: self.read_u32(address + 8)?,
                w_param: self.read_pointer_value(address + 16)?,
                l_param: self.read_pointer_value(address + 24)?,
                time: self.read_u32(address + 32)?,
                point_x: self.read_i32(address + 36)?,
                point_y: self.read_i32(address + 40)?,
                hook_code: MSGF_DIALOGBOX,
            }
        };
        Ok(Some(message))
    }

    pub(super) fn user32_write_message_to_memory(
        &mut self,
        address: u64,
        message: &User32MessageRecord,
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        let bytes = if self.arch.is_x86() {
            let mut bytes = vec![0u8; 32];
            bytes[0..4].copy_from_slice(&(message.hwnd as u32).to_le_bytes());
            bytes[4..8].copy_from_slice(&message.message.to_le_bytes());
            bytes[8..12].copy_from_slice(&(message.w_param as u32).to_le_bytes());
            bytes[12..16].copy_from_slice(&(message.l_param as u32).to_le_bytes());
            bytes[16..20].copy_from_slice(&message.time.to_le_bytes());
            bytes[20..24].copy_from_slice(&message.point_x.to_le_bytes());
            bytes[24..28].copy_from_slice(&message.point_y.to_le_bytes());
            bytes
        } else {
            let mut bytes = vec![0u8; 48];
            bytes[0..8].copy_from_slice(&message.hwnd.to_le_bytes());
            bytes[8..12].copy_from_slice(&message.message.to_le_bytes());
            bytes[16..24].copy_from_slice(&message.w_param.to_le_bytes());
            bytes[24..32].copy_from_slice(&message.l_param.to_le_bytes());
            bytes[32..36].copy_from_slice(&message.time.to_le_bytes());
            bytes[36..40].copy_from_slice(&message.point_x.to_le_bytes());
            bytes[40..44].copy_from_slice(&message.point_y.to_le_bytes());
            bytes
        };
        Ok(self.modules.memory_mut().write(address, &bytes)?)
    }

    pub(super) fn user32_note_window_activity(
        &mut self,
        hwnd: u32,
        message: u32,
        w_param: u32,
        l_param: u32,
    ) -> Result<(), VmError> {
        let thread_id = self.user32_current_thread_id();
        let resolved_hwnd = if hwnd != 0 {
            hwnd
        } else {
            self.user32_window_handle("active")
        };
        let record = self.user32_message_record(
            thread_id,
            resolved_hwnd as u64,
            message,
            w_param as u64,
            l_param as u64,
            MSGF_DIALOGBOX,
        );
        Self::user32_queue_message(&mut self.user32_state.thread_messages, record);
        Ok(())
    }

    pub(super) fn user32_send_message(
        &mut self,
        hwnd: u64,
        message: u32,
        w_param: u64,
        l_param: u64,
    ) -> Result<u64, VmError> {
        let resolved_hwnd = if (hwnd & 0xFFFF_FFFF) != 0 {
            (hwnd & 0xFFFF_FFFF) as u32
        } else {
            self.user32_window_handle("active")
        };
        let wnd_proc = self.user32_window_proc(resolved_hwnd);
        if wnd_proc == 0 {
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }
        if self.arch.is_x64() && unicorn_context_active() {
            self.schedule_active_x64_user32_sendmessage_callback(
                wnd_proc,
                resolved_hwnd as u64,
                message,
                w_param,
                l_param,
            )?;
            return Ok(0);
        }
        let result = self.call_native_with_entry_frame(
            wnd_proc,
            &[resolved_hwnd as u64, message as u64, w_param, l_param],
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(result)
    }

    fn user32_ensure_poll_message(&mut self, thread_id: u32) {
        self.user32_inject_due_timer_messages(thread_id, 4);
    }

    fn user32_take_message(
        &mut self,
        thread_id: u32,
        hwnd_filter: u32,
        min_filter: u32,
        max_filter: u32,
        remove: bool,
    ) -> Option<User32MessageRecord> {
        self.user32_ensure_poll_message(thread_id);
        let queue = self
            .user32_state
            .thread_messages
            .entry(thread_id)
            .or_default();
        let index = queue.iter().position(|message| {
            Self::user32_message_matches(message, hwnd_filter, min_filter, max_filter)
        })?;
        if remove {
            queue.remove(index)
        } else {
            queue.get(index).cloned()
        }
    }

    pub(super) fn user32_peek_message(
        &mut self,
        lp_msg: u64,
        hwnd_filter: u32,
        min_filter: u32,
        max_filter: u32,
        remove: bool,
    ) -> Result<u64, VmError> {
        let _profile = self.runtime_profiler.start_scope("user32.peek_message");
        self.user32_state.peek_message_calls =
            self.user32_state.peek_message_calls.saturating_add(1);
        let thread_id = self.user32_current_thread_id();
        self.user32_pump_pending_hook_messages(thread_id, 2)?;
        let message =
            self.user32_take_message(thread_id, hwnd_filter, min_filter, max_filter, remove);
        if let Some(message) = message {
            self.user32_write_message_to_memory(lp_msg, &message)?;
            return Ok(1);
        }
        if lp_msg != 0 {
            self.modules.memory_mut().write(lp_msg, &[0u8; 28])?;
        }
        Ok(0)
    }

    pub(in crate::runtime::engine) fn user32_get_message(
        &mut self,
        lp_msg: u64,
        hwnd_filter: u32,
        min_filter: u32,
        max_filter: u32,
    ) -> Result<u64, VmError> {
        let _profile = self.runtime_profiler.start_scope("user32.get_message");
        self.user32_state.get_message_calls = self.user32_state.get_message_calls.saturating_add(1);
        let thread_id = self.user32_current_thread_id();
        let _ = self.scheduler.consume_wait_result();
        self.user32_pump_pending_hook_messages(thread_id, 2)?;
        if let Some(message) =
            self.user32_take_message(thread_id, hwnd_filter, min_filter, max_filter, true)
        {
            self.user32_write_message_to_memory(lp_msg, &message)?;
            return Ok((message.message != WM_QUIT) as u64);
        }
        if self.scheduler.current_tid().is_some() {
            let _ = self.scheduler.sleep_current_thread(
                self.time.current().tick_ms,
                self.user32_message_wait_delay_ms(thread_id),
                false,
            );
            self.request_thread_yield("user32_get_message_wait", true);
            return Ok(0);
        }
        let message = self.user32_idle_message(thread_id);
        self.user32_state.synthetic_idle_messages =
            self.user32_state.synthetic_idle_messages.saturating_add(1);
        self.user32_write_message_to_memory(lp_msg, &message)?;
        Ok(1)
    }

    pub(super) fn user32_translate_message(&mut self) -> u64 {
        let _profile = self
            .runtime_profiler
            .start_scope("user32.translate_message");
        self.user32_state.translate_message_calls =
            self.user32_state.translate_message_calls.saturating_add(1);
        1
    }

    pub(in crate::runtime::engine) fn user32_dispatch_message(
        &mut self,
        lp_msg: u64,
    ) -> Result<u64, VmError> {
        let _profile = self.runtime_profiler.start_scope("user32.dispatch_message");
        self.user32_state.dispatch_message_calls =
            self.user32_state.dispatch_message_calls.saturating_add(1);
        let thread_id = self.user32_current_thread_id();
        self.user32_pump_pending_hook_messages(thread_id, 1)?;
        if let Some(message) = self.user32_read_message_from_memory(lp_msg)? {
            if message.message == WM_TIMER && message.l_param != 0 {
                return self.user32_invoke_timer_callback(&message);
            }
            if message.hwnd == 0 {
                return Ok(0);
            }
            return self.user32_send_message(
                message.hwnd,
                message.message,
                message.w_param,
                message.l_param,
            );
        }
        Ok(0)
    }

    pub(super) fn user32_post_quit_message(&mut self, exit_code: u32) -> Result<u64, VmError> {
        let thread_id = self.user32_current_thread_id();
        let message =
            self.user32_message_record(thread_id, 0, WM_QUIT, exit_code as u64, 0, MSGF_DIALOGBOX);
        Self::user32_queue_message(&mut self.user32_state.thread_messages, message);
        Ok(0)
    }
}
