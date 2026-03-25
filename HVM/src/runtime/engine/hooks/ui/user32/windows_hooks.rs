use super::*;

impl VirtualExecutionEngine {
    fn user32_hook_targets_thread(hook: &User32HookRecord, thread_id: u32) -> bool {
        hook.thread_id == 0 || hook.thread_id == thread_id
    }

    fn user32_invoke_hook_callback(
        &mut self,
        hook: &User32HookRecord,
        message: &User32MessageRecord,
    ) -> Result<u64, VmError> {
        if hook.callback == 0 || !self.arch.is_x86() {
            return Ok(0);
        }
        let (saved_esp, saved_eflags) = self.thread_entry_x86_call_context()?;
        let scratch = saved_esp.saturating_sub(0x80);
        self.user32_write_message_to_memory(scratch, message)?;
        self.call_x86_native_interpreter_context(
            hook.callback,
            &[message.hook_code as u64, 0, scratch],
            saved_esp,
            saved_eflags,
            NativeCallRunMode::Standalone,
        )
    }

    pub(super) fn user32_register_hook(
        &mut self,
        hook_type: i32,
        callback: u64,
        module_handle: u64,
        thread_id: u32,
    ) -> Result<u64, VmError> {
        if callback == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let resolved_thread_id = if thread_id == 0 {
            self.user32_current_thread_id()
        } else {
            thread_id
        };
        let handle = self.allocate_object_handle();
        self.user32_state.hooks.insert(
            handle,
            User32HookRecord {
                handle,
                hook_type,
                callback,
                module_handle,
                thread_id: resolved_thread_id,
                seeded: false,
                delivery_count: 0,
            },
        );
        if hook_type == WH_MSGFILTER {
            let keyboard_seed = self.user32_seed_msgfilter_message(resolved_thread_id);
            Self::user32_queue_message(&mut self.user32_state.pending_hook_messages, keyboard_seed);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(handle as u64)
    }

    pub(super) fn user32_unhook(&mut self, handle: u32) -> bool {
        let removed = self.user32_state.hooks.remove(&handle).is_some();
        self.set_last_error(if removed {
            ERROR_SUCCESS as u32
        } else {
            ERROR_INVALID_HANDLE as u32
        });
        removed
    }

    pub(super) fn user32_pump_pending_hook_messages(
        &mut self,
        thread_id: u32,
        max_messages: usize,
    ) -> Result<(), VmError> {
        for _ in 0..max_messages.max(1) {
            let Some(message) = ({
                self.user32_state
                    .pending_hook_messages
                    .entry(thread_id)
                    .or_default()
                    .pop_front()
            }) else {
                break;
            };
            let hook_handles: Vec<u32> = self
                .user32_state
                .hooks
                .iter()
                .filter_map(|(handle, hook)| {
                    Self::user32_hook_targets_thread(hook, thread_id).then_some(*handle)
                })
                .collect();
            for handle in hook_handles {
                let Some(hook) = self.user32_state.hooks.get(&handle).cloned() else {
                    continue;
                };
                let callback_result = self
                    .user32_invoke_hook_callback(&hook, &message)
                    .unwrap_or(0);
                self.user32_state.hook_callback_dispatches =
                    self.user32_state.hook_callback_dispatches.saturating_add(1);
                if let Some(live_hook) = self.user32_state.hooks.get_mut(&handle) {
                    live_hook.seeded = true;
                    live_hook.delivery_count = live_hook.delivery_count.saturating_add(1);
                }
                if callback_result != 0 {
                    break;
                }
            }
        }
        Ok(())
    }
}
