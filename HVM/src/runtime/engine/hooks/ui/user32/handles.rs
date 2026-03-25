use super::*;

impl VirtualExecutionEngine {
    fn user32_class_key(name: &str) -> String {
        name.trim().to_ascii_lowercase()
    }

    fn user32_identifier_atom(identifier: u64) -> Option<u16> {
        (identifier != 0 && (identifier >> 16) == 0).then_some(identifier as u16)
    }

    fn user32_read_text_identifier(
        &self,
        identifier: u64,
        wide: bool,
    ) -> Result<Option<String>, VmError> {
        if identifier == 0 || Self::user32_identifier_atom(identifier).is_some() {
            return Ok(None);
        }
        let text = if wide {
            self.read_wide_string_from_memory(identifier)?
        } else {
            self.read_c_string_from_memory(identifier)?
        };
        let trimmed = text.trim();
        Ok((!trimmed.is_empty()).then_some(trimmed.to_string()))
    }

    fn user32_wndclassex_layout(&self) -> (u64, u64, u64) {
        if self.arch.is_x86() {
            (8, 20, 40)
        } else {
            (8, 24, 64)
        }
    }

    fn user32_resolve_registered_class(
        &self,
        identifier: u64,
        wide: bool,
    ) -> Result<Option<User32ClassRecord>, VmError> {
        if identifier == 0 {
            return Ok(None);
        }
        if let Some(atom) = Self::user32_identifier_atom(identifier) {
            if let Some(key) = self.user32_state.class_atoms.get(&atom) {
                return Ok(self.user32_state.registered_classes.get(key).cloned());
            }
            if let Some(name) = self.global_atoms.get(&atom) {
                return Ok(self
                    .user32_state
                    .registered_classes
                    .get(&Self::user32_class_key(name))
                    .cloned());
            }
            return Ok(None);
        }
        let Some(name) = self.user32_read_text_identifier(identifier, wide)? else {
            return Ok(None);
        };
        Ok(self
            .user32_state
            .registered_classes
            .get(&Self::user32_class_key(&name))
            .cloned())
    }

    fn user32_allocate_created_window_handle(&mut self) -> u32 {
        if let Some(handle) = self
            .user32_state
            .active_window
            .filter(|handle| !self.user32_state.windows.contains_key(handle))
        {
            return handle;
        }
        self.allocate_object_handle()
    }

    pub(super) fn user32_register_class_ex(
        &mut self,
        class_ptr: u64,
        wide: bool,
    ) -> Result<u64, VmError> {
        if class_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let (wnd_proc_offset, instance_offset, class_name_offset) = self.user32_wndclassex_layout();
        let wnd_proc = self.read_pointer_value(class_ptr + wnd_proc_offset)?;
        let instance = self.read_pointer_value(class_ptr + instance_offset)?;
        let class_name_ptr = self.read_pointer_value(class_ptr + class_name_offset)?;
        let Some(class_name) = self.user32_read_text_identifier(class_name_ptr, wide)? else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        let key = Self::user32_class_key(&class_name);
        let atom = if let Some(existing) = self.user32_state.registered_classes.get(&key) {
            existing.atom
        } else {
            let next = self.user32_state.next_class_atom.max(1);
            self.user32_state.next_class_atom = next.saturating_add(1).max(1);
            next
        };
        self.user32_state.class_atoms.insert(atom, key.clone());
        self.user32_state.registered_classes.insert(
            key,
            User32ClassRecord {
                atom,
                class_name,
                wnd_proc,
                instance,
            },
        );
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(atom as u64)
    }

    pub(super) fn user32_create_window_ex(
        &mut self,
        class_identifier: u64,
        window_name_ptr: u64,
        parent: u64,
        instance: u64,
        wide: bool,
    ) -> Result<u64, VmError> {
        let class_record = self.user32_resolve_registered_class(class_identifier, wide)?;
        let class_name = if let Some(class) = class_record.as_ref() {
            class.class_name.clone()
        } else if let Some(name) = self.user32_read_text_identifier(class_identifier, wide)? {
            name
        } else if let Some(atom) = Self::user32_identifier_atom(class_identifier) {
            format!("#{atom}")
        } else {
            "window".to_string()
        };
        let title = self
            .user32_read_text_identifier(window_name_ptr, wide)?
            .unwrap_or_default();
        let handle = self.user32_allocate_created_window_handle();
        let parent_handle = (parent & 0xFFFF_FFFF) as u32;
        let owner_thread = self.user32_current_thread_id();
        self.user32_state.windows.insert(
            handle,
            User32WindowRecord {
                handle,
                class_name,
                wnd_proc: class_record
                    .as_ref()
                    .map(|record| record.wnd_proc)
                    .unwrap_or(0),
                title,
                parent: parent_handle,
                owner_thread,
                instance: class_record
                    .as_ref()
                    .map(|record| record.instance)
                    .unwrap_or(instance),
            },
        );
        self.user32_state.active_window = Some(handle);
        if self.user32_state.desktop_window.is_none() {
            self.user32_state.desktop_window = Some(handle);
        }
        if self.user32_state.shell_window.is_none() {
            self.user32_state.shell_window = Some(handle);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(handle as u64)
    }

    pub(super) fn user32_parent_handle(&self, hwnd: u32) -> u32 {
        self.user32_state
            .windows
            .get(&hwnd)
            .map(|record| record.parent)
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn user32_window_proc(&self, hwnd: u32) -> u64 {
        self.user32_state
            .windows
            .get(&hwnd)
            .map(|record| record.wnd_proc)
            .unwrap_or(0)
    }

    pub(super) fn user32_window_handle(&mut self, kind: &'static str) -> u32 {
        let handle = match kind {
            "desktop" => {
                if let Some(handle) = self.user32_state.desktop_window {
                    return handle;
                }
                let handle = self.allocate_object_handle();
                self.user32_state.desktop_window = Some(handle);
                handle
            }
            "active" => {
                if let Some(handle) = self.user32_state.active_window {
                    return handle;
                }
                let handle = self.allocate_object_handle();
                self.user32_state.active_window = Some(handle);
                handle
            }
            "shell" => {
                if let Some(handle) = self.user32_state.shell_window {
                    return handle;
                }
                let handle = self.allocate_object_handle();
                self.user32_state.shell_window = Some(handle);
                handle
            }
            _ => {
                if let Some(handle) = self.user32_state.desktop_window {
                    return handle;
                }
                let handle = self.allocate_object_handle();
                self.user32_state.desktop_window = Some(handle);
                handle
            }
        };
        if self.user32_state.desktop_window.is_none() {
            self.user32_state.desktop_window = Some(handle);
        }
        if self.user32_state.active_window.is_none() {
            self.user32_state.active_window = Some(handle);
        }
        if self.user32_state.shell_window.is_none() {
            self.user32_state.shell_window = Some(handle);
        }
        handle
    }

    pub(in crate::runtime::engine) fn user32_close_object_handle(&mut self, handle: u32) -> bool {
        let mut closed = self.user32_state.hooks.remove(&handle).is_some();
        closed |= self.user32_state.windows.remove(&handle).is_some();
        let timer_ids: Vec<u32> = self
            .user32_state
            .timers
            .iter()
            .filter_map(|(timer_id, timer)| {
                ((timer.hwnd == handle) || (*timer_id == handle)).then_some(*timer_id)
            })
            .collect();
        let mut timer_threads: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for (timer_id, timer) in &self.user32_state.timers {
            if (timer.hwnd == handle) || (*timer_id == handle) {
                timer_threads
                    .entry(timer.thread_id)
                    .or_default()
                    .push(*timer_id);
            }
        }
        for timer_id in timer_ids {
            closed |= self.user32_state.timers.remove(&timer_id).is_some();
        }
        for (thread_id, timer_ids) in timer_threads {
            self.user32_purge_timer_messages(thread_id, &timer_ids);
        }
        if self.user32_state.active_window == Some(handle) {
            self.user32_state.active_window = None;
        }
        if self.user32_state.desktop_window == Some(handle) {
            self.user32_state.desktop_window = None;
        }
        if self.user32_state.shell_window == Some(handle) {
            self.user32_state.shell_window = None;
        }
        closed
    }

    pub(super) fn user32_dc_handle(&mut self) -> u32 {
        if let Some(handle) = self.user32_state.default_dc {
            return handle;
        }
        let handle = self.allocate_object_handle();
        self.user32_state.default_dc = Some(handle);
        handle
    }

    pub(super) fn user32_icon_handle(&mut self, resource: u64) -> u32 {
        if let Some(existing_handle) = self.user32_state.default_icon {
            return existing_handle.saturating_add(resource as u32);
        }
        let base_handle: u32 = self.allocate_object_handle();
        self.user32_state.default_icon = Some(base_handle);
        base_handle.saturating_add(resource as u32)
    }

    pub(super) fn user32_cursor_handle(&mut self, resource: u64) -> u32 {
        if let Some(existing_handle) = self.user32_state.default_cursor {
            return existing_handle.saturating_add(resource as u32);
        }
        let base_handle: u32 = self.allocate_object_handle();
        self.user32_state.default_cursor = Some(base_handle);
        base_handle.saturating_add(resource as u32)
    }

    pub(super) fn user32_cursor_position(&self) -> (i32, i32) {
        (self.user32_state.cursor_x, self.user32_state.cursor_y)
    }

    pub(super) fn user32_message_pos(&mut self) -> u32 {
        let state = &mut self.user32_state;
        let packed = ((state.message_y as u16 as u32) << 16) | (state.message_x as u16 as u32);
        let width = state.screen_width.max(1);
        let height = state.screen_height.max(1);
        let configured_motion = state.message_step_x != 0 || state.message_step_y != 0;
        state.message_sequence = state.message_sequence.wrapping_add(1);
        let (step_x, step_y) = if configured_motion {
            (state.message_step_x, state.message_step_y)
        } else {
            (
                7 + ((state.message_sequence & 0x3) as i32),
                3 + (((state.message_sequence >> 1) & 0x1) as i32),
            )
        };
        state.message_x = (state.message_x + step_x).rem_euclid(width);
        state.message_y = (state.message_y + step_y).rem_euclid(height);
        state.cursor_x = state.message_x;
        state.cursor_y = state.message_y;
        packed
    }
}
