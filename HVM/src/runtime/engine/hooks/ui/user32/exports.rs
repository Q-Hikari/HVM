use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_user32_hook(
        &mut self,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        if !matches!(
            function,
            "RegisterClassExA"
                | "RegisterClassExW"
                | "RegisterWindowMessageA"
                | "RegisterWindowMessageW"
                | "RegisterClipboardFormatW"
                | "CreateWindowExA"
                | "CreateWindowExW"
                | "GetActiveWindow"
                | "GetDesktopWindow"
                | "GetParent"
                | "GetDC"
                | "GetWindowDC"
                | "ReleaseDC"
                | "LoadIconW"
                | "LoadCursorW"
                | "ShowWindow"
                | "UpdateWindow"
                | "SendMessageA"
                | "SendMessageW"
                | "SendMessageTimeoutW"
                | "WaitForInputIdle"
                | "BeginPaint"
                | "EndPaint"
                | "DefWindowProcW"
                | "GetMessageW"
                | "PeekMessageW"
                | "GetSystemMetrics"
                | "GetSysColor"
                | "GetSysColorBrush"
                | "GetCursorPos"
                | "GetMessagePos"
                | "SetWindowsHookExW"
                | "CallNextHookEx"
                | "UnhookWindowsHookEx"
                | "IsCharAlphaNumericW"
                | "SetRectEmpty"
                | "EnumDisplayMonitors"
                | "SystemParametersInfoW"
                | "TranslateMessage"
                | "DispatchMessageA"
                | "DispatchMessageW"
                | "__vm_sendmessage_continue"
                | "__vm_timerproc_continue"
                | "PostQuitMessage"
                | "SetTimer"
                | "KillTimer"
                | "wsprintfA"
                | "ExitWindowsEx"
        ) {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "RegisterClassExA" => self.user32_register_class_ex(arg(args, 0), false),
                "RegisterClassExW" => self.user32_register_class_ex(arg(args, 0), true),
                "RegisterWindowMessageA" => {
                    let name = self.read_c_string_from_memory(arg(args, 0))?;
                    Ok(self.allocate_global_atom(&name) as u64)
                }
                "RegisterWindowMessageW" => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    Ok(self.allocate_global_atom(&name) as u64)
                }
                "RegisterClipboardFormatW" => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    Ok(self.allocate_global_atom(&name) as u64)
                }
                "CreateWindowExA" => self.user32_create_window_ex(
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 8),
                    arg(args, 10),
                    false,
                ),
                "CreateWindowExW" => self.user32_create_window_ex(
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 8),
                    arg(args, 10),
                    true,
                ),
                "GetActiveWindow" => Ok(self.user32_window_handle("active") as u64),
                "GetDesktopWindow" => Ok(self.user32_window_handle("desktop") as u64),
                "GetParent" => Ok(self.user32_parent_handle(arg(args, 0) as u32) as u64),
                "GetDC" | "GetWindowDC" => Ok(self.user32_dc_handle() as u64),
                "ReleaseDC" => Ok(1),
                "LoadIconW" => Ok(self.user32_icon_handle(arg(args, 1)) as u64),
                "LoadCursorW" => Ok(self.user32_cursor_handle(arg(args, 1)) as u64),
                "ShowWindow" => {
                    self.user32_note_window_activity(
                        arg(args, 0) as u32,
                        0x0018,
                        arg(args, 1) as u32,
                        0,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "UpdateWindow" => {
                    self.user32_note_window_activity(arg(args, 0) as u32, 0x000F, 0, 0)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "SendMessageA" | "SendMessageW" => self.user32_send_message(
                    arg(args, 0),
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                ),
                "SendMessageTimeoutW" => {
                    self.user32_note_window_activity(
                        arg(args, 0) as u32,
                        arg(args, 1) as u32,
                        arg(args, 2) as u32,
                        arg(args, 3) as u32,
                    )?;
                    if arg(args, 6) != 0 {
                        self.write_pointer_value(arg(args, 6), 0)?;
                    }
                    Ok(1)
                }
                "WaitForInputIdle" => Ok(0),
                "BeginPaint" => {
                    if arg(args, 1) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 1), &vec![0u8; 0x80])?;
                    }
                    Ok(1)
                }
                "EndPaint" => Ok(1),
                "DefWindowProcW" => Ok(0),
                "GetMessageW" => self.user32_get_message(
                    arg(args, 0),
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3) as u32,
                ),
                "PeekMessageW" => self.user32_peek_message(
                    arg(args, 0),
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3) as u32,
                    (arg(args, 4) as u32 & 0x0001) != 0,
                ),
                "GetSystemMetrics" => Ok(match arg(args, 0) as i32 {
                    0 => self.environment_profile.display.screen_width.max(1) as u64,
                    1 => self.environment_profile.display.screen_height.max(1) as u64,
                    0x1000 => self.environment_profile.display.remote_session as u64,
                    _ => 1,
                }),
                "GetSysColor" => Ok(match arg(args, 0) as u32 {
                    0x0F => 0x00F0F0F0,
                    0x15 => 0x00E3E3E3,
                    0x16 => 0x00FFFFFF,
                    _ => 0x00C0C0C0,
                }),
                "GetSysColorBrush" => {
                    let index = arg(args, 0) as u32;
                    Ok(0x30000 + index as u64)
                }
                "GetCursorPos" => {
                    if arg(args, 0) != 0 {
                        let (x, y) = self.user32_cursor_position();
                        let mut point = Vec::with_capacity(8);
                        point.extend_from_slice(&x.to_le_bytes());
                        point.extend_from_slice(&y.to_le_bytes());
                        self.modules.memory_mut().write(arg(args, 0), &point)?;
                    }
                    Ok(1)
                }
                "GetMessagePos" => Ok(self.user32_message_pos() as u64),
                "SetWindowsHookExW" => self.user32_register_hook(
                    arg(args, 0) as i32,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                ),
                "CallNextHookEx" => Ok(0),
                "UnhookWindowsHookEx" => Ok(self.user32_unhook(arg(args, 0) as u32) as u64),
                "IsCharAlphaNumericW" => Ok(char::from_u32(arg(args, 0) as u32)
                    .map(|ch| ch.is_alphanumeric() as u64)
                    .unwrap_or(0)),
                "SetRectEmpty" => {
                    if arg(args, 0) != 0 {
                        self.modules.memory_mut().write(arg(args, 0), &[0u8; 16])?;
                    }
                    Ok(1)
                }
                "EnumDisplayMonitors" => Ok(1),
                "SystemParametersInfoW" => {
                    if arg(args, 2) != 0 && arg(args, 1) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 2), &vec![0u8; arg(args, 1) as usize])?;
                    }
                    Ok(1)
                }
                "TranslateMessage" => Ok(self.user32_translate_message()),
                "DispatchMessageA" | "DispatchMessageW" => {
                    self.user32_dispatch_message(arg(args, 0))
                }
                "__vm_sendmessage_continue" => self.resume_pending_user32_sendmessage_callback(),
                "__vm_timerproc_continue" => self.resume_pending_user32_timer_callback(),
                "PostQuitMessage" => self.user32_post_quit_message(arg(args, 0) as u32),
                "SetTimer" => self.user32_register_timer(
                    arg(args, 0) as u32,
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "KillTimer" => {
                    Ok(self.user32_kill_timer(arg(args, 0) as u32, arg(args, 1) as u32) as u64)
                }
                "wsprintfA" => {
                    let destination = arg(args, 0);
                    let format = self.read_c_string_from_memory(arg(args, 1))?;
                    if destination == 0 {
                        Ok(0)
                    } else {
                        self.write_c_string_to_memory(destination, 0x1000, &format)
                    }
                }
                "ExitWindowsEx" => Ok(0),
                _ => unreachable!("validated handled hook name"),
            }
        })())
    }
}
