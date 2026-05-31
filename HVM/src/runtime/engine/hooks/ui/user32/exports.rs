use super::*;
use crate::hooks::types::LogicalAbi;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_user32_hook(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
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
                | "FindWindowA"
                | "FindWindowW"
                | "GetActiveWindow"
                | "GetDesktopWindow"
                | "GetForegroundWindow"
                | "GetCaretBlinkTime"
                | "GetCursor"
                | "GetDoubleClickTime"
                | "GetParent"
                | "GetWindowThreadProcessId"
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
                | "PostThreadMessageW"
                | "GetMessageW"
                | "PeekMessageW"
                | "GetSystemMetrics"
                | "GetSysColor"
                | "GetSysColorBrush"
                | "GetCursorPos"
                | "GetKBCodePage"
                | "GetKeyboardType"
                | "LoadStringW"
                | "GetMessagePos"
                | "SetWindowsHookExW"
                | "CallNextHookEx"
                | "UnhookWindowsHookEx"
                | "IsCharAlphaNumericW"
                | "SetRectEmpty"
                | "EnumDisplayMonitors"
                | "EnumWindows"
                | "SystemParametersInfoW"
                | "TranslateMessage"
                | "DispatchMessageA"
                | "DispatchMessageW"
                | "__vm_sendmessage_continue"
                | "__vm_enumwindows_continue"
                | "__vm_timerproc_continue"
                | "PostQuitMessage"
                | "SetTimer"
                | "KillTimer"
                | "wsprintfA"
                | "ExitWindowsEx"
                | "GetProcessWindowStation"
                | "GetUserObjectInformationW"
        ) {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "RegisterClassExA" => self.user32_register_class_ex(ctx.raw(0), false),
                "RegisterClassExW" => self.user32_register_class_ex(ctx.raw(0), true),
                "RegisterWindowMessageA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let atom = self.allocate_global_atom(&name) as u64;
                    Ok(atom)
                }
                "RegisterWindowMessageW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let atom = self.allocate_global_atom(&name) as u64;
                    Ok(atom)
                }
                "RegisterClipboardFormatW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let atom = self.allocate_global_atom(&name) as u64;
                    Ok(atom)
                }
                "CreateWindowExA" => self.user32_create_window_ex(
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(8),
                    ctx.raw(10),
                    false,
                ),
                "CreateWindowExW" => self.user32_create_window_ex(
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(8),
                    ctx.raw(10),
                    true,
                ),
                "FindWindowA" => self.user32_find_window(ctx.raw(0), ctx.raw(1), false),
                "FindWindowW" => self.user32_find_window(ctx.raw(0), ctx.raw(1), true),
                "GetActiveWindow" => {
                    let handle = self.user32_window_handle("active") as u64;
                    Ok(handle)
                }
                "GetDesktopWindow" => {
                    let handle = self.user32_window_handle("desktop") as u64;
                    Ok(handle)
                }
                "GetForegroundWindow" => {
                    let handle = self.user32_window_handle("active") as u64;
                    Ok(handle)
                }
                "GetCaretBlinkTime" => Ok(self
                    .core
                    .environment_profile
                    .display
                    .caret_blink_time_ms
                    .max(1) as u64),
                "GetCursor" => {
                    let handle = self.user32_cursor_handle(0) as u64;
                    Ok(handle)
                }
                "GetDoubleClickTime" => Ok(self
                    .core
                    .environment_profile
                    .display
                    .double_click_time_ms
                    .max(1) as u64),
                "GetParent" => {
                    let handle = self.user32_parent_handle(ctx.raw(0) as u32) as u64;
                    Ok(handle)
                }
                "GetWindowThreadProcessId" => {
                    self.user32_get_window_thread_process_id(ctx.raw(0) as u32, ctx.raw(1))
                }
                "GetDC" | "GetWindowDC" => {
                    let handle = self.user32_dc_handle() as u64;
                    Ok(handle)
                }
                "ReleaseDC" => Ok(1),
                "LoadIconW" => {
                    let handle = self.user32_icon_handle(ctx.raw(1)) as u64;
                    Ok(handle)
                }
                "LoadCursorW" => {
                    let handle = self.user32_cursor_handle(ctx.raw(1)) as u64;
                    Ok(handle)
                }
                "ShowWindow" => {
                    self.user32_note_window_activity(
                        ctx.raw(0) as u32,
                        0x0018,
                        ctx.raw(1) as u32,
                        0,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "UpdateWindow" => {
                    self.user32_note_window_activity(ctx.raw(0) as u32, 0x000F, 0, 0)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "SendMessageA" | "SendMessageW" => self.user32_send_message(
                    ctx.raw(0),
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                    LogicalAbi::WinApi,
                    4,
                ),
                "SendMessageTimeoutW" => {
                    self.user32_note_window_activity(
                        ctx.raw(0) as u32,
                        ctx.raw(1) as u32,
                        ctx.raw(2) as u32,
                        ctx.raw(3) as u32,
                    )?;
                    if ctx.raw(6) != 0 {
                        self.write_pointer_value(ctx.raw(6), 0)?;
                    }
                    Ok(1)
                }
                "WaitForInputIdle" => Ok(0),
                "BeginPaint" => {
                    if ctx.raw(1) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(1), &vec![0u8; 0x80])?;
                    }
                    Ok(1)
                }
                "EndPaint" => Ok(1),
                "DefWindowProcW" => Ok(0),
                "PostThreadMessageW" => self.user32_post_thread_message(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "GetMessageW" => self.user32_get_message(
                    ctx.raw(0),
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3) as u32,
                ),
                "PeekMessageW" => self.user32_peek_message(
                    ctx.raw(0),
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3) as u32,
                    (ctx.raw(4) as u32 & 0x0001) != 0,
                ),
                "GetSystemMetrics" => Ok(match ctx.raw(0) as i32 {
                    0 => self.core.environment_profile.display.screen_width.max(1) as u64,
                    1 => self.core.environment_profile.display.screen_height.max(1) as u64,
                    0x1000 => self.core.environment_profile.display.remote_session as u64,
                    _ => 1,
                }),
                "GetSysColor" => Ok(match ctx.raw(0) as u32 {
                    0x0F => 0x00F0F0F0,
                    0x15 => 0x00E3E3E3,
                    0x16 => 0x00FFFFFF,
                    _ => 0x00C0C0C0,
                }),
                "GetSysColorBrush" => {
                    let index = ctx.raw(0) as u32;
                    Ok(0x30000 + index as u64)
                }
                "GetCursorPos" => {
                    if ctx.raw(0) != 0 {
                        let (x, y) = self.user32_cursor_position();
                        let mut point = Vec::with_capacity(8);
                        point.extend_from_slice(&x.to_le_bytes());
                        point.extend_from_slice(&y.to_le_bytes());
                        self.core.modules.memory_mut().write(ctx.raw(0), &point)?;
                    }
                    Ok(1)
                }
                "GetKBCodePage" => Ok(self.ansi_code_page()),
                "GetKeyboardType" => Ok(match ctx.raw(0) as i32 {
                    0 => 4,
                    1 => 0,
                    2 => 12,
                    _ => 0,
                }),
                "LoadStringW" => {
                    let buffer = ctx.raw(2);
                    let capacity = (ctx.raw(3) as i32).max(0) as usize;
                    if buffer == 0 || capacity == 0 {
                        return Ok(0);
                    }
                    self.write_wide_string_to_memory(buffer, capacity, "resource")
                }
                "GetMessagePos" => Ok(self.user32_message_pos() as u64),
                "SetWindowsHookExW" => self.user32_register_hook(
                    ctx.raw(0) as i32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                ),
                "CallNextHookEx" => Ok(0),
                "UnhookWindowsHookEx" => {
                    let result = self.user32_unhook(ctx.raw(0) as u32) as u64;
                    Ok(result)
                }
                "IsCharAlphaNumericW" => Ok(char::from_u32(ctx.raw(0) as u32)
                    .map(|ch| ch.is_alphanumeric() as u64)
                    .unwrap_or(0)),
                "SetRectEmpty" => {
                    if ctx.raw(0) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(0), &[0u8; 16])?;
                    }
                    Ok(1)
                }
                "EnumDisplayMonitors" => Ok(1),
                "EnumWindows" => self.user32_enum_windows(ctx.raw(0), ctx.raw(1)),
                "SystemParametersInfoW" => {
                    if ctx.raw(2) != 0 && ctx.raw(1) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2), &vec![0u8; ctx.raw(1) as usize])?;
                    }
                    Ok(1)
                }
                "TranslateMessage" => Ok(self.user32_translate_message()),
                "DispatchMessageA" | "DispatchMessageW" => self.user32_dispatch_message(ctx.raw(0)),
                "__vm_sendmessage_continue" => self.resume_pending_user32_sendmessage_callback(),
                "__vm_enumwindows_continue" => self.resume_pending_user32_enumwindows_callback(),
                "__vm_timerproc_continue" => self.resume_pending_user32_timer_callback(),
                "PostQuitMessage" => self.user32_post_quit_message(ctx.raw(0) as u32),
                "SetTimer" => self.user32_register_timer(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "KillTimer" => {
                    let result =
                        self.user32_kill_timer(ctx.raw(0) as u32, ctx.raw(1) as u32) as u64;
                    Ok(result)
                }
                "wsprintfA" => {
                    let destination = ctx.raw(0);
                    let format = self.read_c_string_from_memory(ctx.raw(1))?;
                    if destination == 0 {
                        Ok(0)
                    } else {
                        self.write_c_string_to_memory(destination, 0x1000, &format)
                    }
                }
                "ExitWindowsEx" => Ok(0),
                "GetProcessWindowStation" => {
                    // Return a pseudo HWINSTA handle (non-zero = valid)
                    Ok(self.sign_extend_win32_handle_for_arch(0xFFFF0001))
                }
                "GetUserObjectInformationW" => {
                    // args: hObj, nIndex, pvInfo, nLength, lpnLengthNeeded
                    let info_index = ctx.raw(1) as u32;
                    let info_ptr = ctx.raw(2);
                    let info_len = ctx.raw(3) as usize;
                    let length_needed_ptr = ctx.raw(4);
                    match info_index {
                        // UOI_NAME = 2
                        2 => {
                            let name = "WinSta0\0"
                                .encode_utf16()
                                .flat_map(|w| w.to_le_bytes())
                                .collect::<Vec<_>>();
                            if length_needed_ptr != 0 {
                                self.write_u32(length_needed_ptr, name.len() as u32)?;
                            }
                            if info_ptr != 0 && info_len >= name.len() {
                                self.core.modules.memory_mut().write(info_ptr, &name)?;
                                Ok(1)
                            } else {
                                Ok(0)
                            }
                        }
                        // UOI_FLAGS = 1
                        1 => {
                            let flags_size = 8u32; // USEROBJECTFLAGS = 8 bytes
                            if length_needed_ptr != 0 {
                                self.write_u32(length_needed_ptr, flags_size)?;
                            }
                            if info_ptr != 0 && info_len >= flags_size as usize {
                                // fInherit=0, fReserved=0, dwFlags=0
                                self.core
                                    .modules
                                    .memory_mut()
                                    .write(info_ptr, &vec![0u8; 8])?;
                                Ok(1)
                            } else {
                                Ok(0)
                            }
                        }
                        _ => Ok(0),
                    }
                }
                _ => unreachable!("validated handled hook name"),
            }
        })())
    }
}
