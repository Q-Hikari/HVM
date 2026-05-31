use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_shell32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("shell32.dll", "IsUserAnAdmin") => true,
            ("shell32.dll", "CommandLineToArgvW") => true,
            ("shell32.dll", "ShellExecuteW") => true,
            ("shell32.dll", "ShellExecuteA") => true,
            ("shell32.dll", "ShellExecuteExW") => true,
            ("shell32.dll", "SHBrowseForFolderA") => true,
            ("shell32.dll", "SHGetFolderPathW") => true,
            ("shell32.dll", "SHGetKnownFolderPath") => true,
            ("shell32.dll", "SHGetMalloc") => true,
            ("shell32.dll", "IMalloc_QueryInterface") => true,
            ("shell32.dll", "IMalloc_AddRef") => true,
            ("shell32.dll", "IMalloc_Release") => true,
            ("shell32.dll", "IMalloc_Alloc") => true,
            ("shell32.dll", "IMalloc_Realloc") => true,
            ("shell32.dll", "IMalloc_Free") => true,
            ("shell32.dll", "IMalloc_GetSize") => true,
            ("shell32.dll", "IMalloc_DidAlloc") => true,
            ("shell32.dll", "IMalloc_HeapMinimize") => true,
            ("shell32.dll", "SHGetPathFromIDListW") => true,
            ("shell32.dll", "SHGetSpecialFolderLocation") => true,
            ("shell32.dll", "SHGetImageList") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("shell32.dll", "IsUserAnAdmin") => {
                    let active_user = self.active_user_name().trim();
                    let is_admin = self
                        .core
                        .environment_profile
                        .users
                        .iter()
                        .find(|user| user.name.eq_ignore_ascii_case(active_user))
                        .map(|user| user.privilege_level >= 2)
                        .unwrap_or_else(|| {
                            active_user.eq_ignore_ascii_case("Administrator")
                                || active_user.eq_ignore_ascii_case("Admin")
                        });
                    Ok(is_admin as u64)
                }
                ("shell32.dll", "CommandLineToArgvW") => {
                    let cmd_line_ptr = ctx.raw(0);
                    let num_args_ptr = ctx.raw(1);
                    let cmd_line = if cmd_line_ptr != 0 {
                        self.read_wide_string_from_memory(cmd_line_ptr)?
                    } else {
                        String::new()
                    };
                    let tokens = command_line_to_args(&cmd_line);
                    let argc = tokens.len() as u32;
                    if num_args_ptr != 0 {
                        self.write_u32(num_args_ptr, argc)?;
                    }
                    if tokens.is_empty() {
                        // Allocate a minimal empty argv array (single NULL entry)
                        let argv_base = self.alloc_process_heap_block(4, "CommandLineToArgvW")?;
                        self.write_u32(argv_base, 0)?;
                        return Ok(argv_base);
                    }
                    // Allocate the pointer array (argc + 1 entries, last is NULL)
                    let ptr_size = if self.core.arch.is_x86() { 4u64 } else { 8u64 };
                    let argv_base = self.alloc_process_heap_block(
                        (tokens.len() as u64 + 1) * ptr_size,
                        "CommandLineToArgvW:argv",
                    )?;
                    for (index, token) in tokens.iter().enumerate() {
                        let wide = token.encode_utf16().collect::<Vec<_>>();
                        let wide_bytes: Vec<u8> =
                            wide.iter().flat_map(|w| w.to_le_bytes()).collect();
                        // Allocate buffer for string + null terminator
                        let str_buf = self.alloc_process_heap_block(
                            (wide.len() as u64 + 1) * 2,
                            "CommandLineToArgvW:str",
                        )?;
                        self.core.modules.memory_mut().write(str_buf, &wide_bytes)?;
                        // Write null terminator
                        self.core
                            .modules
                            .memory_mut()
                            .write(str_buf + wide_bytes.len() as u64, &[0u8, 0u8])?;
                        let slot = argv_base + index as u64 * ptr_size;
                        if self.core.arch.is_x86() {
                            self.write_u32(slot, str_buf as u32)?;
                        } else {
                            self.core
                                .modules
                                .memory_mut()
                                .write(slot, &str_buf.to_le_bytes())?;
                        }
                    }
                    // Write trailing NULL pointer
                    let last_slot = argv_base + tokens.len() as u64 * ptr_size;
                    if self.core.arch.is_x86() {
                        self.write_u32(last_slot, 0)?;
                    } else {
                        self.core
                            .modules
                            .memory_mut()
                            .write(last_slot, &0u64.to_le_bytes())?;
                    }
                    Ok(argv_base)
                }
                ("shell32.dll", "ShellExecuteW") => {
                    let image = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let parameters = self.read_wide_string_from_memory(ctx.raw(3))?;
                    let directory = self.read_wide_string_from_memory(ctx.raw(4))?;
                    let effective_directory = if directory.is_empty() {
                        self.current_directory_display_text()
                    } else {
                        self.resolve_runtime_display_path(&directory)
                    };
                    let launched = self.core.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&effective_directory),
                    );
                    if let Some(handle) = launched {
                        let command_line = if parameters.is_empty() {
                            image.clone()
                        } else {
                            format!("{image} {parameters}")
                        };
                        self.log_process_spawn(
                            "ShellExecuteW",
                            handle,
                            &image,
                            &command_line,
                            &effective_directory,
                        )?;
                    }
                    Ok(if launched.is_some() {
                        SHELL_EXECUTE_SUCCESS as u64
                    } else {
                        0
                    })
                }
                ("shell32.dll", "ShellExecuteA") => {
                    let image = self.read_c_string_from_memory(ctx.raw(2))?;
                    let parameters = self.read_c_string_from_memory(ctx.raw(3))?;
                    let directory = self.read_c_string_from_memory(ctx.raw(4))?;
                    let effective_directory = if directory.is_empty() {
                        self.current_directory_display_text()
                    } else {
                        self.resolve_runtime_display_path(&directory)
                    };
                    let launched = self.core.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&effective_directory),
                    );
                    if let Some(handle) = launched {
                        let command_line = if parameters.is_empty() {
                            image.clone()
                        } else {
                            format!("{image} {parameters}")
                        };
                        self.log_process_spawn(
                            "ShellExecuteA",
                            handle,
                            &image,
                            &command_line,
                            &effective_directory,
                        )?;
                    }
                    Ok(if launched.is_some() {
                        SHELL_EXECUTE_SUCCESS as u64
                    } else {
                        0
                    })
                }
                ("shell32.dll", "ShellExecuteExW") => {
                    let info = ctx.raw(0);
                    if info == 0 {
                        return Ok(0);
                    }
                    let fmask = self.read_u32(info + 0x04)?;
                    let image =
                        self.read_wide_string_from_memory(self.read_u32(info + 0x10)? as u64)?;
                    let parameters =
                        self.read_wide_string_from_memory(self.read_u32(info + 0x14)? as u64)?;
                    let directory =
                        self.read_wide_string_from_memory(self.read_u32(info + 0x18)? as u64)?;
                    let effective_directory = if directory.is_empty() {
                        self.current_directory_display_text()
                    } else {
                        self.resolve_runtime_display_path(&directory)
                    };
                    let handle = self.core.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&effective_directory),
                    );
                    if let Some(process_handle) = handle {
                        let command_line = if parameters.is_empty() {
                            image.clone()
                        } else {
                            format!("{image} {parameters}")
                        };
                        self.log_process_spawn(
                            "ShellExecuteExW",
                            process_handle,
                            &image,
                            &command_line,
                            &effective_directory,
                        )?;
                    }
                    if fmask & SEE_MASK_NOCLOSEPROCESS != 0 {
                        self.write_u32(info + 0x38, handle.unwrap_or(0))?;
                    }
                    Ok(if handle.is_some() { 1 } else { 0 })
                }
                ("shell32.dll", "SHBrowseForFolderA") => Ok(0),
                ("shell32.dll", "SHGetFolderPathW") => {
                    let path = self.shell_folder_path_from_csidl(ctx.raw(1) as u32);
                    let _ = self.write_wide_string_to_memory(ctx.raw(4), 260, &path)?;
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "SHGetKnownFolderPath") => {
                    let rfid_ptr = ctx.raw(0);
                    let ppsz_path = ctx.raw(3);
                    let guid_bytes = self
                        .read_bytes_from_memory(rfid_ptr, 16)
                        .unwrap_or_default();
                    let path = self.path_from_known_folder_guid(&guid_bytes);
                    let mut wide_bytes: Vec<u8> =
                        path.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    wide_bytes.extend_from_slice(&[0, 0]);
                    let str_buf = self.alloc_process_heap_block(
                        wide_bytes.len().max(2) as u64,
                        "SHGetKnownFolderPath",
                    )?;
                    self.core.modules.memory_mut().write(str_buf, &wide_bytes)?;
                    if ppsz_path != 0 {
                        if self.core.arch.is_x86() {
                            self.write_u32(ppsz_path, str_buf as u32)?;
                        } else {
                            self.write_pointer_value(ppsz_path, str_buf)?;
                        }
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "SHGetMalloc") => {
                    if ctx.raw(0) != 0 {
                        let allocator = self.ensure_shell_imalloc()?;
                        self.write_u32(ctx.raw(0), allocator as u32)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "IMalloc_QueryInterface") => {
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), ctx.raw(0) as u32)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "IMalloc_AddRef") => Ok(2),
                ("shell32.dll", "IMalloc_Release") => Ok(1),
                ("shell32.dll", "IMalloc_Alloc") => {
                    if ctx.raw(1) == 0 {
                        Ok(0)
                    } else {
                        self.alloc_process_heap_block(ctx.raw(1), "IMalloc::Alloc")
                    }
                }
                ("shell32.dll", "IMalloc_Realloc") => {
                    let old_address = ctx.raw(1);
                    let new_size = ctx.raw(2);
                    if old_address == 0 {
                        return self.alloc_process_heap_block(new_size.max(1), "IMalloc::Realloc");
                    }
                    if new_size == 0 {
                        let _ = self
                            .process_memory
                            .heaps
                            .free(self.process_memory.heaps.process_heap(), old_address);
                        return Ok(0);
                    }
                    let old_size = self
                        .process_memory
                        .heaps
                        .size(self.process_memory.heaps.process_heap(), old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let new_address =
                        self.alloc_process_heap_block(new_size.max(1), "IMalloc::Realloc")?;
                    let bytes =
                        self.read_bytes_from_memory(old_address, old_size.min(new_size) as usize)?;
                    self.core.modules.memory_mut().write(new_address, &bytes)?;
                    let _ = self
                        .process_memory
                        .heaps
                        .free(self.process_memory.heaps.process_heap(), old_address);
                    Ok(new_address)
                }
                ("shell32.dll", "IMalloc_Free") => {
                    let _ = self
                        .process_memory
                        .heaps
                        .free(self.process_memory.heaps.process_heap(), ctx.raw(1));
                    Ok(0)
                }
                ("shell32.dll", "IMalloc_GetSize") => {
                    let size = self
                        .process_memory
                        .heaps
                        .size(self.process_memory.heaps.process_heap(), ctx.raw(1));
                    Ok(if size == u32::MAX as u64 { 0 } else { size })
                }
                ("shell32.dll", "IMalloc_DidAlloc") => Ok((self
                    .process_memory
                    .heaps
                    .size(self.process_memory.heaps.process_heap(), ctx.raw(1))
                    != u32::MAX as u64)
                    as u64),
                ("shell32.dll", "IMalloc_HeapMinimize") => Ok(0),
                ("shell32.dll", "SHGetPathFromIDListW") => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else {
                        let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                        let _ = self.write_wide_string_to_memory(ctx.raw(1), 260, &path)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("shell32.dll", "SHGetSpecialFolderLocation") => {
                    if ctx.raw(2) == 0 {
                        Ok(E_INVALIDARG_HRESULT)
                    } else {
                        let path = self.shell_folder_path_from_csidl(ctx.raw(1) as u32);
                        let mut bytes = path
                            .encode_utf16()
                            .flat_map(u16::to_le_bytes)
                            .collect::<Vec<_>>();
                        bytes.extend_from_slice(&[0, 0]);
                        let pidl = self.alloc_process_heap_block(
                            bytes.len() as u64,
                            "SHGetSpecialFolderLocation",
                        )?;
                        self.core.modules.memory_mut().write(pidl, &bytes)?;
                        self.write_pointer_value(ctx.raw(2), pidl)?;
                        Ok(ERROR_SUCCESS)
                    }
                }
                ("shell32.dll", "SHGetImageList") => {
                    if ctx.raw(2) != 0 {
                        if self.core.arch.is_x86() {
                            self.write_u32(ctx.raw(2), 0)?;
                        } else {
                            self.core
                                .modules
                                .memory_mut()
                                .write(ctx.raw(2), &0u64.to_le_bytes())?;
                        }
                    }
                    Ok(0)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}

/// Parses a Windows command line string into an argv vector, following the
/// standard CRT argument parsing rules (spaces as delimiters, backslash
/// escaping, double-quote handling).
fn command_line_to_args(cmd_line: &str) -> Vec<String> {
    let chars: Vec<char> = cmd_line.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let len = chars.len();

    // Skip leading whitespace
    while i < len && chars[i] == ' ' || chars[i] == '\t' {
        i += 1;
    }

    while i < len {
        let mut token = String::new();
        let mut in_quotes = false;

        while i < len {
            if chars[i] == '"' {
                in_quotes = !in_quotes;
                i += 1;
                // Consume all consecutive quotes: every pair of quotes produces one literal quote
                let mut quote_count = 0usize;
                while i < len && chars[i] == '"' {
                    quote_count += 1;
                    in_quotes = !in_quotes;
                    i += 1;
                }
                // Each pair of closing quotes adds one literal "
                for _ in 0..quote_count / 2 {
                    token.push('"');
                }
                continue;
            }

            if !in_quotes && (chars[i] == ' ' || chars[i] == '\t') {
                break;
            }

            if chars[i] == '\\' {
                // Count consecutive backslashes
                let mut backslash_count = 0usize;
                while i < len && chars[i] == '\\' {
                    backslash_count += 1;
                    i += 1;
                }
                // Check if followed by a quote
                if i < len && chars[i] == '"' {
                    // N backslashes followed by a quote:
                    // floor(N/2) literal backslashes, then quote starts/ends if N is even
                    for _ in 0..backslash_count / 2 {
                        token.push('\\');
                    }
                    if backslash_count % 2 == 0 {
                        // Even backslashes: quote is a delimiter
                        in_quotes = !in_quotes;
                        i += 1;
                    } else {
                        // Odd backslashes: escaped literal quote
                        token.push('"');
                        i += 1;
                    }
                } else {
                    // Not followed by a quote: all backslashes are literal
                    for _ in 0..backslash_count {
                        token.push('\\');
                    }
                }
                continue;
            }

            token.push(chars[i]);
            i += 1;
        }

        if !token.is_empty() || in_quotes {
            tokens.push(token);
        }

        // Skip whitespace between tokens
        while i < len && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
    }

    tokens
}
