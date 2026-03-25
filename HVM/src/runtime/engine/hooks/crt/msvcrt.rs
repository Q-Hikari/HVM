use super::*;

impl VirtualExecutionEngine {
    fn encode_seh_filter_result(result: i32) -> u64 {
        result as u32 as u64
    }

    fn read_exception_code_from_pointers(
        &self,
        exception_pointers: u64,
    ) -> Result<Option<u32>, VmError> {
        if exception_pointers == 0 {
            return Ok(None);
        }
        let exception_record = self.read_pointer_value(exception_pointers)?;
        if exception_record == 0 {
            return Ok(None);
        }
        Ok(Some(self.read_u32(exception_record)?))
    }

    pub(super) fn dispatch_msvcrt_seh_filter_dll(
        &mut self,
        exception_code: u32,
        exception_pointers: u64,
    ) -> Result<u64, VmError> {
        self.dispatch_msvcrt_seh_filter_exe(exception_code, exception_pointers)
    }

    pub(super) fn dispatch_msvcrt_seh_filter_exe(
        &mut self,
        exception_code: u32,
        exception_pointers: u64,
    ) -> Result<u64, VmError> {
        let effective_code = self
            .read_exception_code_from_pointers(exception_pointers)?
            .unwrap_or(exception_code);
        let filter_result = if effective_code == MSVC_CXX_EXCEPTION {
            EXCEPTION_CONTINUE_SEARCH_FILTER
        } else {
            EXCEPTION_EXECUTE_HANDLER_FILTER
        };
        Ok(Self::encode_seh_filter_result(filter_result))
    }

    pub(in crate::runtime::engine) fn dispatch_msvcrt_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("msvcrt.dll", "?terminate@@YAXXZ") | ("msvcrt.dll", "terminate") => true,
            ("msvcrt.dll", "_controlfp") => true,
            ("msvcrt.dll", "__set_app_type") => true,
            ("msvcrt.dll", "__p__fmode") => true,
            ("msvcrt.dll", "__p__commode") => true,
            ("msvcrt.dll", "__setusermatherr") => true,
            ("msvcrt.dll", "_amsg_exit") | ("msvcrt.dll", "exit") | ("msvcrt.dll", "_exit") => true,
            ("msvcrt.dll", "_initterm") => true,
            ("msvcrt.dll", "_initterm_e") => true,
            ("msvcrt.dll", "__vm_initterm_continue") => true,
            ("msvcrt.dll", "_acmdln") => true,
            ("msvcrt.dll", "_XcptFilter") => true,
            ("msvcrt.dll", "_seh_filter_dll") => true,
            ("msvcrt.dll", "_seh_filter_exe") => true,
            ("msvcrt.dll", "__vcrt_initializecriticalsectionex") => true,
            ("msvcrt.dll", "_cexit") => true,
            ("msvcrt.dll", "_crt_atexit") | ("msvcrt.dll", "atexit") => true,
            ("msvcrt.dll", "_execute_onexit_table") => true,
            ("msvcrt.dll", "_register_onexit_function") => true,
            ("msvcrt.dll", "_initialize_onexit_table") => true,
            ("msvcrt.dll", "_initialize_narrow_environment") => true,
            ("msvcrt.dll", "_invalid_parameter_noinfo_noreturn") => true,
            ("msvcrt.dll", "_errno") => true,
            ("msvcrt.dll", "strerror") => true,
            ("msvcrt.dll", "__getmainargs") => true,
            ("msvcrt.dll", "memset") => true,
            ("msvcrt.dll", "_ismbblead") => true,
            ("msvcrt.dll", "_time64") => true,
            ("msvcrt.dll", "srand") => true,
            ("msvcrt.dll", "rand") => true,
            ("msvcrt.dll", "_vsnwprintf") => true,
            ("msvcrt.dll", "wcsrchr") => true,
            ("msvcrt.dll", "atoi") => true,
            ("msvcrt.dll", "_callnewh") => true,
            ("msvcrt.dll", "malloc") | ("msvcrt.dll", "??2@YAPEAX_K@Z") => true,
            ("msvcrt.dll", "calloc") => true,
            ("msvcrt.dll", "realloc") => true,
            ("msvcrt.dll", "memmove") | ("msvcrt.dll", "memcpy") => true,
            ("msvcrt.dll", "memcmp") => true,
            ("msvcrt.dll", "strlen") => true,
            ("msvcrt.dll", "strchr") => true,
            ("msvcrt.dll", "strstr") => true,
            ("msvcrt.dll", "_stricmp") => true,
            ("msvcrt.dll", "_wcsicmp") => true,
            ("msvcrt.dll", "__C_specific_handler") => true,
            ("msvcrt.dll", "__CxxFrameHandler3") => true,
            ("msvcrt.dll", "_CxxThrowException") => true,
            ("msvcrt.dll", "free") => true,
            ("msvcrt.dll", "??3@YAXPEAX@Z") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("msvcrt.dll", "?terminate@@YAXXZ") | ("msvcrt.dll", "terminate") => {
                    self.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "_controlfp") => {
                    let base = self.ensure_msvcrt_globals()?;
                    let current = self.read_u32(base + MSVCRT_CONTROLFP_OFFSET)?;
                    let new_value = arg(args, 0) as u32;
                    let mask = arg(args, 1) as u32;
                    let next = (current & !mask) | (new_value & mask);
                    self.write_u32(base + MSVCRT_CONTROLFP_OFFSET, next)?;
                    Ok(current as u64)
                }
                ("msvcrt.dll", "__set_app_type") => {
                    let base = self.ensure_msvcrt_globals()?;
                    self.write_u32(base + MSVCRT_APP_TYPE_OFFSET, arg(args, 0) as u32)?;
                    Ok(0)
                }
                ("msvcrt.dll", "__p__fmode") => {
                    Ok(self.ensure_msvcrt_globals()? + MSVCRT_FMODE_OFFSET)
                }
                ("msvcrt.dll", "__p__commode") => {
                    Ok(self.ensure_msvcrt_globals()? + MSVCRT_COMMODE_OFFSET)
                }
                ("msvcrt.dll", "__setusermatherr") => {
                    let base = self.ensure_msvcrt_globals()?;
                    self.modules.memory_mut().write(
                        base + MSVCRT_USER_MATHERR_OFFSET,
                        &arg(args, 0).to_le_bytes(),
                    )?;
                    Ok(0)
                }
                ("msvcrt.dll", "_amsg_exit") | ("msvcrt.dll", "exit") | ("msvcrt.dll", "_exit") => {
                    self.exit_code = Some(arg(args, 0) as u32);
                    self.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "_initterm") => {
                    self.run_msvcrt_initterm_range(arg(args, 0), arg(args, 1), false)
                }
                ("msvcrt.dll", "_initterm_e") => {
                    self.run_msvcrt_initterm_range(arg(args, 0), arg(args, 1), true)
                }
                ("msvcrt.dll", "__vm_initterm_continue") => self.resume_pending_msvcrt_initterm(),
                ("msvcrt.dll", "_acmdln") => Ok(self.process_env.layout().command_line_ansi_buffer),
                ("msvcrt.dll", "_XcptFilter") => Ok(0),
                ("msvcrt.dll", "_seh_filter_dll") => {
                    self.dispatch_msvcrt_seh_filter_dll(arg(args, 0) as u32, arg(args, 1))
                }
                ("msvcrt.dll", "_seh_filter_exe") => {
                    self.dispatch_msvcrt_seh_filter_exe(arg(args, 0) as u32, arg(args, 1))
                }
                ("msvcrt.dll", "__vcrt_initializecriticalsectionex") => Ok(1),
                ("msvcrt.dll", "_cexit") => {
                    let table = self.ensure_msvcrt_global_onexit_table()?;
                    self.execute_msvcrt_onexit_table(table)
                }
                ("msvcrt.dll", "_crt_atexit") | ("msvcrt.dll", "atexit") => {
                    let table = self.ensure_msvcrt_global_onexit_table()?;
                    self.register_msvcrt_onexit_function(table, arg(args, 0))
                }
                ("msvcrt.dll", "_execute_onexit_table") => {
                    self.execute_msvcrt_onexit_table(arg(args, 0))
                }
                ("msvcrt.dll", "_register_onexit_function") => {
                    self.register_msvcrt_onexit_function(arg(args, 0), arg(args, 1))
                }
                ("msvcrt.dll", "_initialize_onexit_table") => {
                    self.initialize_msvcrt_onexit_table(arg(args, 0))?;
                    Ok(0)
                }
                ("msvcrt.dll", "_initialize_narrow_environment") => Ok(0),
                ("msvcrt.dll", "_invalid_parameter_noinfo_noreturn") => {
                    self.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "_errno") => Ok(self.ensure_msvcrt_errno_cell()?),
                ("msvcrt.dll", "strerror") => {
                    let error_code = arg(args, 0) as u32;
                    let message = if error_code == ERROR_FILE_NOT_FOUND as u32 {
                        "No such file or directory"
                    } else if error_code == ERROR_INVALID_PARAMETER as u32 {
                        "Invalid argument"
                    } else {
                        "Unknown error"
                    };
                    let buffer = self.ensure_msvcrt_strerror_buffer()?;
                    let mut bytes = message.as_bytes().to_vec();
                    bytes.push(0);
                    self.modules.memory_mut().write(buffer, &bytes)?;
                    Ok(buffer)
                }
                ("msvcrt.dll", "__getmainargs") => {
                    let base = self.ensure_msvcrt_globals()?;
                    let argv = base + MSVCRT_ARGV_ARRAY_OFFSET;
                    let envp = base + MSVCRT_ENVP_ARRAY_OFFSET;
                    self.write_pointer_value(
                        argv,
                        self.process_env.layout().command_line_ansi_buffer,
                    )?;
                    self.write_pointer_value(argv + self.arch.pointer_size as u64, 0)?;
                    self.write_pointer_value(envp, 0)?;
                    if arg(args, 0) != 0 {
                        self.write_u32(arg(args, 0), 1)?;
                    }
                    if arg(args, 1) != 0 {
                        self.write_pointer_value(arg(args, 1), argv)?;
                    }
                    if arg(args, 2) != 0 {
                        self.write_pointer_value(arg(args, 2), envp)?;
                    }
                    Ok(0)
                }
                ("msvcrt.dll", "memset") => {
                    let address = arg(args, 0);
                    let value = arg(args, 1) as u8;
                    let size = arg(args, 2) as usize;
                    if address != 0 && size != 0 {
                        self.modules
                            .memory_mut()
                            .write(address, &vec![value; size])?;
                    }
                    Ok(address)
                }
                ("msvcrt.dll", "_ismbblead") => {
                    let value = arg(args, 0) as u8;
                    Ok((0x81..=0xFE).contains(&value) as u64)
                }
                ("msvcrt.dll", "_time64") => {
                    let unix_time = self
                        .time
                        .current()
                        .filetime
                        .saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS)
                        / 10_000_000;
                    if arg(args, 0) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 0), &(unix_time as i64).to_le_bytes())?;
                    }
                    Ok(unix_time)
                }
                ("msvcrt.dll", "srand") => {
                    self.msvcrt_rand_seed = arg(args, 0) as u32;
                    Ok(0)
                }
                ("msvcrt.dll", "rand") => {
                    self.msvcrt_rand_seed = self
                        .msvcrt_rand_seed
                        .wrapping_mul(214013)
                        .wrapping_add(2531011);
                    Ok(((self.msvcrt_rand_seed >> 16) & 0x7FFF) as u64)
                }
                ("msvcrt.dll", "_vsnwprintf") => {
                    let buffer = arg(args, 0);
                    let count = arg(args, 1) as usize;
                    let format = self.read_wide_string_from_memory(arg(args, 2))?;
                    if buffer == 0 || count == 0 {
                        Ok(0)
                    } else {
                        let rendered = self.format_variadic_wide_printf(&format, arg(args, 3))?;
                        self.write_wide_string_to_memory(buffer, count, &rendered)
                    }
                }
                ("msvcrt.dll", "wcsrchr") => {
                    let mut result = 0;
                    let mut cursor = arg(args, 0);
                    let needle = arg(args, 1) as u16;
                    if cursor == 0 {
                        return Ok(0);
                    }
                    loop {
                        let bytes = self.modules.memory().read(cursor, 2)?;
                        let value = u16::from_le_bytes(bytes.try_into().unwrap());
                        if value == needle {
                            result = cursor;
                        }
                        if value == 0 {
                            break;
                        }
                        cursor = cursor.saturating_add(2);
                    }
                    Ok(result)
                }
                ("msvcrt.dll", "atoi") => {
                    let text = self.read_c_string_from_memory(arg(args, 0))?;
                    let bytes = text.trim_start().as_bytes();
                    let mut index = 0usize;
                    let mut sign = 1i64;
                    if let Some(byte) = bytes.first().copied() {
                        if byte == b'-' {
                            sign = -1;
                            index = 1;
                        } else if byte == b'+' {
                            index = 1;
                        }
                    }
                    let mut value = 0i64;
                    while let Some(byte) = bytes.get(index).copied() {
                        if !byte.is_ascii_digit() {
                            break;
                        }
                        value = value
                            .saturating_mul(10)
                            .saturating_add((byte - b'0') as i64);
                        index += 1;
                    }
                    Ok((value.saturating_mul(sign) as i32) as u32 as u64)
                }
                ("msvcrt.dll", "_callnewh") => Ok(0),
                ("msvcrt.dll", "malloc") | ("msvcrt.dll", "??2@YAPEAX_K@Z") => Ok(self
                    .heaps
                    .alloc(
                        self.modules.memory_mut(),
                        self.heaps.process_heap(),
                        arg(args, 0).max(1),
                    )
                    .unwrap_or(0)),
                ("msvcrt.dll", "calloc") => {
                    let size = arg(args, 0).saturating_mul(arg(args, 1)).max(1);
                    let address = self
                        .heaps
                        .alloc(self.modules.memory_mut(), self.heaps.process_heap(), size)
                        .unwrap_or(0);
                    if address != 0 {
                        self.fill_memory_pattern(address, size, 0)?;
                    }
                    Ok(address)
                }
                ("msvcrt.dll", "realloc") => {
                    let old_address = arg(args, 0);
                    let new_size = arg(args, 1);
                    if old_address == 0 {
                        return Ok(self
                            .heaps
                            .alloc(
                                self.modules.memory_mut(),
                                self.heaps.process_heap(),
                                new_size.max(1),
                            )
                            .unwrap_or(0));
                    }
                    if new_size == 0 {
                        let _ = self.heaps.free(self.heaps.process_heap(), old_address);
                        return Ok(0);
                    }
                    let old_size = self.heaps.size(self.heaps.process_heap(), old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let Some(new_address) = self.heaps.alloc(
                        self.modules.memory_mut(),
                        self.heaps.process_heap(),
                        new_size.max(1),
                    ) else {
                        return Ok(0);
                    };
                    let copy_size = old_size.min(new_size) as usize;
                    let bytes = self.modules.memory().read(old_address, copy_size)?;
                    self.modules.memory_mut().write(new_address, &bytes)?;
                    let _ = self.heaps.free(self.heaps.process_heap(), old_address);
                    Ok(new_address)
                }
                ("msvcrt.dll", "memmove") | ("msvcrt.dll", "memcpy") => {
                    self.copy_memory_block(arg(args, 0), arg(args, 1), arg(args, 2) as usize)
                }
                ("msvcrt.dll", "memcmp") => {
                    let size = arg(args, 2) as usize;
                    if size == 0 {
                        return Ok(0);
                    }
                    let Ok(left) = self.read_bytes_from_memory(arg(args, 0), size) else {
                        return Ok(1);
                    };
                    let Ok(right) = self.read_bytes_from_memory(arg(args, 1), size) else {
                        return Ok(1);
                    };
                    let result = match left.cmp(&right) {
                        std::cmp::Ordering::Less => -1i32,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    };
                    Ok(result as u32 as u64)
                }
                ("msvcrt.dll", "strlen") => {
                    Ok(self.read_c_string_from_memory(arg(args, 0))?.len() as u64)
                }
                ("msvcrt.dll", "strchr") => {
                    let mut cursor = arg(args, 0);
                    let needle = arg(args, 1) as u8;
                    if cursor == 0 {
                        return Ok(0);
                    }
                    loop {
                        let byte = self.read_u8(cursor)?;
                        if byte == needle {
                            return Ok(cursor);
                        }
                        if byte == 0 {
                            return Ok(0);
                        }
                        cursor = cursor.saturating_add(1);
                    }
                }
                ("msvcrt.dll", "strstr") => {
                    let haystack = self.read_c_string_from_memory(arg(args, 0))?;
                    let needle = self.read_c_string_from_memory(arg(args, 1))?;
                    if needle.is_empty() {
                        return Ok(arg(args, 0));
                    }
                    Ok(haystack
                        .find(&needle)
                        .map(|offset| arg(args, 0) + offset as u64)
                        .unwrap_or(0))
                }
                ("msvcrt.dll", "_stricmp") => {
                    let left = self.read_c_string_from_memory(arg(args, 0))?;
                    let right = self.read_c_string_from_memory(arg(args, 1))?;
                    Ok(compare_ci(&left, &right) as u32 as u64)
                }
                ("msvcrt.dll", "_wcsicmp") => {
                    let left = self.read_wide_string_from_memory(arg(args, 0))?;
                    let right = self.read_wide_string_from_memory(arg(args, 1))?;
                    Ok(compare_ci(&left, &right) as u32 as u64)
                }
                ("msvcrt.dll", "__C_specific_handler") => {
                    Ok(if self.arch.is_x64() { 1 } else { 0 })
                }
                ("msvcrt.dll", "__CxxFrameHandler3") => Ok(if self.arch.is_x64() { 1 } else { 0 }),
                ("msvcrt.dll", "_CxxThrowException") => {
                    self.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "free") | ("msvcrt.dll", "??3@YAXPEAX@Z") => {
                    let _ = self.heaps.free(self.heaps.process_heap(), arg(args, 0));
                    Ok(0)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
