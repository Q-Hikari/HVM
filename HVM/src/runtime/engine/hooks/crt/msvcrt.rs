use super::*;

const MSVCRT_EINVAL: u32 = 22;
const MSVCRT_ERANGE: u32 = 34;

struct ParsedWideInteger {
    value: u64,
    negative: bool,
    end_chars: usize,
    had_digits: bool,
}

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

    fn write_msvcrt_errno_value(&mut self, value: u32) -> Result<(), VmError> {
        let cell = self.ensure_msvcrt_errno_cell()?;
        self.write_u32(cell, value)
    }

    fn clear_msvcrt_wide_buffer(&mut self, address: u64, capacity: usize) -> Result<(), VmError> {
        if address != 0 && capacity != 0 {
            self.write_u16(address, 0)?;
        }
        Ok(())
    }

    fn fail_msvcrt_wide_result(
        &mut self,
        errno: u32,
        buffer: Option<(u64, usize)>,
    ) -> Result<u64, VmError> {
        if let Some((address, capacity)) = buffer {
            self.clear_msvcrt_wide_buffer(address, capacity)?;
        }
        self.write_msvcrt_errno_value(errno)?;
        Ok(errno as u64)
    }

    fn msvcrt_format_unsigned_radix(mut value: u64, radix: u32) -> Option<String> {
        if !(2..=36).contains(&radix) {
            return None;
        }
        if value == 0 {
            return Some("0".to_string());
        }
        let mut digits = Vec::new();
        while value != 0 {
            let digit = (value % radix as u64) as u8;
            digits.push(if digit < 10 {
                (b'0' + digit) as char
            } else {
                (b'a' + digit - 10) as char
            });
            value /= radix as u64;
        }
        digits.reverse();
        Some(digits.into_iter().collect())
    }

    fn msvcrt_format_signed_radix(value: i32, radix: u32) -> Option<String> {
        if !(2..=36).contains(&radix) {
            return None;
        }
        if radix == 10 {
            return Some(value.to_string());
        }
        Self::msvcrt_format_unsigned_radix(value as u32 as u64, radix)
    }

    fn write_msvcrt_wide_text_s(
        &mut self,
        address: u64,
        capacity: usize,
        value: &str,
    ) -> Result<u64, VmError> {
        if address == 0 || capacity == 0 {
            return self.fail_msvcrt_wide_result(MSVCRT_EINVAL, None);
        }
        let required = value.encode_utf16().count().saturating_add(1);
        if required > capacity {
            return self.fail_msvcrt_wide_result(MSVCRT_ERANGE, Some((address, capacity)));
        }
        self.write_wide_string_to_memory(address, capacity, value)?;
        self.write_msvcrt_errno_value(0)?;
        Ok(0)
    }

    fn write_msvcrt_wide_text_unchecked(
        &mut self,
        address: u64,
        value: &str,
    ) -> Result<u64, VmError> {
        if address == 0 {
            return Ok(0);
        }
        self.write_wide_string_to_memory(address, 0x400, value)?;
        Ok(address)
    }

    fn parse_msvcrt_wide_integer(
        &self,
        address: u64,
        base: u32,
    ) -> Result<ParsedWideInteger, VmError> {
        if address == 0 {
            return Ok(ParsedWideInteger {
                value: 0,
                negative: false,
                end_chars: 0,
                had_digits: false,
            });
        }

        let text = self.read_wide_string_from_memory(address)?;
        let chars = text.chars().collect::<Vec<_>>();
        let mut cursor = 0usize;
        while chars
            .get(cursor)
            .copied()
            .map(char::is_whitespace)
            .unwrap_or(false)
        {
            cursor += 1;
        }

        let mut negative = false;
        if let Some(sign) = chars.get(cursor).copied() {
            if sign == '-' {
                negative = true;
                cursor += 1;
            } else if sign == '+' {
                cursor += 1;
            }
        }

        let mut effective_base = base;
        if effective_base == 0 {
            if chars.get(cursor) == Some(&'0') {
                if matches!(chars.get(cursor + 1), Some('x') | Some('X')) {
                    effective_base = 16;
                    cursor += 2;
                } else {
                    effective_base = 8;
                }
            } else {
                effective_base = 10;
            }
        } else if effective_base == 16
            && chars.get(cursor) == Some(&'0')
            && matches!(chars.get(cursor + 1), Some('x') | Some('X'))
        {
            cursor += 2;
        }

        if !(2..=36).contains(&effective_base) {
            return Ok(ParsedWideInteger {
                value: 0,
                negative,
                end_chars: 0,
                had_digits: false,
            });
        }

        let digits_start = cursor;
        let mut value = 0u64;
        while let Some(digit) = chars
            .get(cursor)
            .and_then(|ch| ch.to_digit(effective_base))
            .map(u64::from)
        {
            value = value
                .saturating_mul(effective_base as u64)
                .saturating_add(digit);
            cursor += 1;
        }

        let had_digits = cursor > digits_start;
        Ok(ParsedWideInteger {
            value,
            negative,
            end_chars: if had_digits { cursor } else { 0 },
            had_digits,
        })
    }

    fn write_msvcrt_parse_end(
        &mut self,
        source: u64,
        end_ptr: u64,
        parsed: &ParsedWideInteger,
    ) -> Result<(), VmError> {
        if end_ptr == 0 {
            return Ok(());
        }
        let end = if parsed.had_digits {
            source + parsed.end_chars as u64 * 2
        } else {
            source
        };
        self.write_pointer_value(end_ptr, end)
    }

    fn compare_msvcrt_wide_strings(&self, left: u64, right: u64) -> Result<i32, VmError> {
        let left = self
            .read_wide_string_from_memory(left)?
            .encode_utf16()
            .collect::<Vec<_>>();
        let right = self
            .read_wide_string_from_memory(right)?
            .encode_utf16()
            .collect::<Vec<_>>();
        Ok(match left.cmp(&right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }

    fn render_msvcrt_inline_wide_printf(
        &self,
        format: &str,
        args: &[u64],
    ) -> Result<String, VmError> {
        let mut output = String::new();
        let mut cursor = 0usize;
        let mut chars = format.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch != '%' {
                output.push(ch);
                continue;
            }
            if chars.peek() == Some(&'%') {
                chars.next();
                output.push('%');
                continue;
            }

            while chars
                .peek()
                .copied()
                .map(|next| matches!(next, '-' | '+' | ' ' | '#' | '0'))
                .unwrap_or(false)
            {
                chars.next();
            }
            while chars
                .peek()
                .copied()
                .map(|next| next.is_ascii_digit())
                .unwrap_or(false)
            {
                chars.next();
            }
            if chars.peek() == Some(&'.') {
                chars.next();
                while chars
                    .peek()
                    .copied()
                    .map(|next| next.is_ascii_digit())
                    .unwrap_or(false)
                {
                    chars.next();
                }
            }

            let mut wide_arg = false;
            let mut wide_integer = false;
            if let Some(length) = chars.peek().copied() {
                match length {
                    'l' | 'L' => {
                        wide_arg = true;
                        chars.next();
                        if chars.peek() == Some(&'l') {
                            chars.next();
                            wide_integer = true;
                        }
                    }
                    'I' => {
                        chars.next();
                        let mut digits = String::new();
                        while chars
                            .peek()
                            .copied()
                            .map(|next| next.is_ascii_digit())
                            .unwrap_or(false)
                        {
                            digits.push(chars.next().unwrap());
                        }
                        wide_integer = digits == "64";
                    }
                    _ => {}
                }
            }

            let Some(specifier) = chars.next() else {
                output.push('%');
                break;
            };
            let next_arg = |cursor: &mut usize| {
                let value = args.get(*cursor).copied().unwrap_or(0);
                *cursor += 1;
                value
            };
            match specifier {
                'd' | 'i' => {
                    let raw = next_arg(&mut cursor);
                    let value = if wide_integer {
                        raw as i64
                    } else {
                        raw as u32 as i32 as i64
                    };
                    output.push_str(&value.to_string());
                }
                'u' => {
                    let raw = next_arg(&mut cursor);
                    let value = if wide_integer { raw } else { raw as u32 as u64 };
                    output.push_str(&value.to_string());
                }
                'x' => {
                    let raw = next_arg(&mut cursor);
                    let value = if wide_integer { raw } else { raw as u32 as u64 };
                    output.push_str(&format!("{value:x}"));
                }
                'X' => {
                    let raw = next_arg(&mut cursor);
                    let value = if wide_integer { raw } else { raw as u32 as u64 };
                    output.push_str(&format!("{value:X}"));
                }
                'p' => {
                    output.push_str(&format!("0x{:X}", next_arg(&mut cursor)));
                }
                's' | 'S' => {
                    let pointer = next_arg(&mut cursor);
                    let text = if pointer == 0 {
                        String::new()
                    } else if wide_arg || specifier == 'S' {
                        self.read_wide_string_from_memory(pointer)?
                    } else {
                        self.read_c_string_from_memory(pointer)?
                    };
                    output.push_str(&text);
                }
                'c' | 'C' => {
                    let value = next_arg(&mut cursor);
                    if wide_arg || specifier == 'C' {
                        if let Some(ch) = char::from_u32(value as u16 as u32) {
                            output.push(ch);
                        }
                    } else if let Some(ch) = char::from_u32(value as u8 as u32) {
                        output.push(ch);
                    }
                }
                _ => {
                    output.push('%');
                    output.push(specifier);
                }
            }
        }

        Ok(output)
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
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("msvcrt.dll", "?terminate@@YAXXZ") | ("msvcrt.dll", "terminate") => true,
            ("msvcrt.dll", "_controlfp") => true,
            ("msvcrt.dll", "_controlfp_s") => true,
            ("msvcrt.dll", "__set_app_type") => true,
            ("msvcrt.dll", "_set_app_type") => true,
            ("msvcrt.dll", "_set_fmode") => true,
            ("msvcrt.dll", "_configure_narrow_argv") => true,
            ("msvcrt.dll", "_configure_wide_argv") => true,
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
            ("msvcrt.dll", "_onexit") => true,
            ("msvcrt.dll", "_initialize_narrow_environment") => true,
            ("msvcrt.dll", "_invalid_parameter_noinfo_noreturn") => true,
            ("msvcrt.dll", "_errno") => true,
            ("msvcrt.dll", "getenv") => true,
            ("msvcrt.dll", "strerror") => true,
            ("msvcrt.dll", "__crtGetShowWindowMode") => true,
            ("msvcrt.dll", "__getmainargs") => true,
            ("msvcrt.dll", "__wgetmainargs") => true,
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
            ("msvcrt.dll", "memcpy_s") | ("msvcrt.dll", "memmove_s") => true,
            ("msvcrt.dll", "memcmp") => true,
            ("msvcrt.dll", "strlen") => true,
            ("msvcrt.dll", "strchr") => true,
            ("msvcrt.dll", "strstr") => true,
            ("msvcrt.dll", "_stricmp") => true,
            ("msvcrt.dll", "_wcsicmp") => true,
            ("msvcrt.dll", "_itow_s") => true,
            ("msvcrt.dll", "_itow") => true,
            ("msvcrt.dll", "wcscpy_s") => true,
            ("msvcrt.dll", "wcscmp") => true,
            ("msvcrt.dll", "wcstoul") => true,
            ("msvcrt.dll", "wcstol") => true,
            ("msvcrt.dll", "_wtoi") => true,
            ("msvcrt.dll", "_wtol") => true,
            ("msvcrt.dll", "_wcsdup") => true,
            ("msvcrt.dll", "iswspace") => true,
            ("msvcrt.dll", "swprintf_s") => true,
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
                    self.core.exit_code = Some(1);
                    self.dispatch.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "_controlfp") => {
                    let base = self.ensure_msvcrt_globals()?;
                    let current = self.read_u32(base + MSVCRT_CONTROLFP_OFFSET)?;
                    let new_value = ctx.raw(0) as u32;
                    let mask = ctx.raw(1) as u32;
                    let next = (current & !mask) | (new_value & mask);
                    self.write_u32(base + MSVCRT_CONTROLFP_OFFSET, next)?;
                    Ok(current as u64)
                }
                ("msvcrt.dll", "_controlfp_s") => {
                    let base = self.ensure_msvcrt_globals()?;
                    let current = self.read_u32(base + MSVCRT_CONTROLFP_OFFSET)?;
                    if ctx.raw(0) != 0 {
                        self.write_u32(ctx.raw(0), current)?;
                    }
                    let new_value = ctx.raw(1) as u32;
                    let mask = ctx.raw(2) as u32;
                    let next = (current & !mask) | (new_value & mask);
                    self.write_u32(base + MSVCRT_CONTROLFP_OFFSET, next)?;
                    Ok(0)
                }
                ("msvcrt.dll", "__set_app_type") => {
                    let base = self.ensure_msvcrt_globals()?;
                    self.write_u32(base + MSVCRT_APP_TYPE_OFFSET, ctx.raw(0) as u32)?;
                    Ok(0)
                }
                ("msvcrt.dll", "_set_app_type") => {
                    let base = self.ensure_msvcrt_globals()?;
                    self.write_u32(base + MSVCRT_APP_TYPE_OFFSET, ctx.raw(0) as u32)?;
                    Ok(0)
                }
                ("msvcrt.dll", "_set_fmode") => {
                    let base = self.ensure_msvcrt_globals()?;
                    self.write_u32(base + MSVCRT_FMODE_OFFSET, ctx.raw(0) as u32)?;
                    Ok(0)
                }
                ("msvcrt.dll", "_configure_narrow_argv")
                | ("msvcrt.dll", "_configure_wide_argv") => Ok(0),
                ("msvcrt.dll", "__p__fmode") => {
                    let ptr = self.ensure_msvcrt_globals()? + MSVCRT_FMODE_OFFSET;
                    Ok(ptr)
                }
                ("msvcrt.dll", "__p__commode") => {
                    let ptr = self.ensure_msvcrt_globals()? + MSVCRT_COMMODE_OFFSET;
                    Ok(ptr)
                }
                ("msvcrt.dll", "__setusermatherr") => {
                    let base = self.ensure_msvcrt_globals()?;
                    self.core
                        .modules
                        .memory_mut()
                        .write(base + MSVCRT_USER_MATHERR_OFFSET, &ctx.raw(0).to_le_bytes())?;
                    Ok(0)
                }
                ("msvcrt.dll", "_amsg_exit") | ("msvcrt.dll", "exit") | ("msvcrt.dll", "_exit") => {
                    self.core.exit_code = Some(ctx.raw(0) as u32);
                    self.dispatch.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "_initterm") => {
                    self.run_msvcrt_initterm_range(ctx.raw(0), ctx.raw(1), false)
                }
                ("msvcrt.dll", "_initterm_e") => {
                    self.run_msvcrt_initterm_range(ctx.raw(0), ctx.raw(1), true)
                }
                ("msvcrt.dll", "__vm_initterm_continue") => self.resume_pending_msvcrt_initterm(),
                ("msvcrt.dll", "_acmdln") => {
                    Ok(self.core.process_env.layout().command_line_ansi_buffer)
                }
                ("msvcrt.dll", "_XcptFilter") => Ok(0),
                ("msvcrt.dll", "_seh_filter_dll") => {
                    self.dispatch_msvcrt_seh_filter_dll(ctx.raw(0) as u32, ctx.raw(1))
                }
                ("msvcrt.dll", "_seh_filter_exe") => {
                    self.dispatch_msvcrt_seh_filter_exe(ctx.raw(0) as u32, ctx.raw(1))
                }
                ("msvcrt.dll", "__vcrt_initializecriticalsectionex") => Ok(1),
                ("msvcrt.dll", "_cexit") => {
                    let table = self.ensure_msvcrt_global_onexit_table()?;
                    self.execute_msvcrt_onexit_table(table)
                }
                ("msvcrt.dll", "_crt_atexit") | ("msvcrt.dll", "atexit") => {
                    let table = self.ensure_msvcrt_global_onexit_table()?;
                    self.register_msvcrt_onexit_function(table, ctx.raw(0))
                }
                ("msvcrt.dll", "_execute_onexit_table") => {
                    self.execute_msvcrt_onexit_table(ctx.raw(0))
                }
                ("msvcrt.dll", "_register_onexit_function") => {
                    self.register_msvcrt_onexit_function(ctx.raw(0), ctx.raw(1))
                }
                ("msvcrt.dll", "_initialize_onexit_table") => {
                    self.initialize_msvcrt_onexit_table(ctx.raw(0))?;
                    Ok(0)
                }
                ("msvcrt.dll", "_onexit") => {
                    let function = ctx.raw(0);
                    if function == 0 {
                        return Ok(0);
                    }
                    let table = self.ensure_msvcrt_global_onexit_table()?;
                    self.register_msvcrt_onexit_function(table, function)?;
                    Ok(function)
                }
                ("msvcrt.dll", "_initialize_narrow_environment") => Ok(0),
                ("msvcrt.dll", "_invalid_parameter_noinfo_noreturn") => {
                    self.dispatch.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "_errno") => {
                    let cell = self.ensure_msvcrt_errno_cell()?;
                    Ok(cell)
                }
                ("msvcrt.dll", "getenv") => {
                    if ctx.raw(0) == 0 {
                        return Ok(0);
                    }
                    let name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let Some(value) = self.runtime_environment_value(&name) else {
                        return Ok(0);
                    };
                    let buffer = self.ensure_msvcrt_strerror_buffer()?;
                    let _ =
                        self.write_c_string_to_memory(buffer, PAGE_SIZE as usize - 0x200, &value)?;
                    Ok(buffer)
                }
                ("msvcrt.dll", "strerror") => {
                    let error_code = ctx.raw(0) as u32;
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
                    self.core.modules.memory_mut().write(buffer, &bytes)?;
                    Ok(buffer)
                }
                ("msvcrt.dll", "__crtGetShowWindowMode") => Ok(10),
                ("msvcrt.dll", "__getmainargs") => {
                    let base = self.ensure_msvcrt_globals()?;
                    let argv = base + MSVCRT_ARGV_ARRAY_OFFSET;
                    let envp = base + MSVCRT_ENVP_ARRAY_OFFSET;
                    self.write_pointer_value(
                        argv,
                        self.core.process_env.layout().command_line_ansi_buffer,
                    )?;
                    self.write_pointer_value(argv + self.core.arch.pointer_size as u64, 0)?;
                    self.write_pointer_value(envp, 0)?;
                    if ctx.raw(0) != 0 {
                        self.write_u32(ctx.raw(0), 1)?;
                    }
                    if ctx.raw(1) != 0 {
                        self.write_pointer_value(ctx.raw(1), argv)?;
                    }
                    if ctx.raw(2) != 0 {
                        self.write_pointer_value(ctx.raw(2), envp)?;
                    }
                    Ok(0)
                }
                ("msvcrt.dll", "__wgetmainargs") => {
                    let base = self.ensure_msvcrt_globals()?;
                    let argv = base + MSVCRT_ARGV_ARRAY_OFFSET;
                    let envp = base + MSVCRT_ENVP_ARRAY_OFFSET;
                    self.write_pointer_value(
                        argv,
                        self.core.process_env.layout().command_line_buffer,
                    )?;
                    self.write_pointer_value(argv + self.core.arch.pointer_size as u64, 0)?;
                    self.write_pointer_value(
                        envp,
                        self.core.process_env.layout().environment_w_buffer,
                    )?;
                    self.write_pointer_value(envp + self.core.arch.pointer_size as u64, 0)?;
                    if ctx.raw(0) != 0 {
                        self.write_u32(ctx.raw(0), 1)?;
                    }
                    if ctx.raw(1) != 0 {
                        self.write_pointer_value(ctx.raw(1), argv)?;
                    }
                    if ctx.raw(2) != 0 {
                        self.write_pointer_value(ctx.raw(2), envp)?;
                    }
                    Ok(0)
                }
                ("msvcrt.dll", "memset") => {
                    let address = ctx.raw(0);
                    let value = ctx.raw(1) as u8;
                    let size = ctx.raw(2) as usize;
                    if address != 0 && size != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(address, &vec![value; size])?;
                    }
                    Ok(address)
                }
                ("msvcrt.dll", "_ismbblead") => {
                    let value = ctx.raw(0) as u8;
                    Ok((0x81..=0xFE).contains(&value) as u64)
                }
                ("msvcrt.dll", "_time64") => {
                    let unix_time = self
                        .dispatch
                        .time
                        .current()
                        .filetime
                        .saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS)
                        / 10_000_000;
                    if ctx.raw(0) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(0), &(unix_time as i64).to_le_bytes())?;
                    }
                    Ok(unix_time)
                }
                ("msvcrt.dll", "srand") => {
                    self.crt.msvcrt_rand_seed = ctx.raw(0) as u32;
                    Ok(0)
                }
                ("msvcrt.dll", "rand") => {
                    self.crt.msvcrt_rand_seed = self
                        .crt
                        .msvcrt_rand_seed
                        .wrapping_mul(214013)
                        .wrapping_add(2531011);
                    Ok(((self.crt.msvcrt_rand_seed >> 16) & 0x7FFF) as u64)
                }
                ("msvcrt.dll", "_vsnwprintf") => {
                    let buffer = ctx.raw(0);
                    let count = ctx.raw(1) as usize;
                    let format = self.read_wide_string_from_memory(ctx.raw(2))?;
                    if buffer == 0 || count == 0 {
                        Ok(0)
                    } else {
                        let rendered = self.format_variadic_wide_printf(&format, ctx.raw(3))?;
                        self.write_wide_string_to_memory(buffer, count, &rendered)
                    }
                }
                ("msvcrt.dll", "wcsrchr") => {
                    let mut result = 0;
                    let mut cursor = ctx.raw(0);
                    let needle = ctx.raw(1) as u16;
                    if cursor == 0 {
                        return Ok(0);
                    }
                    loop {
                        let bytes = self.core.modules.memory().read(cursor, 2)?;
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
                    let text = self.read_c_string_from_memory(ctx.raw(0))?;
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
                    Ok(value.saturating_mul(sign) as i32 as u64)
                }
                ("msvcrt.dll", "_callnewh") => Ok(0),
                ("msvcrt.dll", "malloc") | ("msvcrt.dll", "??2@YAPEAX_K@Z") => {
                    let address = self
                        .process_memory
                        .heaps
                        .alloc(
                            self.core.modules.memory_mut(),
                            self.process_memory.heaps.process_heap(),
                            ctx.raw(0).max(1),
                        )
                        .unwrap_or(0);
                    Ok(address)
                }
                ("msvcrt.dll", "calloc") => {
                    let size = ctx.raw(0).saturating_mul(ctx.raw(1)).max(1);
                    let address = self
                        .process_memory
                        .heaps
                        .alloc(
                            self.core.modules.memory_mut(),
                            self.process_memory.heaps.process_heap(),
                            size,
                        )
                        .unwrap_or(0);
                    if address != 0 {
                        self.fill_memory_pattern(address, size, 0)?;
                    }
                    Ok(address)
                }
                ("msvcrt.dll", "realloc") => {
                    let old_address = ctx.raw(0);
                    let new_size = ctx.raw(1);
                    if old_address == 0 {
                        let address = self
                            .process_memory
                            .heaps
                            .alloc(
                                self.core.modules.memory_mut(),
                                self.process_memory.heaps.process_heap(),
                                new_size.max(1),
                            )
                            .unwrap_or(0);
                        return Ok(address);
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
                    let Some(new_address) = self.process_memory.heaps.alloc(
                        self.core.modules.memory_mut(),
                        self.process_memory.heaps.process_heap(),
                        new_size.max(1),
                    ) else {
                        return Ok(0);
                    };
                    let copy_size = old_size.min(new_size) as usize;
                    let bytes = self.core.modules.memory().read(old_address, copy_size)?;
                    self.core.modules.memory_mut().write(new_address, &bytes)?;
                    let _ = self
                        .process_memory
                        .heaps
                        .free(self.process_memory.heaps.process_heap(), old_address);
                    Ok(new_address)
                }
                ("msvcrt.dll", "memmove") | ("msvcrt.dll", "memcpy") => {
                    self.copy_memory_block(ctx.raw(0), ctx.raw(1), ctx.raw(2) as usize)
                }
                ("msvcrt.dll", "memcpy_s") | ("msvcrt.dll", "memmove_s") => {
                    let destination = ctx.raw(0);
                    let capacity = ctx.raw(1) as usize;
                    let source = ctx.raw(2);
                    let count = ctx.raw(3) as usize;
                    if count == 0 {
                        self.write_msvcrt_errno_value(0)?;
                        return Ok(0);
                    }
                    if destination == 0 || source == 0 || capacity == 0 {
                        return self.fail_msvcrt_wide_result(MSVCRT_EINVAL, None);
                    }
                    if count > capacity {
                        self.fill_memory_pattern(destination, capacity as u64, 0)?;
                        return self.fail_msvcrt_wide_result(MSVCRT_ERANGE, None);
                    }
                    self.copy_memory_block(destination, source, count)?;
                    self.write_msvcrt_errno_value(0)?;
                    Ok(0)
                }
                ("msvcrt.dll", "memcmp") => {
                    let size = ctx.raw(2) as usize;
                    if size == 0 {
                        return Ok(0);
                    }
                    let Ok(left) = self.read_bytes_from_memory(ctx.raw(0), size) else {
                        return Ok(1);
                    };
                    let Ok(right) = self.read_bytes_from_memory(ctx.raw(1), size) else {
                        return Ok(1);
                    };
                    let result = match left.cmp(&right) {
                        std::cmp::Ordering::Less => -1i32,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    };
                    Ok(result as u64)
                }
                ("msvcrt.dll", "strlen") => {
                    Ok(self.read_c_string_from_memory(ctx.raw(0))?.len() as u64)
                }
                ("msvcrt.dll", "strchr") => {
                    let mut cursor = ctx.raw(0);
                    let needle = ctx.raw(1) as u8;
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
                    let haystack = self.read_c_string_from_memory(ctx.raw(0))?;
                    let needle = self.read_c_string_from_memory(ctx.raw(1))?;
                    if needle.is_empty() {
                        return Ok(ctx.raw(0));
                    }
                    Ok(haystack
                        .find(&needle)
                        .map(|offset| ctx.raw(0) + offset as u64)
                        .unwrap_or(0))
                }
                ("msvcrt.dll", "_stricmp") => {
                    let left = self.read_c_string_from_memory(ctx.raw(0))?;
                    let right = self.read_c_string_from_memory(ctx.raw(1))?;
                    Ok(compare_ci(&left, &right) as u64)
                }
                ("msvcrt.dll", "_wcsicmp") => {
                    let left = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let right = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(compare_ci(&left, &right) as u64)
                }
                ("msvcrt.dll", "_itow_s") => {
                    let value = ctx.raw(0) as u32 as i32;
                    let buffer = ctx.raw(1);
                    let capacity = ctx.raw(2) as usize;
                    let radix = ctx.raw(3) as u32;
                    let Some(rendered) = Self::msvcrt_format_signed_radix(value, radix) else {
                        return self
                            .fail_msvcrt_wide_result(MSVCRT_EINVAL, Some((buffer, capacity)));
                    };
                    self.write_msvcrt_wide_text_s(buffer, capacity, &rendered)
                }
                ("msvcrt.dll", "_itow") => {
                    let value = ctx.raw(0) as u32 as i32;
                    let buffer = ctx.raw(1);
                    let radix = ctx.raw(2) as u32;
                    let Some(rendered) = Self::msvcrt_format_signed_radix(value, radix) else {
                        return Ok(0);
                    };
                    self.write_msvcrt_wide_text_unchecked(buffer, &rendered)
                }
                ("msvcrt.dll", "wcscpy_s") => {
                    let destination = ctx.raw(0);
                    let capacity = ctx.raw(1) as usize;
                    let source = self.read_wide_string_from_memory(ctx.raw(2))?;
                    self.write_msvcrt_wide_text_s(destination, capacity, &source)
                }
                ("msvcrt.dll", "wcscmp") => {
                    Ok(self.compare_msvcrt_wide_strings(ctx.raw(0), ctx.raw(1))? as u64)
                }
                ("msvcrt.dll", "wcstoul") => {
                    let source = ctx.raw(0);
                    let parsed = self.parse_msvcrt_wide_integer(source, ctx.raw(2) as u32)?;
                    self.write_msvcrt_parse_end(source, ctx.raw(1), &parsed)?;
                    if !parsed.had_digits {
                        return Ok(0);
                    }
                    let value = if parsed.negative {
                        0u32.wrapping_sub(parsed.value as u32) as u64
                    } else {
                        parsed.value as u32 as u64
                    };
                    Ok(value)
                }
                ("msvcrt.dll", "wcstol") => {
                    let source = ctx.raw(0);
                    let parsed = self.parse_msvcrt_wide_integer(source, ctx.raw(2) as u32)?;
                    self.write_msvcrt_parse_end(source, ctx.raw(1), &parsed)?;
                    if !parsed.had_digits {
                        return Ok(0);
                    }
                    let signed = if parsed.negative {
                        -(parsed.value as i64)
                    } else {
                        parsed.value as i64
                    };
                    Ok(signed as i32 as u64)
                }
                ("msvcrt.dll", "_wtoi") => {
                    let parsed = self.parse_msvcrt_wide_integer(ctx.raw(0), 10)?;
                    let signed = if parsed.negative {
                        -(parsed.value as i64)
                    } else {
                        parsed.value as i64
                    };
                    Ok(signed as i32 as u64)
                }
                ("msvcrt.dll", "_wtol") => {
                    let parsed = self.parse_msvcrt_wide_integer(ctx.raw(0), 10)?;
                    let signed = if parsed.negative {
                        -(parsed.value as i64)
                    } else {
                        parsed.value as i64
                    };
                    Ok(signed as i32 as u64)
                }
                ("msvcrt.dll", "_wcsdup") => {
                    let text = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let size = text
                        .encode_utf16()
                        .count()
                        .saturating_add(1)
                        .saturating_mul(2) as u64;
                    let address = self
                        .process_memory
                        .heaps
                        .alloc(
                            self.core.modules.memory_mut(),
                            self.process_memory.heaps.process_heap(),
                            size.max(2),
                        )
                        .unwrap_or(0);
                    if address == 0 {
                        return Ok(0);
                    }
                    self.write_wide_string_to_memory(address, size as usize / 2, &text)?;
                    Ok(address)
                }
                ("msvcrt.dll", "iswspace") => {
                    let value = char::from_u32(ctx.raw(0) as u32)
                        .map(char::is_whitespace)
                        .unwrap_or(false);
                    Ok(value as u64)
                }
                ("msvcrt.dll", "swprintf_s") => {
                    let buffer = ctx.raw(0);
                    let capacity = ctx.raw(1) as usize;
                    let format = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let rendered =
                        self.render_msvcrt_inline_wide_printf(&format, &ctx.args()[3..])?;
                    if buffer == 0 || capacity == 0 {
                        return self.fail_msvcrt_wide_result(MSVCRT_EINVAL, None);
                    }
                    let required = rendered.encode_utf16().count().saturating_add(1);
                    if required > capacity {
                        self.clear_msvcrt_wide_buffer(buffer, capacity)?;
                        self.write_msvcrt_errno_value(MSVCRT_ERANGE)?;
                        return Ok(u32::MAX as u64);
                    }
                    let written = self.write_wide_string_to_memory(buffer, capacity, &rendered)?;
                    self.write_msvcrt_errno_value(0)?;
                    Ok(written)
                }
                ("msvcrt.dll", "__C_specific_handler") => {
                    Ok(if self.core.arch.is_x64() { 1 } else { 0 })
                }
                ("msvcrt.dll", "__CxxFrameHandler3") => {
                    Ok(if self.core.arch.is_x64() { 1 } else { 0 })
                }
                ("msvcrt.dll", "_CxxThrowException") => {
                    self.dispatch.force_native_return = true;
                    Ok(0)
                }
                ("msvcrt.dll", "free") | ("msvcrt.dll", "??3@YAXPEAX@Z") => {
                    let _ = self
                        .process_memory
                        .heaps
                        .free(self.process_memory.heaps.process_heap(), ctx.raw(0));
                    Ok(0)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
