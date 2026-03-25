use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn emit_console_text(
        &mut self,
        source: &str,
        handle: u64,
        text: &str,
    ) -> Result<(), VmError> {
        if text.is_empty() {
            return Ok(());
        }
        self.api_logger.log_console_output(
            self.current_process_id(),
            self.current_log_tid(),
            self.time.current().tick_ms,
            self.instruction_count,
            source,
            text,
            handle,
        )
    }

    fn read_printf_vararg(&self, cursor: &mut u64, wide: bool) -> Result<u64, VmError> {
        let width = if wide || self.arch.is_x64() {
            8u64
        } else {
            4u64
        };
        let value = if width == 8 {
            u64::from_le_bytes(
                self.modules
                    .memory()
                    .read(*cursor, width as usize)?
                    .try_into()
                    .unwrap(),
            )
        } else {
            self.read_u32(*cursor)? as u64
        };
        *cursor = (*cursor).saturating_add(width);
        Ok(value)
    }

    pub(in crate::runtime::engine) fn format_variadic_wide_printf(
        &self,
        format: &str,
        arg_list: u64,
    ) -> Result<String, VmError> {
        let mut output = String::new();
        let mut cursor = arg_list;
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
            match specifier {
                'd' | 'i' => {
                    let raw = self.read_printf_vararg(&mut cursor, wide_integer)?;
                    let value = if wide_integer {
                        raw as i64
                    } else {
                        raw as u32 as i32 as i64
                    };
                    output.push_str(&value.to_string());
                }
                'u' => {
                    let raw = self.read_printf_vararg(&mut cursor, wide_integer)?;
                    let value = if wide_integer { raw } else { raw as u32 as u64 };
                    output.push_str(&value.to_string());
                }
                'x' => {
                    let raw = self.read_printf_vararg(&mut cursor, wide_integer)?;
                    let value = if wide_integer { raw } else { raw as u32 as u64 };
                    output.push_str(&format!("{value:x}"));
                }
                'X' => {
                    let raw = self.read_printf_vararg(&mut cursor, wide_integer)?;
                    let value = if wide_integer { raw } else { raw as u32 as u64 };
                    output.push_str(&format!("{value:X}"));
                }
                'p' => {
                    let value = self.read_printf_vararg(&mut cursor, true)?;
                    output.push_str(&format!("0x{value:X}"));
                }
                's' | 'S' => {
                    let pointer = self.read_printf_vararg(&mut cursor, false)?;
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
                    let value = self.read_printf_vararg(&mut cursor, false)?;
                    if wide_arg || specifier == 'C' {
                        if let Some(ch) = char::from_u32(value as u16 as u32) {
                            output.push(ch);
                        }
                    } else {
                        output.push(value as u8 as char);
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

    pub(in crate::runtime::engine) fn write_version_info(
        &mut self,
        address: u64,
        wide: bool,
    ) -> Result<bool, VmError> {
        if address == 0 {
            return Ok(false);
        }
        let requested_size = self.read_u32(address)? as usize;
        if requested_size == 0 {
            return Ok(false);
        }

        let (base_size, ex_size, csd) = if wide {
            (0x114usize, 0x11Cusize, {
                let mut bytes = self
                    .environment_profile
                    .os_version
                    .csd_version
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>();
                bytes.resize(128 * 2, 0);
                bytes
            })
        } else {
            (0x94usize, 0x9Cusize, {
                let mut bytes = self
                    .environment_profile
                    .os_version
                    .csd_version
                    .chars()
                    .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' })
                    .collect::<Vec<_>>();
                bytes.resize(128, 0);
                bytes
            })
        };
        let version = &self.environment_profile.os_version;

        let mut payload = Vec::with_capacity(requested_size);
        payload.extend_from_slice(&(requested_size as u32).to_le_bytes());
        payload.extend_from_slice(&version.major.to_le_bytes());
        payload.extend_from_slice(&version.minor.to_le_bytes());
        payload.extend_from_slice(&version.build.to_le_bytes());
        payload.extend_from_slice(&version.platform_id.to_le_bytes());
        payload.extend_from_slice(&csd);
        if requested_size >= ex_size {
            payload.extend_from_slice(&version.service_pack_major.to_le_bytes());
            payload.extend_from_slice(&version.service_pack_minor.to_le_bytes());
            payload.extend_from_slice(&version.suite_mask.to_le_bytes());
            payload.push(version.product_type);
            payload.push(0);
        } else if requested_size < base_size {
            payload.truncate(requested_size);
        }
        payload.resize(requested_size, 0);
        self.modules.memory_mut().write(address, &payload)?;
        Ok(true)
    }
}
