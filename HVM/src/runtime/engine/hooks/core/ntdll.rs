use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_ntdll_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        if module_name != "ntdll.dll" {
            return None;
        }

        // Delegate to sub-dispatchers grouped by functionality.
        // Each returns Some(result) if it handles the function, None otherwise.
        self.dispatch_ntdll_syscalls(function, ctx)
            .or_else(|| self.dispatch_ntdll_rtl(function, ctx))
            .or_else(|| self.dispatch_ntdll_version(function, ctx))
            .or_else(|| self.dispatch_ntdll_stubs(function, ctx))
            .or_else(|| {
                // New ntdll exports without specific implementations return STATUS_SUCCESS.
                Some(Ok(STATUS_SUCCESS as u64))
            })
    }

    /// Handles ntdll.dll functions forwarded from kernel32.dll that need actual
    /// implementation (not just STATUS_SUCCESS).  Currently covers version-
    /// checking helpers whose return values affect sample control flow.
    pub(in crate::runtime::engine) fn dispatch_ntdll_version(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        match function {
            "VerSetConditionMask" => {
                let (current_mask, type_mask, condition) = if self.core.arch.is_x86() {
                    (ctx.raw(0) | (ctx.raw(1) << 32), ctx.raw(2), ctx.raw(3))
                } else {
                    (ctx.raw(0), ctx.raw(1), ctx.raw(2))
                };
                let bit_shift = (type_mask.trailing_zeros().min(20) * 3) as u64;
                Some(Ok(current_mask | ((condition & 0x7) << bit_shift)))
            }
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn ldr_find_entry_for_address(
        &mut self,
        address: u64,
        entry_out: u64,
    ) -> Result<u64, VmError> {
        let Some(module) = self.core.modules.get_by_address(address) else {
            if entry_out != 0 {
                self.write_pointer_value(entry_out, 0)?;
            }
            return Ok(STATUS_DLL_NOT_FOUND as u64);
        };
        let Some(entry) = self
            .core
            .process_env
            .loader_entry_for_module_base(module.visible_base)?
        else {
            if entry_out != 0 {
                self.write_pointer_value(entry_out, 0)?;
            }
            return Ok(STATUS_DLL_NOT_FOUND as u64);
        };
        if entry_out != 0 {
            self.write_pointer_value(entry_out, entry)?;
        }
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn request_ntdll_process_exit(
        &mut self,
        exit_status: u64,
    ) -> u64 {
        self.core.exit_code = Some(exit_status as u32);
        self.core.process_exit_requested = true;
        self.dispatch.force_native_return = true;
        exit_status
    }

    pub(in crate::runtime::engine) fn request_ntdll_thread_exit(
        &mut self,
        exit_status: u64,
    ) -> u64 {
        self.dispatch.force_native_return = true;
        exit_status
    }

    pub(in crate::runtime::engine) fn nt_terminate_process(
        &mut self,
        process_handle: u64,
        exit_status: u64,
    ) -> Result<u64, VmError> {
        if self.is_current_process_handle(process_handle) {
            return Ok(self.request_ntdll_process_exit(exit_status));
        }
        Ok(if self.is_known_process_target(process_handle) {
            STATUS_SUCCESS as u64
        } else {
            STATUS_INVALID_HANDLE as u64
        })
    }

    pub(in crate::runtime::engine) fn nt_terminate_thread(
        &mut self,
        thread_handle: u64,
        exit_status: u64,
    ) -> Result<u64, VmError> {
        if self.is_current_thread_handle(thread_handle) {
            return Ok(self.request_ntdll_thread_exit(exit_status));
        }
        Ok(
            if self
                .core
                .scheduler
                .thread_tid_for_handle((thread_handle & 0xFFFF_FFFF) as u32)
                .is_some()
            {
                STATUS_SUCCESS as u64
            } else {
                STATUS_INVALID_HANDLE as u64
            },
        )
    }

    pub(in crate::runtime::engine) fn ldr_get_procedure_address(
        &mut self,
        module_handle: u64,
        function_name: u64,
        ordinal: u16,
        function_address_out: u64,
    ) -> Result<u64, VmError> {
        let address = if function_name != 0 {
            let name = self.read_ansi_string_value(function_name)?;
            self.core.modules.resolve_export(
                module_handle,
                &self.core.config,
                &mut self.core.hooks,
                Some(&name),
                None,
            )
        } else if ordinal != 0 {
            self.core.modules.resolve_export(
                module_handle,
                &self.core.config,
                &mut self.core.hooks,
                None,
                Some(ordinal),
            )
        } else {
            0
        };
        if function_address_out != 0 {
            self.write_pointer_value(function_address_out, address)?;
        }
        Ok(if address != 0 {
            STATUS_SUCCESS as u64
        } else {
            STATUS_PROCEDURE_NOT_FOUND as u64
        })
    }

    pub(in crate::runtime::engine) fn ldr_load_dll(
        &mut self,
        _search_path: u64,
        _load_flags: u64,
        module_file_name: u64,
        module_handle_out: u64,
    ) -> Result<u64, VmError> {
        let name = self.read_unicode_string_value(module_file_name)?;
        let existing = self.core.modules.get_loaded(&name).cloned();
        let module = match self.core.modules.load_runtime_dependency(
            &name,
            &self.core.config,
            &mut self.core.hooks,
        ) {
            Ok(module) => module,
            Err(VmError::ModuleNotFound(_)) => {
                if module_handle_out != 0 {
                    self.write_pointer_value(module_handle_out, 0)?;
                }
                return Ok(STATUS_DLL_NOT_FOUND as u64);
            }
            Err(source) => return Err(source),
        };
        let module = self
            .refresh_module_visible_base(module.base)
            .unwrap_or(module);
        if existing.is_none() {
            self.register_module_image_allocation(self.current_process_space_key(), &module)?;
            self.run_dynamic_library_attach(&module)?;
            self.sync_process_environment_modules()?;
            self.log_module_event("MODULE_LOAD", &module, "LdrLoadDll")?;
        }
        let refcount = self
            .objects
            .dynamic_library_refs
            .entry(module.base)
            .or_insert(0);
        *refcount = refcount.saturating_add(1);
        if module_handle_out != 0 {
            self.write_pointer_value(module_handle_out, module.visible_base)?;
        }
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn read_ansi_string_value(
        &self,
        address: u64,
    ) -> Result<String, VmError> {
        if address == 0 {
            return Ok(String::new());
        }
        let length = self.read_u16(address)? as usize;
        let buffer = if self.core.arch.is_x86() {
            self.read_u32(address + 4)? as u64
        } else {
            self.read_pointer_value(address + 8)?
        };
        if buffer == 0 || length == 0 {
            return Ok(String::new());
        }
        Ok(String::from_utf8_lossy(&self.read_bytes_from_memory(buffer, length)?).into_owned())
    }

    pub(in crate::runtime::engine) fn rtl_create_unicode_string_from_asciiz(
        &mut self,
        destination_string: u64,
        source_string: u64,
    ) -> Result<u64, VmError> {
        if destination_string == 0 {
            return Ok(0);
        }
        if source_string == 0 {
            self.write_unicode_string_descriptor(destination_string, 0, 0, 0)?;
            return Ok(1);
        }
        let text = self.read_c_string_from_memory(source_string)?;
        let mut bytes = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let length = bytes.len().min(u16::MAX as usize) as u16;
        bytes.extend_from_slice(&[0, 0]);
        let Some(buffer) = self.process_memory.heaps.alloc(
            self.core.modules.memory_mut(),
            self.process_memory.heaps.process_heap(),
            bytes.len().max(2) as u64,
        ) else {
            self.write_unicode_string_descriptor(destination_string, 0, 0, 0)?;
            return Ok(0);
        };
        self.core.modules.memory_mut().write(buffer, &bytes)?;
        self.write_unicode_string_descriptor(destination_string, buffer, length, length + 2)?;
        Ok(1)
    }

    pub(in crate::runtime::engine) fn rtl_free_unicode_string(
        &mut self,
        unicode_string: u64,
    ) -> Result<u64, VmError> {
        if unicode_string == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let buffer = if self.core.arch.is_x86() {
            self.read_u32(unicode_string + 4)? as u64
        } else {
            self.read_pointer_value(unicode_string + 8)?
        };
        if buffer != 0 {
            let _ = self
                .process_memory
                .heaps
                .free(self.process_memory.heaps.process_heap(), buffer);
        }
        self.write_unicode_string_descriptor(unicode_string, 0, 0, 0)?;
        Ok(self.active_unicorn_return_value().unwrap_or(0))
    }

    pub(in crate::runtime::engine) fn rtl_init_unicode_string(
        &mut self,
        destination_string: u64,
        source_string: u64,
    ) -> Result<u64, VmError> {
        if destination_string == 0 {
            return Ok(0);
        }
        if source_string == 0 {
            self.write_unicode_string_descriptor(destination_string, 0, 0, 0)?;
            return Ok(0);
        }
        let length = self
            .read_wide_string_from_memory(source_string)?
            .encode_utf16()
            .count()
            .saturating_mul(2)
            .min(u16::MAX as usize) as u16;
        self.write_unicode_string_descriptor(
            destination_string,
            source_string,
            length,
            length.saturating_add(2),
        )?;
        Ok(0)
    }

    pub(in crate::runtime::engine) fn rtl_int64_to_unicode_string(
        &mut self,
        value: u64,
        base: u32,
        string: u64,
    ) -> Result<u64, VmError> {
        let Some(base) = Self::normalize_numeric_base(base) else {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };
        if string == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }

        let text = Self::format_unsigned_integer(value, base);
        let buffer = if self.core.arch.is_x86() {
            self.read_u32(string + 4)? as u64
        } else {
            self.read_pointer_value(string + 8)?
        };
        let maximum_length = self.read_u16(string + 2)? as usize;
        let encoded = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        if buffer == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        if encoded.len() > maximum_length {
            return Ok(STATUS_BUFFER_TOO_SMALL as u64);
        }

        self.core.modules.memory_mut().write(buffer, &encoded)?;
        if maximum_length >= encoded.len() + 2 {
            self.core
                .modules
                .memory_mut()
                .write(buffer + encoded.len() as u64, &[0, 0])?;
        }
        self.write_u16(string, encoded.len() as u16)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn rtl_integer_to_char(
        &mut self,
        value: u32,
        base: u32,
        output_length: i32,
        string: u64,
    ) -> Result<u64, VmError> {
        let Some(base) = Self::normalize_numeric_base(base) else {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };
        if string == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }

        let text = Self::format_unsigned_integer(value as u64, base);
        let capacity = output_length.max(0) as usize;
        // Real Windows checks string length against output length WITHOUT
        // counting the null terminator.  A buffer of exactly `len` bytes is
        // sufficient — the conversion succeeds and null termination is
        // attempted only when there is room.
        if capacity != 0 && text.len() > capacity {
            return Ok(STATUS_BUFFER_OVERFLOW as u64);
        }

        self.core
            .modules
            .memory_mut()
            .write(string, text.as_bytes())?;
        // Null-terminate only when the output buffer has room.
        if text.len() < capacity {
            self.core
                .modules
                .memory_mut()
                .write(string + text.len() as u64, &[0])?;
        }
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn rtl_random_ex(
        &mut self,
        seed_address: u64,
    ) -> Result<u64, VmError> {
        if seed_address == 0 {
            return Ok(0);
        }
        let seed = self.read_u32(seed_address)?;
        let next = seed.wrapping_mul(214013).wrapping_add(2_531_011);
        self.write_u32(seed_address, next)?;
        Ok(((next >> 16) & 0x7fff) as u64)
    }

    pub(in crate::runtime::engine) fn write_unicode_string_descriptor(
        &mut self,
        address: u64,
        buffer: u64,
        length: u16,
        maximum_length: u16,
    ) -> Result<(), VmError> {
        self.write_u16(address, length)?;
        self.write_u16(address + 2, maximum_length)?;
        if self.core.arch.is_x86() {
            self.write_u32(address + 4, buffer as u32)?;
        } else {
            self.write_u32(address + 4, 0)?;
            self.write_pointer_value(address + 8, buffer)?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn normalize_numeric_base(base: u32) -> Option<u32> {
        match base {
            0 => Some(10),
            2 | 8 | 10 | 16 => Some(base),
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn format_unsigned_integer(value: u64, base: u32) -> String {
        match base {
            2 => format!("{value:b}"),
            8 => format!("{value:o}"),
            16 => format!("{value:X}"),
            _ => value.to_string(),
        }
    }

    // ── ntdll string/memory helpers ─────────────────────────────────

    pub(in crate::runtime::engine) fn rtl_init_ansi_string(
        &mut self,
        destination: u64,
        source: u64,
    ) -> Result<u64, VmError> {
        if destination == 0 {
            return Ok(0);
        }
        if source == 0 {
            self.write_ansi_string_descriptor(destination, 0, 0, 0)?;
            return Ok(0);
        }
        let text = self.read_c_string_from_memory(source)?;
        let length = text.len().min(u16::MAX as usize) as u16;
        self.write_ansi_string_descriptor(destination, source, length, length.saturating_add(1))?;
        Ok(0)
    }

    pub(in crate::runtime::engine) fn write_ansi_string_descriptor(
        &mut self,
        address: u64,
        buffer: u64,
        length: u16,
        maximum_length: u16,
    ) -> Result<(), VmError> {
        self.write_u16(address, length)?;
        self.write_u16(address + 2, maximum_length)?;
        if self.core.arch.is_x86() {
            self.write_u32(address + 4, buffer as u32)?;
        } else {
            self.write_u32(address + 4, 0)?;
            self.write_pointer_value(address + 8, buffer)?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn rtl_append_unicode_to_string(
        &mut self,
        destination: u64,
        source: u64,
    ) -> Result<u64, VmError> {
        if destination == 0 || source == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let append_text = self.read_wide_string_from_memory(source)?;
        let dest_length = self.read_u16(destination)? as usize;
        let dest_max_length = self.read_u16(destination + 2)? as usize;
        let dest_buffer = if self.core.arch.is_x86() {
            self.read_u32(destination + 4)? as u64
        } else {
            self.read_pointer_value(destination + 8)?
        };
        if dest_buffer == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let append_bytes: Vec<u8> = append_text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let new_length = dest_length + append_bytes.len();
        if new_length > dest_max_length {
            return Ok(STATUS_BUFFER_TOO_SMALL as u64);
        }
        self.core
            .modules
            .memory_mut()
            .write(dest_buffer + dest_length as u64, &append_bytes)?;
        self.write_u16(destination, new_length as u16)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn rtl_append_unicode_string_to_string(
        &mut self,
        destination: u64,
        source: u64,
    ) -> Result<u64, VmError> {
        if destination == 0 || source == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let src_length = self.read_u16(source)? as usize;
        let src_buffer = if self.core.arch.is_x86() {
            self.read_u32(source + 4)? as u64
        } else {
            self.read_pointer_value(source + 8)?
        };
        if src_buffer == 0 || src_length == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let dest_length = self.read_u16(destination)? as usize;
        let dest_max_length = self.read_u16(destination + 2)? as usize;
        let dest_buffer = if self.core.arch.is_x86() {
            self.read_u32(destination + 4)? as u64
        } else {
            self.read_pointer_value(destination + 8)?
        };
        if dest_buffer == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let new_length = dest_length + src_length;
        if new_length > dest_max_length {
            return Ok(STATUS_BUFFER_TOO_SMALL as u64);
        }
        let src_data = self.read_bytes_from_memory(src_buffer, src_length)?;
        self.core
            .modules
            .memory_mut()
            .write(dest_buffer + dest_length as u64, &src_data)?;
        self.write_u16(destination, new_length as u16)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn rtl_compare_memory_impl(
        &self,
        left: u64,
        right: u64,
        length: usize,
    ) -> Result<usize, VmError> {
        if length == 0 || left == 0 || right == 0 {
            return Ok(0);
        }
        let left_bytes = self.read_bytes_from_memory(left, length)?;
        let right_bytes = self.read_bytes_from_memory(right, length)?;
        let matching = left_bytes
            .iter()
            .zip(right_bytes.iter())
            .take_while(|(a, b)| a == b)
            .count();
        Ok(matching)
    }

    pub(in crate::runtime::engine) fn rtl_compare_unicode_string_impl(
        &mut self,
        string1: u64,
        string2: u64,
        case_insensitive: bool,
    ) -> Result<u64, VmError> {
        let s1 = self.read_unicode_string_value(string1)?;
        let s2 = self.read_unicode_string_value(string2)?;
        let cmp = if case_insensitive {
            s1.to_ascii_lowercase().cmp(&s2.to_ascii_lowercase())
        } else {
            s1.cmp(&s2)
        };
        Ok(match cmp {
            std::cmp::Ordering::Less => u64::MAX,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }

    pub(in crate::runtime::engine) fn rtl_equal_unicode_string_impl(
        &mut self,
        string1: u64,
        string2: u64,
        case_insensitive: bool,
    ) -> Result<u64, VmError> {
        let s1 = self.read_unicode_string_value(string1)?;
        let s2 = self.read_unicode_string_value(string2)?;
        let equal = if case_insensitive {
            s1.eq_ignore_ascii_case(&s2)
        } else {
            s1 == s2
        };
        Ok(if equal { 1u64 } else { 0 })
    }

    pub(in crate::runtime::engine) fn rtl_ansi_string_to_unicode_string(
        &mut self,
        destination: u64,
        source: u64,
        allocate: bool,
    ) -> Result<u64, VmError> {
        if destination == 0 || source == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let ansi_text = self.read_ansi_string_value(source)?;
        let wide_bytes: Vec<u8> = ansi_text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let length = wide_bytes.len().min(u16::MAX as usize) as u16;
        let buffer = if allocate && !wide_bytes.is_empty() {
            let Some(buf) = self.process_memory.heaps.alloc(
                self.core.modules.memory_mut(),
                self.process_memory.heaps.process_heap(),
                wide_bytes.len().saturating_add(2) as u64,
            ) else {
                self.write_unicode_string_descriptor(destination, 0, 0, 0)?;
                return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
            };
            self.core.modules.memory_mut().write(buf, &wide_bytes)?;
            self.core
                .modules
                .memory_mut()
                .write(buf + wide_bytes.len() as u64, &[0u8, 0])?;
            buf
        } else {
            // Use source buffer directly if not allocating
            0
        };
        self.write_unicode_string_descriptor(
            destination,
            buffer,
            length,
            length.saturating_add(2),
        )?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn rtl_unicode_string_to_ansi_string(
        &mut self,
        destination: u64,
        source: u64,
        allocate: bool,
    ) -> Result<u64, VmError> {
        if destination == 0 || source == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let unicode_text = self.read_unicode_string_value(source)?;
        let ansi_bytes = unicode_text.as_bytes();
        let length = ansi_bytes.len().min(u16::MAX as usize) as u16;
        let buffer = if allocate && !ansi_bytes.is_empty() {
            let Some(buf) = self.process_memory.heaps.alloc(
                self.core.modules.memory_mut(),
                self.process_memory.heaps.process_heap(),
                ansi_bytes.len().saturating_add(1) as u64,
            ) else {
                self.write_ansi_string_descriptor(destination, 0, 0, 0)?;
                return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
            };
            self.core.modules.memory_mut().write(buf, ansi_bytes)?;
            self.core
                .modules
                .memory_mut()
                .write(buf + ansi_bytes.len() as u64, &[0u8])?;
            buf
        } else {
            0
        };
        self.write_ansi_string_descriptor(destination, buffer, length, length.saturating_add(1))?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn rtl_free_ansi_string_impl(
        &mut self,
        string: u64,
    ) -> Result<u64, VmError> {
        if string == 0 {
            return Ok(self.active_unicorn_return_value().unwrap_or(0));
        }
        let buffer = if self.core.arch.is_x86() {
            self.read_u32(string + 4)? as u64
        } else {
            self.read_pointer_value(string + 8)?
        };
        if buffer != 0 {
            let _ = self
                .process_memory
                .heaps
                .free(self.process_memory.heaps.process_heap(), buffer);
        }
        self.write_ansi_string_descriptor(string, 0, 0, 0)?;
        Ok(self.active_unicorn_return_value().unwrap_or(0))
    }
}

// Helper constant for ansi-to-unicode conversion
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
