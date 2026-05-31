use super::*;

impl VirtualExecutionEngine {
    /// Time/File I/O dispatch — arms 171-255.
    pub(in crate::runtime::engine) fn dispatch_k32_time_file(
        &mut self,
        function: &str,
        signature: &HookSignature,
        stub_address: u64,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let _ = stub_address;
        match function {
            "GetSystemTimeAsFileTime" | "GetSystemTimePreciseAsFileTime" => {
                Some((|| -> Result<u64, VmError> {
                    if ctx.raw(0) != 0 {
                        self.core.modules.memory_mut().write(
                            ctx.raw(0),
                            &self.dispatch.time.current().filetime.to_le_bytes(),
                        )?;
                    }
                    Ok(0)
                })())
            }
            "lstrlenA" => {
                Some(if ctx.raw(0) == 0 {
                    Ok(0)
                } else {
                    // lstrlenA returns the byte count until the null terminator,
                    // NOT the filtered ASCII character count. Real Windows would
                    // raise on an invalid pointer; for analysis, treat bad probe
                    // pointers as empty strings so one corrupt/guarded pointer does
                    // not terminate the whole VM run.
                    Ok(self
                        .read_c_string_bytes_from_memory(ctx.raw(0))
                        .map(|bytes| bytes.len() as u64)
                        .unwrap_or(0))
                })
            }
            "lstrlenW" => Some(if ctx.raw(0) == 0 {
                Ok(0)
            } else {
                Ok(self
                    .read_wide_string_from_memory(ctx.raw(0))
                    .map(|text| text.encode_utf16().count() as u64)
                    .unwrap_or(0))
            }),
            "uaw_wcsrchr" => Some((|| -> Result<u64, VmError> {
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
            })()),
            "CxIZKa" => Some((|| -> Result<u64, VmError> {
                for pointer in [ctx.raw(1), ctx.raw(3), ctx.raw(4)] {
                    if pointer != 0 {
                        self.write_pointer_value(pointer, 0)?;
                    }
                }
                self.set_last_error(ERROR_SUCCESS as u32);
                Ok(0)
            })()),
            "GetTickCount" => Some(Ok(self.dispatch.time.current().tick_ms)),
            "GetTickCount64" => Some(Ok(self.dispatch.time.current().tick_ms)),
            "EnumSystemLocalesW" | "EnumSystemLocalesA" => Some(Ok(1)),
            "GetUserDefaultLCID" => Some(Ok(self.user_default_lcid())),
            "GetVersion" => Some(Ok(self.version_return_value())),
            "GetVersionExA" => Some((|| -> Result<u64, VmError> {
                Ok(self.write_version_info(ctx.raw(0), false)? as u64)
            })()),
            "GetVersionExW" => Some((|| -> Result<u64, VmError> {
                Ok(self.write_version_info(ctx.raw(0), true)? as u64)
            })()),
            "HeapAlloc" => Some((|| -> Result<u64, VmError> {
                let heap = ctx.raw(0) as u32;
                let size = ctx.raw(2).max(1);
                let flags = ctx.raw(1);
                if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                    eprintln!(
                        "[HOOK] HeapAlloc heap=0x{:X} flags=0x{:X} size=0x{:X}",
                        heap, flags, size
                    );
                }
                let address = self
                    .process_memory
                    .heaps
                    .alloc(self.core.modules.memory_mut(), heap, size)
                    .unwrap_or(0);
                if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                    eprintln!("[HOOK] HeapAlloc:alloc_result address=0x{:X}", address);
                }
                if address != 0 {
                    if flags & HEAP_ZERO_MEMORY != 0 {
                        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                            eprintln!(
                                "[HOOK] HeapAlloc:fill address=0x{:X} size=0x{:X}",
                                address, size
                            );
                        }
                        self.fill_memory_pattern(address, size, 0)?;
                        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                            eprintln!(
                                "[HOOK] HeapAlloc:fill_done address=0x{:X} size=0x{:X}",
                                address, size
                            );
                        }
                    }
                    self.log_heap_event("HEAP_ALLOC", heap, address, size, "HeapAlloc")?;
                }
                if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                    eprintln!("[HOOK] HeapAlloc:done address=0x{:X}", address);
                }
                Ok(address)
            })()),
            "HeapCreate" => Some((|| -> Result<u64, VmError> {
                let heap = self
                    .process_memory
                    .heaps
                    .create_heap(self.core.modules.memory_mut())?;
                Ok(heap as u64)
            })()),
            "HeapDestroy" => Some(Ok(self
                .process_memory
                .heaps
                .destroy(self.core.modules.memory_mut(), ctx.raw(0) as u32)
                as u64)),
            "HeapFree" => Some((|| -> Result<u64, VmError> {
                let result = self
                    .process_memory
                    .heaps
                    .free(ctx.raw(0) as u32, ctx.raw(2)) as u64;
                if result != 0 {
                    self.log_heap_event("HEAP_FREE", ctx.raw(0) as u32, ctx.raw(2), 0, "HeapFree")?;
                }
                Ok(result)
            })()),
            "HeapLock" | "HeapUnlock" => Some(Ok(1)),
            "HeapReAlloc" => Some((|| -> Result<u64, VmError> {
                let heap = ctx.raw(0) as u32;
                let old_address = ctx.raw(2);
                let new_size = ctx.raw(3).max(1);
                let old_size = self.process_memory.heaps.size(heap, old_address);
                if old_size == u32::MAX as u64 {
                    return Ok(0);
                }
                let Some(new_address) =
                    self.process_memory
                        .heaps
                        .alloc(self.core.modules.memory_mut(), heap, new_size)
                else {
                    return Ok(0);
                };
                let copy_size = old_size.min(new_size) as usize;
                let bytes = self.core.modules.memory().read(old_address, copy_size)?;
                self.core.modules.memory_mut().write(new_address, &bytes)?;
                if ctx.raw(1) & HEAP_ZERO_MEMORY != 0 && new_size > old_size {
                    self.fill_memory_pattern(
                        new_address + old_size,
                        new_size.saturating_sub(old_size),
                        0,
                    )?;
                }
                self.process_memory.heaps.free(heap, old_address);
                self.log_heap_event("HEAP_REALLOC", heap, new_address, new_size, "HeapReAlloc")?;
                Ok(new_address)
            })()),
            "HeapSetInformation" => Some(Ok(1)),
            "HeapSize" => Some(Ok(self
                .process_memory
                .heaps
                .size(ctx.raw(0) as u32, ctx.raw(2)))),
            "HeapWalk" => Some(Ok(0)),
            "IsDebuggerPresent" => Some(Ok(0)),
            "IsWow64Process" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(1) != 0 {
                    self.write_u32(ctx.raw(1), 1)?;
                }
                Ok(1)
            })()),
            "IsValidCodePage" => Some(Ok(1)),
            "IsValidLocale" => Some(Ok(1)),
            "IsProcessorFeaturePresent" => Some(Ok(1)),
            "LCMapStringA" => Some((|| -> Result<u64, VmError> {
                let mut text = self.read_c_string_from_memory(ctx.raw(2))?;
                let source_len = ctx.raw(3);
                if source_len != 0 && source_len != u32::MAX as u64 {
                    text = text.chars().take(source_len as usize).collect();
                }
                let mut data = text.into_bytes();
                data.push(0);
                if ctx.raw(5) == 0 {
                    Ok(data.len() as u64)
                } else {
                    self.write_raw_bytes_to_memory(ctx.raw(4), ctx.raw(5) as usize, &data)
                }
            })()),
            "LCMapStringEx" => Some((|| -> Result<u64, VmError> {
                let mut text = self.read_wide_string_from_memory(ctx.raw(2))?;
                let source_len = ctx.raw(3);
                if source_len != 0 && source_len != u32::MAX as u64 {
                    text = text.chars().take(source_len as usize).collect();
                }
                let data = text
                    .encode_utf16()
                    .flat_map(|word| word.to_le_bytes())
                    .chain([0, 0])
                    .collect::<Vec<_>>();
                let required = data.len() / 2;
                if ctx.raw(4) == 0 || ctx.raw(5) == 0 {
                    Ok(required as u64)
                } else {
                    let written = self.write_raw_bytes_to_memory(
                        ctx.raw(4),
                        (ctx.raw(5) as usize).saturating_mul(2),
                        &data,
                    )?;
                    Ok((written / 2) as u64)
                }
            })()),
            "LCMapStringW" => Some((|| -> Result<u64, VmError> {
                let mut text = self.read_wide_string_from_memory(ctx.raw(2))?;
                let source_len = ctx.raw(3);
                if source_len != 0 && source_len != u32::MAX as u64 {
                    text = text.chars().take(source_len as usize).collect();
                }
                let data = text
                    .encode_utf16()
                    .flat_map(|word| word.to_le_bytes())
                    .chain([0, 0])
                    .collect::<Vec<_>>();
                let required = data.len() / 2;
                if ctx.raw(5) == 0 {
                    Ok(required as u64)
                } else {
                    let written = self.write_raw_bytes_to_memory(
                        ctx.raw(4),
                        (ctx.raw(5) as usize).saturating_mul(2),
                        &data,
                    )?;
                    Ok((written / 2) as u64)
                }
            })()),
            "CompareStringW" => Some((|| -> Result<u64, VmError> {
                let left = self.read_wide_input_string(ctx.raw(2), ctx.raw(3))?;
                let right = self.read_wide_input_string(ctx.raw(4), ctx.raw(5))?;
                let ordering = if ctx.raw(1) & 0x0000_0001 != 0 {
                    compare_ci(&left, &right)
                } else {
                    match left.cmp(&right) {
                        std::cmp::Ordering::Less => -1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    }
                };
                Ok(match ordering {
                    value if value < 0 => CSTR_LESS_THAN,
                    0 => CSTR_EQUAL,
                    _ => CSTR_GREATER_THAN,
                })
            })()),
            "LocalAlloc" => Some((|| -> Result<u64, VmError> {
                let size = ctx.raw(1).max(1);
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
                    if ctx.raw(0) & LMEM_ZEROINIT != 0 {
                        self.fill_memory_pattern(address, size, 0)?;
                    }
                    self.log_heap_event(
                        "HEAP_ALLOC",
                        self.process_memory.heaps.process_heap(),
                        address,
                        size,
                        "LocalAlloc",
                    )?;
                }
                Ok(address)
            })()),
            "LocalFree" => Some(Ok(
                if self
                    .process_memory
                    .heaps
                    .free(self.process_memory.heaps.process_heap(), ctx.raw(0))
                {
                    let _ = self.log_heap_event(
                        "HEAP_FREE",
                        self.process_memory.heaps.process_heap(),
                        ctx.raw(0),
                        0,
                        "LocalFree",
                    );
                    0
                } else {
                    ctx.raw(0)
                },
            )),
            "LocalFileTimeToFileTime" => Some((|| -> Result<u64, VmError> {
                let source = self.read_bytes_from_memory(ctx.raw(0), 8)?;
                self.core.modules.memory_mut().write(ctx.raw(1), &source)?;
                Ok(1)
            })()),
            "LoadLibraryA" | "LoadLibraryExA" => Some((|| -> Result<u64, VmError> {
                let name = self.read_c_string_from_memory(ctx.raw(0))?;
                let existing = self.core.modules.get_loaded(&name).cloned();
                let module = self.core.modules.load_runtime_dependency(
                    &name,
                    &self.core.config,
                    &mut self.core.hooks,
                )?;
                let module = self
                    .refresh_module_visible_base(module.base)
                    .unwrap_or(module);
                if existing.is_none() {
                    self.register_module_image_allocation(
                        self.current_process_space_key(),
                        &module,
                    )?;
                    self.run_dynamic_library_attach(&module)?;
                    self.sync_process_environment_modules()?;
                    self.log_module_event("MODULE_LOAD", &module, signature.function)?;
                }
                let refcount = self
                    .objects
                    .dynamic_library_refs
                    .entry(module.base)
                    .or_insert(0);
                *refcount = refcount.saturating_add(1);
                if module.visible_base != 0 {
                    self.set_last_error(ERROR_SUCCESS as u32);
                }
                Ok(module.visible_base)
            })()),
            "LoadLibraryW" | "LoadLibraryExW" => Some((|| -> Result<u64, VmError> {
                let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                let existing = self.core.modules.get_loaded(&name).cloned();
                let module = self.core.modules.load_runtime_dependency(
                    &name,
                    &self.core.config,
                    &mut self.core.hooks,
                )?;
                let module = self
                    .refresh_module_visible_base(module.base)
                    .unwrap_or(module);
                if existing.is_none() {
                    self.register_module_image_allocation(
                        self.current_process_space_key(),
                        &module,
                    )?;
                    self.run_dynamic_library_attach(&module)?;
                    self.sync_process_environment_modules()?;
                    self.log_module_event("MODULE_LOAD", &module, signature.function)?;
                }
                let refcount = self
                    .objects
                    .dynamic_library_refs
                    .entry(module.base)
                    .or_insert(0);
                *refcount = refcount.saturating_add(1);
                if module.visible_base != 0 {
                    self.set_last_error(ERROR_SUCCESS as u32);
                }
                Ok(module.visible_base)
            })()),
            "lstrcatA" => Some((|| -> Result<u64, VmError> {
                let destination = ctx.raw(0);
                let mut left = self.read_c_string_from_memory(destination)?;
                let right = self.read_c_string_from_memory(ctx.raw(1))?;
                left.push_str(&right);
                let _ = self.write_c_string_to_memory(destination, 0x1000, &left)?;
                Ok(destination)
            })()),
            "lstrcatW" => Some((|| -> Result<u64, VmError> {
                let destination = ctx.raw(0);
                let mut left = self.read_wide_string_from_memory(destination)?;
                let right = self.read_wide_string_from_memory(ctx.raw(1))?;
                left.push_str(&right);
                let _ = self.write_wide_string_to_memory(destination, 0x1000, &left)?;
                Ok(destination)
            })()),
            "lstrcmpiW" => Some((|| -> Result<u64, VmError> {
                let left = self.read_wide_string_from_memory(ctx.raw(0))?;
                let right = self.read_wide_string_from_memory(ctx.raw(1))?;
                Ok(compare_ci(&left, &right) as u64)
            })()),
            "lstrcpynA" => Some((|| -> Result<u64, VmError> {
                let destination = ctx.raw(0);
                let text = self.read_c_string_from_memory(ctx.raw(1))?;
                let max_length = (ctx.raw(2) as i32).max(0) as usize;
                if destination == 0 || max_length == 0 {
                    return Ok(destination);
                }
                let writable = max_length.saturating_sub(1);
                let clipped = &text[..text.len().min(writable)];
                let _ = self.write_c_string_to_memory(destination, max_length, clipped)?;
                Ok(destination)
            })()),
            "lstrcpyA" => Some((|| -> Result<u64, VmError> {
                let destination = ctx.raw(0);
                let text = self.read_c_string_from_memory(ctx.raw(1))?;
                let _ = self.write_c_string_to_memory(destination, 0x1000, &text)?;
                Ok(destination)
            })()),
            "lstrcpyW" => Some((|| -> Result<u64, VmError> {
                let destination = ctx.raw(0);
                let text = self.read_wide_string_from_memory(ctx.raw(1))?;
                let _ = self.write_wide_string_to_memory(destination, 0x1000, &text)?;
                Ok(destination)
            })()),
            "MoveFileA" => Some((|| -> Result<u64, VmError> {
                let source = self.read_c_string_from_memory(ctx.raw(0))?;
                let destination = self.read_c_string_from_memory(ctx.raw(1))?;
                if source.is_empty() || destination.is_empty() {
                    self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                    return Ok(0);
                }
                let Some(source_path) = self.prepare_runtime_read_target(&source, "MoveFileA")?
                else {
                    return Ok(0);
                };
                self.ensure_runtime_path_backing(&destination)?;
                let destination_path = self.resolve_runtime_path(&destination);
                let result = std::fs::rename(&source_path, &destination_path).is_ok() as u64;
                if result != 0 {
                    self.log_file_event(
                        "FILE_RENAME",
                        0,
                        &format!(
                            "{} -> {}",
                            source_path.to_string_lossy(),
                            destination_path.to_string_lossy()
                        ),
                        None,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                } else {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                }
                Ok(result)
            })()),
            "MoveFileW" | "MoveFileExW" => Some((|| -> Result<u64, VmError> {
                let source = self.read_wide_string_from_memory(ctx.raw(0))?;
                let destination = self.read_wide_string_from_memory(ctx.raw(1))?;
                if source.is_empty() || destination.is_empty() {
                    self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                    return Ok(0);
                }
                let Some(source_path) = self.prepare_runtime_read_target(&source, "MoveFileW")?
                else {
                    return Ok(0);
                };
                self.ensure_runtime_path_backing(&destination)?;
                let destination_path = self.resolve_runtime_path(&destination);
                if source_path.exists() {
                    self.log_file_event(
                        "FILE_RENAME",
                        0,
                        &format!(
                            "{} -> {}",
                            source_path.to_string_lossy(),
                            destination_path.to_string_lossy()
                        ),
                        None,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                } else {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    Ok(0)
                }
            })()),
            "MapViewOfFile" => Some(self.map_view_of_file(
                ctx.raw(0) as u32,
                ctx.raw(1) as u32,
                (ctx.raw(2) << 32) | ctx.raw(3),
                ctx.raw(4),
            )),
            "MultiByteToWideChar" => Some((|| -> Result<u64, VmError> {
                let source = self.read_ansi_input(ctx.raw(2), ctx.raw(3))?;
                let text = self.decode_code_page_bytes(ctx.raw(0), &source);
                let encoded = text
                    .encode_utf16()
                    .flat_map(|word| word.to_le_bytes())
                    .chain([0, 0])
                    .collect::<Vec<_>>();
                let required = encoded.len() / 2;
                if ctx.raw(4) == 0 || ctx.raw(5) == 0 {
                    Ok(required as u64)
                } else {
                    let writable = (ctx.raw(5) as usize).min(required) * 2;
                    self.core
                        .modules
                        .memory_mut()
                        .write(ctx.raw(4), &encoded[..writable])?;
                    Ok(required.min(ctx.raw(5) as usize) as u64)
                }
            })()),
            "InitializeSListHead" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(0) != 0 {
                    self.core.modules.memory_mut().write(ctx.raw(0), &[0; 8])?;
                }
                Ok(0)
            })()),
            "InterlockedPushEntrySList" => Some((|| -> Result<u64, VmError> {
                let header = ctx.raw(0);
                let entry = ctx.raw(1);
                if header == 0 || entry == 0 {
                    return Ok(0);
                }
                let previous = self.read_pointer_value(header)?;
                self.write_pointer_value(entry, previous)?;
                self.write_pointer_value(header, entry)?;
                Ok(previous)
            })()),
            "InterlockedCompareExchange" => Some((|| -> Result<u64, VmError> {
                let address = ctx.raw(0);
                let exchange = ctx.raw(1) as u32;
                let comparand = ctx.raw(2) as u32;
                let current = self.read_u32(address)?;
                if current == comparand {
                    self.write_u32(address, exchange)?;
                }
                Ok(current as u64)
            })()),
            "InterlockedDecrement" => Some((|| -> Result<u64, VmError> {
                let address = ctx.raw(0);
                let value = self.read_u32(address)?.wrapping_sub(1);
                self.write_u32(address, value)?;
                Ok(value as u64)
            })()),
            "InterlockedExchange" => Some((|| -> Result<u64, VmError> {
                let address = ctx.raw(0);
                let value = ctx.raw(1) as u32;
                let current = self.read_u32(address)?;
                self.write_u32(address, value)?;
                Ok(current as u64)
            })()),
            "InterlockedExchangeAdd" => Some((|| -> Result<u64, VmError> {
                let address = ctx.raw(0);
                let delta = ctx.raw(1) as u32;
                let current = self.read_u32(address)?;
                self.write_u32(address, current.wrapping_add(delta))?;
                Ok(current as u64)
            })()),
            "InterlockedIncrement" => Some((|| -> Result<u64, VmError> {
                let address = ctx.raw(0);
                let value = self.read_u32(address)?.wrapping_add(1);
                self.write_u32(address, value)?;
                Ok(value as u64)
            })()),
            "InterlockedFlushSList" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(0) != 0 {
                    self.core.modules.memory_mut().write(ctx.raw(0), &[0; 8])?;
                }
                Ok(0)
            })()),
            "QueryPerformanceCounter" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(0) == 0 {
                    return Ok(0);
                }
                let counter = self.dispatch.time.current().tick_ms.saturating_mul(10_000);
                self.core
                    .modules
                    .memory_mut()
                    .write(ctx.raw(0), &counter.to_le_bytes())?;
                Ok(1)
            })()),
            "QueryFullProcessImageNameA" => Some(self.query_full_process_image_name_result(
                ctx.raw(0),
                ctx.raw(2),
                ctx.raw(3),
                false,
            )),
            "QueryFullProcessImageNameW" => Some(self.query_full_process_image_name_result(
                ctx.raw(0),
                ctx.raw(2),
                ctx.raw(3),
                true,
            )),
            "QueryDosDeviceA" => Some((|| -> Result<u64, VmError> {
                let entries = if ctx.raw(0) == 0 {
                    self.query_dos_device_names()
                } else {
                    self.query_dos_device_targets(&self.read_c_string_from_memory(ctx.raw(0))?)
                };
                if entries.is_empty() {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    Ok(0)
                } else {
                    let mut payload = entries.join("\0");
                    payload.push('\0');
                    payload.push('\0');
                    let required = payload.len();
                    if ctx.raw(1) == 0 || ctx.raw(2) == 0 || (ctx.raw(2) as usize) < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(1), payload.as_bytes())?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok((required.saturating_sub(1)) as u64)
                    }
                }
            })()),
            "QueryDosDeviceW" => Some((|| -> Result<u64, VmError> {
                let entries = if ctx.raw(0) == 0 {
                    self.query_dos_device_names()
                } else {
                    self.query_dos_device_targets(&self.read_wide_string_from_memory(ctx.raw(0))?)
                };
                if entries.is_empty() {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    Ok(0)
                } else {
                    let mut payload = entries.join("\0");
                    payload.push('\0');
                    payload.push('\0');
                    let units = payload.encode_utf16().collect::<Vec<_>>();
                    let required = units.len();
                    let bytes = units
                        .into_iter()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>();
                    if ctx.raw(1) == 0 || ctx.raw(2) == 0 || (ctx.raw(2) as usize) < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        self.core.modules.memory_mut().write(ctx.raw(1), &bytes)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok((required.saturating_sub(1)) as u64)
                    }
                }
            })()),
            "QueueUserAPC" => Some((|| -> Result<u64, VmError> {
                if self
                    .core
                    .scheduler
                    .queue_user_apc(ctx.raw(0) as u32, ctx.raw(1), ctx.raw(2))
                    .is_some()
                {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                } else {
                    self.set_last_error(ERROR_INVALID_HANDLE as u32);
                    Ok(0)
                }
            })()),
            "QueueUserWorkItem" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(0) == 0 {
                    self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                    Ok(0)
                } else {
                    let _ = self.create_runtime_thread(ctx.raw(0), ctx.raw(1), 0, 0)?;
                    Ok(1)
                }
            })()),
            "PostQueuedCompletionStatus" => Some((|| -> Result<u64, VmError> {
                let handle = ctx.raw(0) as u32;
                let Some(queue) = self.handles.io_completion_ports.get_mut(&handle) else {
                    self.set_last_error(ERROR_INVALID_HANDLE as u32);
                    return Ok(0);
                };
                queue.push_back(IoCompletionPacket {
                    bytes_transferred: ctx.raw(1) as u32,
                    completion_key: ctx.raw(2),
                    overlapped: ctx.raw(3),
                });
                self.set_last_error(ERROR_SUCCESS as u32);
                Ok(1)
            })()),
            "QueryActCtxW" => Some((|| -> Result<u64, VmError> {
                let info_class = ctx.raw(3);
                let buffer = ctx.raw(4);
                let buffer_size = ctx.raw(5) as usize;
                let required = match info_class {
                    1 => {
                        if self.core.arch.is_x86() {
                            8
                        } else {
                            16
                        }
                    }
                    _ => buffer_size.max(1),
                };
                if ctx.raw(6) != 0 {
                    self.write_u32(ctx.raw(6), required as u32)?;
                }
                if buffer == 0 || buffer_size < required {
                    self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                    Ok(0)
                } else {
                    self.core
                        .modules
                        .memory_mut()
                        .write(buffer, &vec![0u8; required])?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
            })()),
            "ActivateActCtx" => Some((|| -> Result<u64, VmError> {
                let cookie_ptr = ctx.raw(1);
                if cookie_ptr != 0 {
                    let cookie_size = self.core.arch.pointer_size as u64;
                    if !self.is_writable_guest_range(cookie_ptr, cookie_size) {
                        self.set_last_error(ERROR_SUCCESS as u32);
                    } else if self.core.arch.is_x86() {
                        self.write_u32(cookie_ptr, ctx.raw(0) as u32)?;
                    } else {
                        self.core
                            .modules
                            .memory_mut()
                            .write(cookie_ptr, &ctx.raw(0).to_le_bytes())?;
                    }
                }
                self.set_last_error(ERROR_SUCCESS as u32);
                Ok(1)
            })()),
            "RegisterApplicationRestart"
            | "RegisterApplicationRecoveryCallback"
            | "UnregisterApplicationRestart"
            | "UnregisterApplicationRecoveryCallback" => Some(Ok(ERROR_SUCCESS)),
            "ApplicationRecoveryInProgress" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(0) != 0 {
                    self.write_u32(ctx.raw(0), 0)?;
                }
                Ok(ERROR_SUCCESS)
            })()),
            "ApplicationRecoveryFinished" => Some(Ok(0)),
            "DeactivateActCtx" => Some((|| -> Result<u64, VmError> {
                self.set_last_error(ERROR_SUCCESS as u32);
                Ok(1)
            })()),
            "FindActCtxSectionStringW" => Some((|| -> Result<u64, VmError> {
                let returned_data = ctx.raw(4);
                if returned_data != 0 {
                    let declared_size =
                        self.read_u32(returned_data).unwrap_or(0x40).max(4) as usize;
                    self.core
                        .modules
                        .memory_mut()
                        .write(returned_data, &vec![0u8; declared_size])?;
                    self.write_u32(returned_data, declared_size as u32)?;
                }
                self.set_last_error(ERROR_SUCCESS as u32);
                Ok(1)
            })()),
            "RaiseException" => Some(Ok(0)),
            "ReadFile" => Some((|| -> Result<u64, VmError> {
                let handle = ctx.raw(0) as u32;
                let buffer = ctx.raw(1);
                let size = ctx.raw(2) as usize;
                if handle as u64 == STD_INPUT_HANDLE {
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), 0)?;
                    }
                    if buffer != 0 && size == 0 {
                        self.core.modules.memory_mut().write(buffer, &[])?;
                    }
                    Ok(1)
                } else if let Some(path) = self
                    .handles
                    .file_handles
                    .get(&handle)
                    .map(|state| state.path.clone())
                {
                    if !self
                        .ensure_runtime_read_allowed_path(std::path::Path::new(&path), "ReadFile")?
                    {
                        if ctx.raw(3) != 0 {
                            self.write_u32(ctx.raw(3), 0)?;
                        }
                        return Ok(0);
                    }
                    let state = self
                        .handles
                        .file_handles
                        .get_mut(&handle)
                        .ok_or(VmError::RuntimeInvariant("file handle disappeared"))?;
                    let mut data = vec![0u8; size];
                    let read = state.file.read(&mut data).unwrap_or(0);
                    data.truncate(read);
                    if buffer != 0 && !data.is_empty() {
                        self.core.modules.memory_mut().write(buffer, &data)?;
                    }
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), read as u32)?;
                    }
                    self.log_file_event("FILE_READ", handle, &path, Some(read as u64))?;
                    Ok(1)
                } else {
                    self.set_last_error(ERROR_INVALID_HANDLE as u32);
                    Ok(0)
                }
            })()),
            "ReadConsoleW" => Some((|| -> Result<u64, VmError> {
                if ctx.raw(3) != 0 {
                    self.write_u32(ctx.raw(3), 0)?;
                }
                if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                    self.core
                        .modules
                        .memory_mut()
                        .write(ctx.raw(1), &vec![0u8; ctx.raw(2) as usize * 2])?;
                }
                Ok(1)
            })()),
            "ReleaseMutex" => Some(Ok(self.release_mutex_handle(ctx.raw(0) as u32) as u64)),
            "ReleaseSemaphore" => Some((|| -> Result<u64, VmError> {
                Ok(self.release_semaphore_handle(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                )? as u64)
            })()),
            "ConnectNamedPipe" | "DisconnectNamedPipe" | "SetNamedPipeHandleState" => {
                Some((|| -> Result<u64, VmError> {
                    if self
                        .handles
                        .device_handles
                        .contains_key(&(ctx.raw(0) as u32))
                    {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                })())
            }
            "ResetEvent" => Some(Ok(
                self.core.scheduler.reset_event(ctx.raw(0) as u32).is_some() as u64,
            )),
            "RemoveDirectoryW" => Some((|| -> Result<u64, VmError> {
                let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                let Some(target) = self.prepare_runtime_read_target(&path, "RemoveDirectoryW")?
                else {
                    return Ok(0);
                };
                let result = std::fs::remove_dir_all(&target).is_ok() as u64;
                if result != 0 {
                    self.log_file_event("FILE_RMDIR", 0, &target.to_string_lossy(), None)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                } else {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                }
                Ok(result)
            })()),
            "ReplaceFileW" => Some((|| -> Result<u64, VmError> {
                let replaced = self.read_wide_string_from_memory(ctx.raw(0))?;
                let replacement = self.read_wide_string_from_memory(ctx.raw(1))?;
                let backup = self.read_optional_wide_text(ctx.raw(2))?;
                let Some(replaced_path) =
                    self.prepare_runtime_read_target(&replaced, "ReplaceFileW")?
                else {
                    return Ok(0);
                };
                let Some(replacement_path) =
                    self.prepare_runtime_read_target(&replacement, "ReplaceFileW")?
                else {
                    return Ok(0);
                };
                if !backup.is_empty() {
                    self.ensure_runtime_path_backing(&backup)?;
                    let backup_path = self.resolve_runtime_path(&backup);
                    let _ = std::fs::copy(&replaced_path, &backup_path);
                }
                let result = std::fs::copy(&replacement_path, &replaced_path)
                    .and_then(|_| std::fs::remove_file(&replacement_path))
                    .is_ok() as u64;
                if result != 0 {
                    self.set_last_error(ERROR_SUCCESS as u32);
                } else {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                }
                Ok(result)
            })()),
            "ResumeThread" => Some((|| -> Result<u64, VmError> {
                let handle = ctx.raw(0) as u32;
                let Some(tid) = self.core.scheduler.thread_tid_for_handle(handle) else {
                    return Ok(u32::MAX as u64);
                };
                let Some(previous_suspend_count) = self.core.scheduler.resume_thread(handle) else {
                    return Ok(u32::MAX as u64);
                };
                if previous_suspend_count != 0 && self.objects.pending_thread_attach.remove(&tid) {
                    self.dispatch_thread_notification(tid, DLL_THREAD_ATTACH)?;
                    self.objects.started_threads.insert(tid);
                }
                if let Some(thread) = self.core.scheduler.thread_snapshot(tid) {
                    self.log_thread_event(
                        "THREAD_RESUME",
                        tid,
                        handle,
                        thread.start_address,
                        thread.parameter,
                        "ready",
                    )?;
                    if previous_suspend_count != 0 {
                        self.log_thread_entry_dump_if_dynamic(
                            "THREAD_RESUME_DUMP",
                            "THREAD_RESUME",
                            tid,
                            handle,
                            thread.start_address,
                            thread.parameter,
                            "ready",
                        )?;
                    }
                }
                Ok(previous_suspend_count as u64)
            })()),
            "SetHandleCount" => Some(Ok(ctx.raw(0))),
            "SetLastError" => Some((|| -> Result<u64, VmError> {
                self.set_last_error(ctx.raw(0) as u32);
                Ok(0)
            })()),
            "SetPriorityClass" => Some((|| -> Result<u64, VmError> {
                if self.process_identity_for_handle(ctx.raw(0)).is_none()
                    && !self.is_current_process_handle(ctx.raw(0))
                {
                    self.set_last_error(ERROR_INVALID_HANDLE as u32);
                    Ok(0)
                } else {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
            })()),
            _ => None,
        }
    }
}
