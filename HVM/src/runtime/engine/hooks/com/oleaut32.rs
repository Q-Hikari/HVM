use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_oleaut32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("oleaut32.dll", "SysAllocString") | ("oleaut32.dll", "ordinal_2") => true,
            ("oleaut32.dll", "SysAllocStringLen") | ("oleaut32.dll", "ordinal_4") => true,
            ("oleaut32.dll", "SysFreeString") | ("oleaut32.dll", "ordinal_6") => true,
            ("oleaut32.dll", "SysStringLen") | ("oleaut32.dll", "ordinal_7") => true,
            ("oleaut32.dll", "SysStringByteLen") | ("oleaut32.dll", "ordinal_8") => true,
            ("oleaut32.dll", "VariantInit") | ("oleaut32.dll", "ordinal_9") => true,
            ("oleaut32.dll", "VariantClear") | ("oleaut32.dll", "ordinal_10") => true,
            ("oleaut32.dll", "VariantCopy") | ("oleaut32.dll", "ordinal_11") => true,
            ("oleaut32.dll", "VariantChangeType") | ("oleaut32.dll", "ordinal_12") => true,
            ("oleaut32.dll", "SafeArrayCreate") | ("oleaut32.dll", "ordinal_15") => true,
            ("oleaut32.dll", "SafeArrayCreateVector") => true,
            ("oleaut32.dll", "SafeArrayGetDim") | ("oleaut32.dll", "ordinal_17") => true,
            ("oleaut32.dll", "SafeArrayGetElemsize") | ("oleaut32.dll", "ordinal_18") => true,
            ("oleaut32.dll", "SafeArrayAccessData") | ("oleaut32.dll", "ordinal_23") => true,
            ("oleaut32.dll", "SafeArrayUnaccessData") | ("oleaut32.dll", "ordinal_24") => true,
            ("oleaut32.dll", "SafeArrayLock") | ("oleaut32.dll", "ordinal_21") => true,
            ("oleaut32.dll", "SafeArrayUnlock") | ("oleaut32.dll", "ordinal_22") => true,
            ("oleaut32.dll", "SafeArrayGetUBound") | ("oleaut32.dll", "ordinal_19") => true,
            ("oleaut32.dll", "SafeArrayGetLBound") | ("oleaut32.dll", "ordinal_20") => true,
            ("oleaut32.dll", "SafeArrayPutElement") | ("oleaut32.dll", "ordinal_26") => true,
            ("oleaut32.dll", "SafeArrayGetElement") | ("oleaut32.dll", "ordinal_25") => true,
            ("oleaut32.dll", "SafeArrayPtrOfIndex") | ("oleaut32.dll", "ordinal_148") => true,
            ("oleaut32.dll", "SafeArrayDestroy") | ("oleaut32.dll", "ordinal_16") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("oleaut32.dll", "SysAllocString") | ("oleaut32.dll", "ordinal_2") => {
                    self.alloc_bstr_from_wide_ptr(ctx.raw(0), None, "SysAllocString")
                }
                ("oleaut32.dll", "SysAllocStringLen") | ("oleaut32.dll", "ordinal_4") => self
                    .alloc_bstr_from_wide_ptr(
                        ctx.raw(0),
                        Some(ctx.raw(1) as usize),
                        "SysAllocStringLen",
                    ),
                ("oleaut32.dll", "SysFreeString") | ("oleaut32.dll", "ordinal_6") => {
                    let _ = self.free_bstr(ctx.raw(0));
                    Ok(0)
                }
                ("oleaut32.dll", "SysStringLen") | ("oleaut32.dll", "ordinal_7") => {
                    Ok((self.read_bstr_byte_len(ctx.raw(0))? / 2) as u64)
                }
                ("oleaut32.dll", "SysStringByteLen") | ("oleaut32.dll", "ordinal_8") => {
                    Ok(self.read_bstr_byte_len(ctx.raw(0))? as u64)
                }
                ("oleaut32.dll", "VariantInit") | ("oleaut32.dll", "ordinal_9") => {
                    if ctx.raw(0) != 0 {
                        let size = if self.core.arch.is_x86() {
                            VARIANT_SIZE_X86
                        } else {
                            VARIANT_SIZE_X64
                        };
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(0), &vec![0u8; size])?;
                    }
                    Ok(0)
                }
                ("oleaut32.dll", "VariantClear") | ("oleaut32.dll", "ordinal_10") => {
                    if ctx.raw(0) != 0 {
                        let size = if self.core.arch.is_x86() {
                            VARIANT_SIZE_X86
                        } else {
                            VARIANT_SIZE_X64
                        };
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(0), &vec![0u8; size])?;
                    }
                    Ok(0)
                }
                ("oleaut32.dll", "VariantCopy") | ("oleaut32.dll", "ordinal_11") => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let size = if self.core.arch.is_x86() {
                        VARIANT_SIZE_X86
                    } else {
                        VARIANT_SIZE_X64
                    };
                    let bytes = self.read_bytes_from_memory(ctx.raw(1), size)?;
                    self.core.modules.memory_mut().write(ctx.raw(0), &bytes)?;
                    Ok(0)
                }
                ("oleaut32.dll", "VariantChangeType") | ("oleaut32.dll", "ordinal_12") => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let size = if self.core.arch.is_x86() {
                        VARIANT_SIZE_X86
                    } else {
                        VARIANT_SIZE_X64
                    };
                    let bytes = self.read_bytes_from_memory(ctx.raw(1), size)?;
                    self.core.modules.memory_mut().write(ctx.raw(0), &bytes)?;
                    self.write_u16(ctx.raw(0), ctx.raw(3) as u16)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayCreate") | ("oleaut32.dll", "ordinal_15") => {
                    if ctx.raw(1) == 0 || ctx.raw(2) == 0 {
                        return Ok(0);
                    }
                    let count = self.read_u32(ctx.raw(2))?;
                    let lower_bound = self.read_u32(ctx.raw(2) + 4)? as i32;
                    self.create_safe_array(ctx.raw(0) as u16, count, lower_bound, "SafeArrayCreate")
                }
                ("oleaut32.dll", "SafeArrayCreateVector") => self.create_safe_array(
                    ctx.raw(0) as u16,
                    ctx.raw(2) as u32,
                    ctx.raw(1) as i32,
                    "SafeArrayCreateVector",
                ),
                ("oleaut32.dll", "SafeArrayGetDim") | ("oleaut32.dll", "ordinal_17") => {
                    let (_, _, _, _, dims) = self.read_safe_array_info(ctx.raw(0))?;
                    Ok(dims as u64)
                }
                ("oleaut32.dll", "SafeArrayGetElemsize") | ("oleaut32.dll", "ordinal_18") => {
                    let (_, cb_elements, _, _, _) = self.read_safe_array_info(ctx.raw(0))?;
                    Ok(cb_elements as u64)
                }
                ("oleaut32.dll", "SafeArrayAccessData") | ("oleaut32.dll", "ordinal_23") => {
                    let (data, _, _, _, _) = self.read_safe_array_info(ctx.raw(0))?;
                    if ctx.raw(1) == 0 || data == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    self.write_pointer_value(ctx.raw(1), data)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayUnaccessData") | ("oleaut32.dll", "ordinal_24") => Ok(0),
                ("oleaut32.dll", "SafeArrayLock") | ("oleaut32.dll", "ordinal_21") => {
                    if ctx.raw(0) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let locks = self.read_u32(ctx.raw(0) + 8)?.saturating_add(1);
                    self.write_u32(ctx.raw(0) + 8, locks)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayUnlock") | ("oleaut32.dll", "ordinal_22") => {
                    if ctx.raw(0) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let locks = self.read_u32(ctx.raw(0) + 8)?.saturating_sub(1);
                    self.write_u32(ctx.raw(0) + 8, locks)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayGetUBound") | ("oleaut32.dll", "ordinal_19") => {
                    let (_, _, lower_bound, count, dims) = self.read_safe_array_info(ctx.raw(0))?;
                    if ctx.raw(2) == 0 || dims == 0 || count == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    self.write_u32(
                        ctx.raw(2),
                        lower_bound.saturating_add(count as i32).saturating_sub(1) as u32,
                    )?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayGetLBound") | ("oleaut32.dll", "ordinal_20") => {
                    let (_, _, lower_bound, _, dims) = self.read_safe_array_info(ctx.raw(0))?;
                    if ctx.raw(2) == 0 || dims == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    self.write_u32(ctx.raw(2), lower_bound as u32)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayPutElement") | ("oleaut32.dll", "ordinal_26") => {
                    let (data, cb_elements, lower_bound, count, dims) =
                        self.read_safe_array_info(ctx.raw(0))?;
                    if data == 0 || ctx.raw(1) == 0 || ctx.raw(2) == 0 || dims == 0 || count == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let index = self.read_u32(ctx.raw(1))? as i32;
                    if index < lower_bound || index >= lower_bound.saturating_add(count as i32) {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let offset = (index - lower_bound) as u64 * cb_elements as u64;
                    let bytes = self.read_bytes_from_memory(ctx.raw(2), cb_elements as usize)?;
                    self.core
                        .modules
                        .memory_mut()
                        .write(data + offset, &bytes)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayGetElement") | ("oleaut32.dll", "ordinal_25") => {
                    let (data, cb_elements, lower_bound, count, dims) =
                        self.read_safe_array_info(ctx.raw(0))?;
                    if data == 0 || ctx.raw(1) == 0 || ctx.raw(2) == 0 || dims == 0 || count == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let index = self.read_u32(ctx.raw(1))? as i32;
                    if index < lower_bound || index >= lower_bound.saturating_add(count as i32) {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let offset = (index - lower_bound) as u64 * cb_elements as u64;
                    let bytes = self.read_bytes_from_memory(data + offset, cb_elements as usize)?;
                    self.core.modules.memory_mut().write(ctx.raw(2), &bytes)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayPtrOfIndex") | ("oleaut32.dll", "ordinal_148") => {
                    let (data, cb_elements, lower_bound, count, dims) =
                        self.read_safe_array_info(ctx.raw(0))?;
                    if data == 0 || ctx.raw(1) == 0 || ctx.raw(2) == 0 || dims == 0 || count == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let index = self.read_u32(ctx.raw(1))? as i32;
                    if index < lower_bound || index >= lower_bound.saturating_add(count as i32) {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let offset = (index - lower_bound) as u64 * cb_elements as u64;
                    self.write_pointer_value(ctx.raw(2), data + offset)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayDestroy") | ("oleaut32.dll", "ordinal_16") => {
                    let (data, _, _, _, _) = self.read_safe_array_info(ctx.raw(0))?;
                    if data != 0 {
                        let _ = self
                            .process_memory
                            .heaps
                            .free(self.process_memory.heaps.process_heap(), data);
                    }
                    if ctx.raw(0) != 0 {
                        let _ = self
                            .process_memory
                            .heaps
                            .free(self.process_memory.heaps.process_heap(), ctx.raw(0));
                    }
                    Ok(0)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
