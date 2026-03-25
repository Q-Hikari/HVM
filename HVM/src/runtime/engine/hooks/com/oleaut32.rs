use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_oleaut32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("oleaut32.dll", "SysAllocString") | ("oleaut32.dll", "ordinal_2") => true,
            ("oleaut32.dll", "SysAllocStringLen") | ("oleaut32.dll", "ordinal_4") => true,
            ("oleaut32.dll", "SysFreeString") | ("oleaut32.dll", "ordinal_6") => true,
            ("oleaut32.dll", "SysStringLen") | ("oleaut32.dll", "ordinal_7") => true,
            ("oleaut32.dll", "VariantInit") | ("oleaut32.dll", "ordinal_8") => true,
            ("oleaut32.dll", "VariantClear") | ("oleaut32.dll", "ordinal_9") => true,
            ("oleaut32.dll", "VariantCopy") | ("oleaut32.dll", "ordinal_10") => true,
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
                    self.alloc_bstr_from_wide_ptr(arg(args, 0), None, "SysAllocString")
                }
                ("oleaut32.dll", "SysAllocStringLen") | ("oleaut32.dll", "ordinal_4") => self
                    .alloc_bstr_from_wide_ptr(
                        arg(args, 0),
                        Some(arg(args, 1) as usize),
                        "SysAllocStringLen",
                    ),
                ("oleaut32.dll", "SysFreeString") | ("oleaut32.dll", "ordinal_6") => {
                    let _ = self.free_bstr(arg(args, 0));
                    Ok(0)
                }
                ("oleaut32.dll", "SysStringLen") | ("oleaut32.dll", "ordinal_7") => {
                    Ok((self.read_bstr_byte_len(arg(args, 0))? / 2) as u64)
                }
                ("oleaut32.dll", "VariantInit") | ("oleaut32.dll", "ordinal_8") => {
                    if arg(args, 0) != 0 {
                        let size = if self.arch.is_x86() {
                            VARIANT_SIZE_X86
                        } else {
                            VARIANT_SIZE_X64
                        };
                        self.modules
                            .memory_mut()
                            .write(arg(args, 0), &vec![0u8; size])?;
                    }
                    Ok(0)
                }
                ("oleaut32.dll", "VariantClear") | ("oleaut32.dll", "ordinal_9") => {
                    if arg(args, 0) != 0 {
                        let size = if self.arch.is_x86() {
                            VARIANT_SIZE_X86
                        } else {
                            VARIANT_SIZE_X64
                        };
                        self.modules
                            .memory_mut()
                            .write(arg(args, 0), &vec![0u8; size])?;
                    }
                    Ok(0)
                }
                ("oleaut32.dll", "VariantCopy") | ("oleaut32.dll", "ordinal_10") => {
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let size = if self.arch.is_x86() {
                        VARIANT_SIZE_X86
                    } else {
                        VARIANT_SIZE_X64
                    };
                    let bytes = self.read_bytes_from_memory(arg(args, 1), size)?;
                    self.modules.memory_mut().write(arg(args, 0), &bytes)?;
                    Ok(0)
                }
                ("oleaut32.dll", "VariantChangeType") | ("oleaut32.dll", "ordinal_12") => {
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let size = if self.arch.is_x86() {
                        VARIANT_SIZE_X86
                    } else {
                        VARIANT_SIZE_X64
                    };
                    let bytes = self.read_bytes_from_memory(arg(args, 1), size)?;
                    self.modules.memory_mut().write(arg(args, 0), &bytes)?;
                    self.write_u16(arg(args, 0), arg(args, 3) as u16)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayCreate") | ("oleaut32.dll", "ordinal_15") => {
                    if arg(args, 1) == 0 || arg(args, 2) == 0 {
                        return Ok(0);
                    }
                    let count = self.read_u32(arg(args, 2))?;
                    let lower_bound = self.read_u32(arg(args, 2) + 4)? as i32;
                    self.create_safe_array(
                        arg(args, 0) as u16,
                        count,
                        lower_bound,
                        "SafeArrayCreate",
                    )
                }
                ("oleaut32.dll", "SafeArrayCreateVector") => self.create_safe_array(
                    arg(args, 0) as u16,
                    arg(args, 2) as u32,
                    arg(args, 1) as i32,
                    "SafeArrayCreateVector",
                ),
                ("oleaut32.dll", "SafeArrayGetDim") | ("oleaut32.dll", "ordinal_17") => {
                    let (_, _, _, _, dims) = self.read_safe_array_info(arg(args, 0))?;
                    Ok(dims as u64)
                }
                ("oleaut32.dll", "SafeArrayGetElemsize") | ("oleaut32.dll", "ordinal_18") => {
                    let (_, cb_elements, _, _, _) = self.read_safe_array_info(arg(args, 0))?;
                    Ok(cb_elements as u64)
                }
                ("oleaut32.dll", "SafeArrayAccessData") | ("oleaut32.dll", "ordinal_23") => {
                    let (data, _, _, _, _) = self.read_safe_array_info(arg(args, 0))?;
                    if arg(args, 1) == 0 || data == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    self.write_pointer_value(arg(args, 1), data)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayUnaccessData") | ("oleaut32.dll", "ordinal_24") => Ok(0),
                ("oleaut32.dll", "SafeArrayLock") | ("oleaut32.dll", "ordinal_21") => {
                    if arg(args, 0) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let locks = self.read_u32(arg(args, 0) + 8)?.saturating_add(1);
                    self.write_u32(arg(args, 0) + 8, locks)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayUnlock") | ("oleaut32.dll", "ordinal_22") => {
                    if arg(args, 0) == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let locks = self.read_u32(arg(args, 0) + 8)?.saturating_sub(1);
                    self.write_u32(arg(args, 0) + 8, locks)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayGetUBound") | ("oleaut32.dll", "ordinal_19") => {
                    let (_, _, lower_bound, count, dims) =
                        self.read_safe_array_info(arg(args, 0))?;
                    if arg(args, 2) == 0 || dims == 0 || count == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    self.write_u32(
                        arg(args, 2),
                        lower_bound.saturating_add(count as i32).saturating_sub(1) as u32,
                    )?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayGetLBound") | ("oleaut32.dll", "ordinal_20") => {
                    let (_, _, lower_bound, _, dims) = self.read_safe_array_info(arg(args, 0))?;
                    if arg(args, 2) == 0 || dims == 0 {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    self.write_u32(arg(args, 2), lower_bound as u32)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayPutElement") | ("oleaut32.dll", "ordinal_26") => {
                    let (data, cb_elements, lower_bound, count, dims) =
                        self.read_safe_array_info(arg(args, 0))?;
                    if data == 0
                        || arg(args, 1) == 0
                        || arg(args, 2) == 0
                        || dims == 0
                        || count == 0
                    {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let index = self.read_u32(arg(args, 1))? as i32;
                    if index < lower_bound || index >= lower_bound.saturating_add(count as i32) {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let offset = (index - lower_bound) as u64 * cb_elements as u64;
                    let bytes = self.read_bytes_from_memory(arg(args, 2), cb_elements as usize)?;
                    self.modules.memory_mut().write(data + offset, &bytes)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayGetElement") | ("oleaut32.dll", "ordinal_25") => {
                    let (data, cb_elements, lower_bound, count, dims) =
                        self.read_safe_array_info(arg(args, 0))?;
                    if data == 0
                        || arg(args, 1) == 0
                        || arg(args, 2) == 0
                        || dims == 0
                        || count == 0
                    {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let index = self.read_u32(arg(args, 1))? as i32;
                    if index < lower_bound || index >= lower_bound.saturating_add(count as i32) {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let offset = (index - lower_bound) as u64 * cb_elements as u64;
                    let bytes = self.read_bytes_from_memory(data + offset, cb_elements as usize)?;
                    self.modules.memory_mut().write(arg(args, 2), &bytes)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayPtrOfIndex") | ("oleaut32.dll", "ordinal_148") => {
                    let (data, cb_elements, lower_bound, count, dims) =
                        self.read_safe_array_info(arg(args, 0))?;
                    if data == 0
                        || arg(args, 1) == 0
                        || arg(args, 2) == 0
                        || dims == 0
                        || count == 0
                    {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let index = self.read_u32(arg(args, 1))? as i32;
                    if index < lower_bound || index >= lower_bound.saturating_add(count as i32) {
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let offset = (index - lower_bound) as u64 * cb_elements as u64;
                    self.write_pointer_value(arg(args, 2), data + offset)?;
                    Ok(0)
                }
                ("oleaut32.dll", "SafeArrayDestroy") | ("oleaut32.dll", "ordinal_16") => {
                    let (data, _, _, _, _) = self.read_safe_array_info(arg(args, 0))?;
                    if data != 0 {
                        let _ = self.heaps.free(self.heaps.process_heap(), data);
                    }
                    if arg(args, 0) != 0 {
                        let _ = self.heaps.free(self.heaps.process_heap(), arg(args, 0));
                    }
                    Ok(0)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
