use super::*;
use crate::hooks::signature::ReturnSpec;
use crate::runtime::api_logger::{ApiExecutionContext, ApiStackWord};
use serde_json::Value;

impl VirtualExecutionEngine {
    const PAYLOAD_PREVIEW_BYTES: usize = 10;
    const API_SUPPRESSION_REPORT_INTERVAL: u64 = 256;
    pub fn exception_code_name(code: u32) -> Option<&'static str> {
        match code {
            0x8000_0003 => Some("STATUS_BREAKPOINT"),
            0xC000_0005 => Some("STATUS_ACCESS_VIOLATION"),
            0xC000_001D => Some("STATUS_ILLEGAL_INSTRUCTION"),
            0xC000_0094 => Some("STATUS_INTEGER_DIVIDE_BY_ZERO"),
            0xC000_0096 => Some("STATUS_PRIVILEGED_INSTRUCTION"),
            0xC000_00FD => Some("STATUS_STACK_OVERFLOW"),
            0xE06D_7363 => Some("MSVC_CXX_EXCEPTION"),
            _ => None,
        }
    }

    pub fn format_exception_code_for_log(code: u32) -> String {
        match Self::exception_code_name(code) {
            Some(name) => format!("0x{code:08X}<{name}>"),
            None => format!("0x{code:08X}"),
        }
    }

    pub fn format_seh_filter_result_for_log(retval: u64) -> String {
        match retval as u32 as i32 {
            EXCEPTION_CONTINUE_EXECUTION_FILTER => "EXCEPTION_CONTINUE_EXECUTION(-1)".to_string(),
            EXCEPTION_CONTINUE_SEARCH_FILTER => "EXCEPTION_CONTINUE_SEARCH(0)".to_string(),
            EXCEPTION_EXECUTE_HANDLER_FILTER => "EXCEPTION_EXECUTE_HANDLER(1)".to_string(),
            other => format!("{other}"),
        }
    }

    pub fn format_runtime_bytes(bytes: &[u8]) -> String {
        let mut rendered = String::new();
        for (index, byte) in bytes.iter().enumerate() {
            if index != 0 {
                rendered.push(' ');
            }
            use std::fmt::Write as _;
            let _ = write!(&mut rendered, "{byte:02X}");
        }
        rendered
    }

    pub fn format_payload_preview(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }
        let preview_len = bytes.len().min(Self::PAYLOAD_PREVIEW_BYTES);
        let mut rendered = Self::format_runtime_bytes(&bytes[..preview_len]);
        if bytes.len() > Self::PAYLOAD_PREVIEW_BYTES {
            rendered.push_str(" ...");
        }
        Some(rendered)
    }

    pub fn add_payload_preview_field(fields: &mut Map<String, Value>, bytes: &[u8]) {
        if let Some(preview_hex) = Self::format_payload_preview(bytes) {
            fields.insert("preview_hex".to_string(), json!(preview_hex));
        }
    }

    pub fn current_log_tid(&self) -> u32 {
        self.core
            .scheduler
            .current_tid()
            .or(self.core.main_thread_tid)
            .unwrap_or(0)
    }

    pub fn address_ref(&self, address: u64) -> AddressRef {
        if address == 0 {
            return AddressRef::unknown(0);
        }
        if let Some(module) = self.core.modules.get_by_address(address) {
            let in_visible_range = module.visible_base != module.base
                && address >= module.visible_base
                && address < module.visible_base.saturating_add(module.size);
            let (module_base, rva) = if in_visible_range {
                (
                    module.visible_base,
                    address.saturating_sub(module.visible_base),
                )
            } else {
                (module.base, address.saturating_sub(module.base))
            };
            return AddressRef {
                va: address,
                owner: format!("{}+0x{:X}", module.name, rva),
                module: Some(module.name.clone()),
                module_base: Some(module_base),
                rva: Some(rva),
                module_path: module
                    .path
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string()),
                region: None,
                region_base: None,
                region_offset: None,
            };
        }
        if let Some(region) = self.core.modules.memory().find_region(address, 1) {
            let offset = address.saturating_sub(region.base);
            return AddressRef {
                va: address,
                owner: format!("{}+0x{:X}", region.tag, offset),
                module: None,
                module_base: None,
                rva: None,
                module_path: None,
                region: Some(region.tag.clone()),
                region_base: Some(region.base),
                region_offset: Some(offset),
            };
        }
        AddressRef::unknown(address)
    }

    pub fn capture_api_execution_context(&self, fallback_pc: u64) -> Option<ApiExecutionContext> {
        if !self.core.config.api_log_include_context {
            return None;
        }
        if let Some(context) = self.dispatch.api_log_context_override.clone() {
            return Some(context);
        }
        if let Ok(Some(context)) = self
            .capture_active_api_execution_context(fallback_pc, self.core.config.api_log_stack_words)
        {
            return Some(context);
        }
        let thread = self.current_thread_snapshot()?;
        let pointer_size = if self.core.arch.is_x86() { 4u64 } else { 8u64 };
        let (mut ip, sp, bp, ax, bx, cx, dx, si, di, flags) = if self.core.arch.is_x86() {
            (
                thread.registers.eip,
                thread.registers.esp,
                thread.registers.ebp,
                thread.registers.eax,
                thread.registers.ebx,
                thread.registers.ecx,
                thread.registers.edx,
                thread.registers.esi,
                thread.registers.edi,
                thread.registers.eflags,
            )
        } else {
            (
                thread.registers.rip,
                thread.registers.rsp,
                thread.registers.rbp,
                thread.registers.rax,
                thread.registers.rbx,
                thread.registers.rcx,
                thread.registers.rdx,
                thread.registers.rsi,
                thread.registers.rdi,
                thread.registers.rflags,
            )
        };
        if ip == 0 {
            ip = fallback_pc;
        }
        let stack_words = (0..self.core.config.api_log_stack_words)
            .map(|index| {
                let address = sp.saturating_add((index as u64).saturating_mul(pointer_size));
                match self.read_pointer_value(address) {
                    Ok(value) => ApiStackWord {
                        address,
                        value: Some(value),
                        value_ref: (value != 0).then(|| self.address_ref(value)),
                        read_error: None,
                    },
                    Err(error) => ApiStackWord {
                        address,
                        value: None,
                        value_ref: None,
                        read_error: Some(error.to_string()),
                    },
                }
            })
            .collect::<Vec<_>>();
        Some(ApiExecutionContext {
            ip,
            sp,
            bp,
            ax,
            bx,
            cx,
            dx,
            si,
            di,
            flags,
            direction_flag: ((flags >> 10) & 1) != 0,
            stack_words,
        })
    }

    pub fn log_api_call(
        &mut self,
        signature: &HookSignature,
        pc: u64,
        return_to: Option<u64>,
        args: &[u64],
    ) -> Result<u64, VmError> {
        if !self.core.api_logger.trace_enabled() {
            return Ok(0);
        }
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("api_logger.call_total");
        let target_name = format!("{}!{}", signature.module, signature.function);
        *self
            .core
            .api_call_counts
            .entry(target_name.clone())
            .or_insert(0) += 1;

        // --- High-frequency API log suppression ---
        const SUPPRESS_THRESHOLD: u64 = 100;
        let same_as_last = self.dispatch.suppress_last_api_pc == Some(pc)
            && self.dispatch.suppress_last_api_target.as_deref() == Some(target_name.as_str());
        if same_as_last {
            self.dispatch.suppress_api_count += 1;
            if self.dispatch.suppress_api_count > SUPPRESS_THRESHOLD {
                if self.dispatch.suppress_api_count % Self::API_SUPPRESSION_REPORT_INTERVAL == 0 {
                    self.emit_api_suppression_summary(self.dispatch.suppress_api_count)?;
                }
                return Ok(0); // suppressed — skip logging + return
            }
        } else {
            // Sequence broken — flush summary if there were suppressed calls
            if self.dispatch.suppress_api_count > SUPPRESS_THRESHOLD {
                self.flush_api_suppression_summary()?;
            }
            self.dispatch.suppress_last_api_pc = Some(pc);
            self.dispatch.suppress_last_api_target = Some(target_name);
            self.dispatch.suppress_api_count = 1;
        }

        let target_base = self
            .core
            .modules
            .get_loaded(signature.module)
            .map(|module| module.visible_base)
            .unwrap_or(0);
        let tick_ms = self.dispatch.time.current().tick_ms;
        let rendered_args = self.describe_api_call_args(signature, args);
        let context = self.capture_api_execution_context(pc);
        let call_id = self.core.api_logger.log_api_call(
            self.current_process_id(),
            self.current_log_tid(),
            tick_ms,
            self.core.instruction_count,
            signature.module,
            signature.function,
            pc,
            return_to,
            target_base,
            &rendered_args,
            Some(self.address_ref(pc)),
            return_to.map(|address| self.address_ref(address)),
            context,
        )?;
        Ok(call_id)
    }

    pub fn log_api_return(
        &mut self,
        call_id: u64,
        signature: &HookSignature,
        pc: u64,
        args: &[u64],
        retval: u64,
    ) -> Result<(), VmError> {
        if call_id == 0 {
            return Ok(());
        }
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("api_logger.return_total");
        let target_base = self
            .core
            .modules
            .get_loaded(signature.module)
            .map(|module| module.visible_base)
            .unwrap_or(0);
        let tick_ms = self.dispatch.time.current().tick_ms;
        let decoded_text = self
            .describe_api_return_decoded_text(signature.module, signature.function, args, retval)
            .or_else(|| self.format_return_from_signature(Some(signature), retval));
        let context = if self.has_active_unicorn_context() {
            self.capture_active_api_execution_context(pc, self.core.config.api_log_stack_words)
                .ok()
                .flatten()
                .or_else(|| self.capture_api_execution_context(pc))
        } else {
            self.capture_api_execution_context(pc)
        };
        self.core.api_logger.log_api_return(
            self.current_process_id(),
            self.current_log_tid(),
            tick_ms,
            self.core.instruction_count,
            call_id,
            signature.module,
            signature.function,
            pc,
            target_base,
            retval,
            self.core.last_error,
            decoded_text,
            Some(self.address_ref(pc)),
            context,
        )?;
        Ok(())
    }

    pub fn format_return_from_signature(
        &self,
        signature: Option<&HookSignature>,
        retval: u64,
    ) -> Option<String> {
        let ret_spec = signature?.ret;
        let formatted = match ret_spec {
            ReturnSpec::Void => format!("void"),
            ReturnSpec::Bool32 => {
                if retval == 0 {
                    "BOOL=FALSE".to_string()
                } else {
                    "BOOL=TRUE".to_string()
                }
            }
            ReturnSpec::I32 => format!("i32={}", retval as u32 as i32),
            ReturnSpec::U32 => format!("u32={}", retval as u32),
            ReturnSpec::U16 => format!("u16={}", retval as u16),
            ReturnSpec::I64 => format!("i64={}", retval as i64),
            ReturnSpec::U64 => format!("u64={retval}"),
            ReturnSpec::NtStatus => {
                let code = retval as u32;
                match Self::exception_code_name(code) {
                    Some(name) => format!("NTSTATUS=0x{code:08X}<{name}>"),
                    None => format!("NTSTATUS=0x{code:08X}"),
                }
            }
            ReturnSpec::Win32Error => format!("ERROR=0x{:X}", retval as u32),
            ReturnSpec::Handle => self.describe_pointer(retval, false),
            ReturnSpec::ModuleHandle => self.describe_module_handle(retval),
            ReturnSpec::Pointer => self.describe_pointer(retval, false),
            ReturnSpec::PointerSizedUInt => format!("ptr_uint=0x{retval:X}"),
            ReturnSpec::PointerSizedInt => format!("ptr_int={}", retval as i64),
        };
        Some(formatted)
    }

    pub fn flush_api_suppression_summary(&mut self) -> Result<(), VmError> {
        let count = self.dispatch.suppress_api_count;
        let target = self.dispatch.suppress_last_api_target.take();
        let pc = self.dispatch.suppress_last_api_pc.take();
        self.dispatch.suppress_api_count = 0;
        if count == 0 || target.is_none() {
            return Ok(());
        }
        self.emit_api_suppression_summary_with_target(count, target.unwrap(), pc)
    }

    fn emit_api_suppression_summary(&mut self, count: u64) -> Result<(), VmError> {
        let Some(target) = self.dispatch.suppress_last_api_target.clone() else {
            return Ok(());
        };
        let pc = self.dispatch.suppress_last_api_pc;
        self.emit_api_suppression_summary_with_target(count, target, pc)
    }

    fn emit_api_suppression_summary_with_target(
        &mut self,
        count: u64,
        target: String,
        pc: Option<u64>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("target".to_string(), json!(target));
        if let Some(pc) = pc {
            fields.insert("pc".to_string(), json!(pc));
            fields.insert("pc_ref".to_string(), self.address_ref(pc).to_json_value());
        }
        fields.insert("suppressed_count".to_string(), json!(count));
        self.log_runtime_event("API_SUPPRESSED", fields)
    }

    pub fn describe_api_call_args(
        &self,
        signature: &HookSignature,
        args: &[u64],
    ) -> Vec<ApiLogArg> {
        if let Some(rendered) =
            self.describe_custom_api_call_args(signature.module, signature.function, args)
        {
            return rendered;
        }

        // Signature-driven path: use ParamSpec when available.
        if !signature.params.is_empty() {
            return args
                .iter()
                .enumerate()
                .filter_map(|(index, &value)| {
                    let Some(spec) = signature.params.get(index) else {
                        return Some(ApiLogArg {
                            index,
                            name: format!("arg{index}"),
                            kind: "raw".to_string(),
                            value,
                            text: format!("0x{value:X}"),
                        });
                    };
                    let name = if spec.name.is_empty() {
                        format!("arg{index}")
                    } else {
                        spec.name.to_string()
                    };
                    let text = self
                        .format_param_type_value(&spec.ty, spec.dir, value, args, spec.log)
                        .unwrap_or_else(|| "SKIPPED".to_string());
                    Some(ApiLogArg {
                        index,
                        name,
                        kind: Self::param_type_to_kind_str(&spec.ty).to_string(),
                        value,
                        text,
                    })
                })
                .collect();
        }

        // Fallback: raw value rendering for hooks that still only have stub metadata.
        args.iter()
            .enumerate()
            .map(|(index, value)| ApiLogArg {
                index,
                name: format!("arg{index}"),
                kind: "raw".to_string(),
                value: *value,
                text: format!("0x{value:X}"),
            })
            .collect()
    }

    pub fn render_api_arg(
        &self,
        index: usize,
        name: &'static str,
        kind: ApiArgKind,
        value: u64,
    ) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: kind.as_str().to_string(),
            value,
            text: self.format_api_value(kind, value),
        }
    }

    pub fn render_api_custom_arg(
        &self,
        index: usize,
        name: &'static str,
        kind: &'static str,
        value: u64,
        text: Option<String>,
    ) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: kind.to_string(),
            value,
            text: text.unwrap_or_else(|| self.describe_pointer(value, false)),
        }
    }

    pub fn render_api_buffer_arg(
        &self,
        index: usize,
        name: &'static str,
        address: u64,
        byte_len: u64,
    ) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: "buffer_hex".to_string(),
            value: address,
            text: self.describe_buffer_pointer(address, byte_len),
        }
    }

    pub fn render_api_size_arg(&self, index: usize, name: &'static str, value: u64) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: "size".to_string(),
            value,
            text: format!("0x{value:X}"),
        }
    }

    pub fn render_api_byte_arg(&self, index: usize, name: &'static str, value: u64) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: "byte".to_string(),
            value,
            text: format!("0x{:02X}", value & 0xFF),
        }
    }
}
