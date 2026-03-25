use super::*;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApiArgKind {
    Auto,
    Int32,
    UInt32,
    Hex32,
    Bool,
    Ptr,
    LpStr,
    LpWStr,
    ProcName,
    Module,
    UnicodeStringPtr,
    AnsiStringPtr,
}

impl ApiArgKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Int32 => "int32",
            Self::UInt32 => "uint32",
            Self::Hex32 => "hex32",
            Self::Bool => "bool",
            Self::Ptr => "ptr",
            Self::LpStr => "lpstr",
            Self::LpWStr => "lpwstr",
            Self::ProcName => "proc_name",
            Self::Module => "module",
            Self::UnicodeStringPtr => "unicode_string_ptr",
            Self::AnsiStringPtr => "ansi_string_ptr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ApiParameterSpec {
    name: &'static str,
    kind: ApiArgKind,
}

pub(super) fn spec(name: &'static str, kind: ApiArgKind) -> ApiParameterSpec {
    ApiParameterSpec { name, kind }
}

impl VirtualExecutionEngine {
    const PAYLOAD_PREVIEW_BYTES: usize = 10;

    fn exception_code_name(code: u32) -> Option<&'static str> {
        match code {
            0xC000_0005 => Some("STATUS_ACCESS_VIOLATION"),
            0xC000_001D => Some("STATUS_ILLEGAL_INSTRUCTION"),
            0xC000_0094 => Some("STATUS_INTEGER_DIVIDE_BY_ZERO"),
            0xC000_0096 => Some("STATUS_PRIVILEGED_INSTRUCTION"),
            0xC000_00FD => Some("STATUS_STACK_OVERFLOW"),
            0xE06D_7363 => Some("MSVC_CXX_EXCEPTION"),
            _ => None,
        }
    }

    pub(super) fn format_exception_code_for_log(code: u32) -> String {
        match Self::exception_code_name(code) {
            Some(name) => format!("0x{code:08X}<{name}>"),
            None => format!("0x{code:08X}"),
        }
    }

    pub(super) fn format_seh_filter_result_for_log(retval: u64) -> String {
        match retval as u32 as i32 {
            EXCEPTION_CONTINUE_EXECUTION_FILTER => "EXCEPTION_CONTINUE_EXECUTION(-1)".to_string(),
            EXCEPTION_CONTINUE_SEARCH_FILTER => "EXCEPTION_CONTINUE_SEARCH(0)".to_string(),
            EXCEPTION_EXECUTE_HANDLER_FILTER => "EXCEPTION_EXECUTE_HANDLER(1)".to_string(),
            other => format!("{other}"),
        }
    }

    pub(super) fn format_runtime_bytes(bytes: &[u8]) -> String {
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

    pub(super) fn format_payload_preview(bytes: &[u8]) -> Option<String> {
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

    pub(super) fn add_payload_preview_field(fields: &mut Map<String, Value>, bytes: &[u8]) {
        if let Some(preview_hex) = Self::format_payload_preview(bytes) {
            fields.insert("preview_hex".to_string(), json!(preview_hex));
        }
    }

    pub(super) fn current_log_tid(&self) -> u32 {
        self.scheduler
            .current_tid()
            .or(self.main_thread_tid)
            .unwrap_or(0)
    }

    pub(super) fn address_ref(&self, address: u64) -> AddressRef {
        if address == 0 {
            return AddressRef::unknown(0);
        }
        if let Some(module) = self.modules.get_by_address(address) {
            let rva = address.saturating_sub(module.base);
            return AddressRef {
                va: address,
                owner: format!("{}+0x{:X}", module.name, rva),
                module: Some(module.name.clone()),
                module_base: Some(module.base),
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
        if let Some(region) = self.modules.memory().find_region(address, 1) {
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

    pub(super) fn log_api_call(
        &mut self,
        definition: &HookDefinition,
        pc: u64,
        return_to: Option<u64>,
        args: &[u64],
    ) -> Result<u64, VmError> {
        if !self.api_logger.trace_enabled() {
            return Ok(0);
        }
        let _profile = self.runtime_profiler.start_scope("api_logger.call_total");
        let target_name = format!("{}!{}", definition.module, definition.function);
        *self.api_call_counts.entry(target_name).or_insert(0) += 1;
        let target_base = self
            .modules
            .get_loaded(definition.module)
            .map(|module| module.base)
            .unwrap_or(0);
        let tick_ms = self.time.current().tick_ms;
        let rendered_args = self.describe_api_call_args(definition, args);
        self.api_logger.log_api_call(
            self.current_process_id(),
            self.current_log_tid(),
            tick_ms,
            self.instruction_count,
            definition,
            pc,
            return_to,
            target_base,
            &rendered_args,
            Some(self.address_ref(pc)),
            return_to.map(|address| self.address_ref(address)),
        )
    }

    pub(super) fn log_api_return(
        &mut self,
        call_id: u64,
        definition: &HookDefinition,
        pc: u64,
        args: &[u64],
        retval: u64,
    ) -> Result<(), VmError> {
        if call_id == 0 {
            return Ok(());
        }
        let _profile = self.runtime_profiler.start_scope("api_logger.return_total");
        let target_base = self
            .modules
            .get_loaded(definition.module)
            .map(|module| module.base)
            .unwrap_or(0);
        let tick_ms = self.time.current().tick_ms;
        self.api_logger.log_api_return(
            self.current_process_id(),
            self.current_log_tid(),
            tick_ms,
            self.instruction_count,
            call_id,
            definition,
            pc,
            target_base,
            retval,
            self.last_error,
            self.describe_api_return_decoded_text(definition, args, retval),
            Some(self.address_ref(pc)),
        )
    }

    fn describe_api_call_args(&self, definition: &HookDefinition, args: &[u64]) -> Vec<ApiLogArg> {
        if let Some(rendered) = self.describe_custom_api_call_args(definition, args) {
            return rendered;
        }

        let specs = Self::api_parameter_specs(definition.module, definition.function);
        args.iter()
            .enumerate()
            .map(|(index, value)| {
                let spec = specs.get(index).copied().unwrap_or(ApiParameterSpec {
                    name: "",
                    kind: ApiArgKind::Auto,
                });
                let name = if spec.name.is_empty() {
                    format!("arg{index}")
                } else {
                    spec.name.to_string()
                };
                ApiLogArg {
                    index,
                    name,
                    kind: spec.kind.as_str().to_string(),
                    value: *value,
                    text: self.format_api_value(spec.kind, *value),
                }
            })
            .collect()
    }

    pub(super) fn render_api_arg(
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

    pub(super) fn render_api_custom_arg(
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

    pub(super) fn render_api_buffer_arg(
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

    pub(super) fn render_api_size_arg(
        &self,
        index: usize,
        name: &'static str,
        value: u64,
    ) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: "size".to_string(),
            value,
            text: format!("0x{value:X}"),
        }
    }

    pub(super) fn render_api_byte_arg(
        &self,
        index: usize,
        name: &'static str,
        value: u64,
    ) -> ApiLogArg {
        ApiLogArg {
            index,
            name: name.to_string(),
            kind: "byte".to_string(),
            value,
            text: format!("0x{:02X}", value & 0xFF),
        }
    }
}

impl VirtualExecutionEngine {
    pub(super) fn format_api_value(&self, kind: ApiArgKind, value: u64) -> String {
        match kind {
            ApiArgKind::Auto => self.format_auto_api_value(value),
            ApiArgKind::Int32 => format!("{}", value as u32 as i32),
            ApiArgKind::UInt32 => format!("{}", value as u32),
            ApiArgKind::Hex32 => format!("0x{:X}", value as u32),
            ApiArgKind::Bool => {
                if value == 0 {
                    "FALSE".to_string()
                } else {
                    "TRUE".to_string()
                }
            }
            ApiArgKind::Ptr => self.describe_pointer(value, false),
            ApiArgKind::LpStr => self.describe_string_pointer(value, false),
            ApiArgKind::LpWStr => self.describe_string_pointer(value, true),
            ApiArgKind::ProcName => {
                if value <= 0xFFFF {
                    format!("ordinal:{value}")
                } else {
                    self.describe_string_pointer(value, false)
                }
            }
            ApiArgKind::Module => self.describe_module_handle(value),
            ApiArgKind::UnicodeStringPtr => self.describe_unicode_string_struct(value),
            ApiArgKind::AnsiStringPtr => self.describe_ansi_string_struct(value),
        }
    }

    fn format_auto_api_value(&self, value: u64) -> String {
        if value == 0 {
            return "NULL".to_string();
        }
        if let Some(text) = self.try_auto_string(value) {
            return self.format_pointer_with_text(value, &text);
        }
        format!("0x{value:X}")
    }

    pub(super) fn describe_pointer(&self, value: u64, auto_string: bool) -> String {
        if value == 0 {
            return "NULL".to_string();
        }
        if auto_string {
            if let Some(text) = self.try_auto_string(value) {
                return self.format_pointer_with_text(value, &text);
            }
        }
        if let Some(owner) = self.pointer_owner(value) {
            return format!("0x{value:X}<{owner}>");
        }
        format!("0x{value:X}")
    }

    fn describe_string_pointer(&self, address: u64, wide: bool) -> String {
        if address == 0 {
            return "NULL".to_string();
        }
        let text = if wide {
            self.safe_read_wide_c_string_explicit(address)
        } else {
            self.safe_read_ansi_c_string_explicit(address)
        };
        match text {
            Some(text) => self.format_pointer_with_text(address, &text),
            None => self.describe_pointer(address, false),
        }
    }

    fn describe_module_handle(&self, value: u64) -> String {
        if value == 0 {
            return "NULL".to_string();
        }
        if let Some(module) = self.modules.get_by_base(value) {
            return format!("0x{value:X}<module:{}>", module.name);
        }
        self.describe_pointer(value, false)
    }

    fn describe_unicode_string_struct(&self, address: u64) -> String {
        if address == 0 {
            return "NULL".to_string();
        }
        match self.safe_read_unicode_string_struct(address) {
            Some(text) => self.format_pointer_with_text(address, &text),
            None => format!("0x{address:X}<UNICODE_STRING?>"),
        }
    }

    fn describe_ansi_string_struct(&self, address: u64) -> String {
        if address == 0 {
            return "NULL".to_string();
        }
        match self.safe_read_ansi_string_struct(address) {
            Some(text) => self.format_pointer_with_text(address, &text),
            None => format!("0x{address:X}<ANSI_STRING?>"),
        }
    }

    pub(super) fn describe_wide_input_pointer(&self, address: u64, count: u64) -> Option<String> {
        let text = self.safe_read_wide_input(address, count, false)?;
        Some(self.format_pointer_with_text(address, &text))
    }

    pub(super) fn describe_wide_counted_pointer(
        &self,
        address: u64,
        count: usize,
    ) -> Option<String> {
        if address == 0 {
            return Some("NULL".to_string());
        }
        let text = self
            .read_wide_counted_string_from_memory(address, count)
            .ok()
            .and_then(|value| self.sanitize_explicit_api_log_text(&value))?;
        Some(self.format_pointer_with_text(address, &text))
    }

    pub(super) fn describe_ansi_input_pointer(
        &self,
        address: u64,
        count: u64,
        code_page: u64,
    ) -> Option<String> {
        let text = self.safe_read_ansi_input(address, count, code_page, false)?;
        Some(self.format_pointer_with_text(address, &text))
    }

    pub(super) fn describe_exception_pointers_argument(&self, address: u64) -> Option<String> {
        if address == 0 {
            return Some("NULL".to_string());
        }
        let pointer_size = self.arch.pointer_size as u64;
        let exception_record = self.read_pointer_value(address).ok()?;
        let context_record = self.read_pointer_value(address + pointer_size).ok()?;
        let mut rendered = format!("0x{address:X}<EXCEPTION_POINTERS");
        if exception_record != 0 {
            rendered.push_str(&format!(
                ", exception={}",
                self.describe_pointer(exception_record, false)
            ));
            if let Ok(code) = self.read_u32(exception_record) {
                rendered.push_str(&format!(
                    ", code={}",
                    Self::format_exception_code_for_log(code)
                ));
            }
        }
        if context_record != 0 {
            rendered.push_str(&format!(
                ", context={}",
                self.describe_pointer(context_record, false)
            ));
        }
        rendered.push('>');
        Some(rendered)
    }

    pub(super) fn format_pointer_with_text(&self, address: u64, text: &str) -> String {
        if let Some(owner) = self.pointer_owner(address) {
            format!("0x{address:X}<{owner}>:{}", quote_api_log_text(text))
        } else {
            format!("0x{address:X}:{}", quote_api_log_text(text))
        }
    }

    pub(super) fn describe_buffer_pointer(&self, address: u64, byte_len: u64) -> String {
        if address == 0 {
            return "NULL".to_string();
        }

        let total_len = byte_len.min(usize::MAX as u64) as usize;
        let preview_len = total_len.min(self.api_log_binary_preview_limit());
        let preview = self.read_bytes_from_memory(address, preview_len).ok();

        match preview {
            Some(bytes) => {
                let truncated = total_len > bytes.len();
                self.format_pointer_with_binary_preview(address, &bytes, total_len, truncated)
            }
            None => {
                if let Some(owner) = self.pointer_owner(address) {
                    format!("0x{address:X}<{owner}>:buffer<unreadable,len=0x{total_len:X}>")
                } else {
                    format!("0x{address:X}:buffer<unreadable,len=0x{total_len:X}>")
                }
            }
        }
    }

    fn api_log_binary_preview_limit(&self) -> usize {
        self.config.api_log_string_limit.max(24).clamp(24, 96) / 3
    }

    fn format_pointer_with_binary_preview(
        &self,
        address: u64,
        preview: &[u8],
        total_len: usize,
        truncated: bool,
    ) -> String {
        let mut hex = Self::format_runtime_bytes(preview);
        if truncated {
            if !hex.is_empty() {
                hex.push(' ');
            }
            hex.push_str("...");
        }

        if let Some(owner) = self.pointer_owner(address) {
            format!("0x{address:X}<{owner}>:hex[{hex}] len=0x{total_len:X}")
        } else {
            format!("0x{address:X}:hex[{hex}] len=0x{total_len:X}")
        }
    }

    fn pointer_owner(&self, address: u64) -> Option<String> {
        let reference = self.address_ref(address);
        if reference.owner == "unknown" || reference.owner == "NULL" {
            None
        } else {
            Some(reference.owner)
        }
    }
}

fn quote_api_log_text(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| format!("\"{text}\""))
}

pub(super) fn trim_trailing_nul(bytes: &[u8], unit: usize) -> &[u8] {
    if unit == 0 {
        return bytes;
    }
    let mut end = bytes.len();
    while end >= unit && bytes[end - unit..end].iter().all(|byte| *byte == 0) {
        end -= unit;
    }
    &bytes[..end]
}

impl VirtualExecutionEngine {
    pub(super) fn safe_read_wide_input(
        &self,
        address: u64,
        count: u64,
        auto: bool,
    ) -> Option<String> {
        self.read_wide_input_string(address, count)
            .ok()
            .and_then(|value| self.sanitize_api_log_text(&value, auto))
    }

    pub(super) fn safe_read_ansi_input(
        &self,
        address: u64,
        count: u64,
        code_page: u64,
        auto: bool,
    ) -> Option<String> {
        let bytes = self.read_ansi_input(address, count).ok()?;
        let text = if code_page == 0 {
            Self::decode_ascii_bytes_ignoring_errors(trim_trailing_nul(&bytes, 1))
        } else {
            self.decode_code_page_bytes(code_page, trim_trailing_nul(&bytes, 1))
        };
        self.sanitize_api_log_text(&text, auto)
    }

    pub(super) fn safe_read_ansi_c_string_explicit(&self, address: u64) -> Option<String> {
        self.read_c_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_explicit_api_log_text(&value))
    }

    pub(super) fn safe_read_wide_c_string_explicit(&self, address: u64) -> Option<String> {
        self.read_wide_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_explicit_api_log_text(&value))
    }

    fn safe_read_ansi_c_string_auto(&self, address: u64) -> Option<String> {
        self.read_c_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_auto_api_log_text(&value))
    }

    fn safe_read_wide_c_string_auto(&self, address: u64) -> Option<String> {
        self.read_wide_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_auto_api_log_text(&value))
    }

    pub(super) fn safe_read_unicode_string_struct(&self, address: u64) -> Option<String> {
        let length_bytes = self.read_bytes_from_memory(address, 2).ok()?;
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
        let buffer_offset = if self.arch.is_x86() { 4 } else { 8 };
        let buffer_ptr = if self.arch.is_x86() {
            self.read_u32(address + buffer_offset).ok()? as u64
        } else {
            u64::from_le_bytes(
                self.read_bytes_from_memory(address + buffer_offset, 8)
                    .ok()?
                    .try_into()
                    .ok()?,
            )
        };
        if buffer_ptr == 0 {
            return None;
        }
        self.read_wide_counted_string_from_memory(
            buffer_ptr,
            (length / 2).min(self.config.api_log_string_limit.max(16)),
        )
        .ok()
        .and_then(|value| self.sanitize_explicit_api_log_text(&value))
    }

    pub(super) fn safe_read_ansi_string_struct(&self, address: u64) -> Option<String> {
        let length_bytes = self.read_bytes_from_memory(address, 2).ok()?;
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
        let buffer_offset = if self.arch.is_x86() { 4 } else { 8 };
        let buffer_ptr = if self.arch.is_x86() {
            self.read_u32(address + buffer_offset).ok()? as u64
        } else {
            u64::from_le_bytes(
                self.read_bytes_from_memory(address + buffer_offset, 8)
                    .ok()?
                    .try_into()
                    .ok()?,
            )
        };
        if buffer_ptr == 0 {
            return None;
        }
        let bytes = self
            .read_bytes_from_memory(
                buffer_ptr,
                length.min(self.config.api_log_string_limit.max(16)),
            )
            .ok()?;
        let text = Self::decode_ascii_bytes_ignoring_errors(&bytes);
        self.sanitize_explicit_api_log_text(&text)
    }

    pub(super) fn try_auto_string(&self, address: u64) -> Option<String> {
        if address == 0 || self.modules.memory().find_region(address, 1).is_none() {
            return None;
        }
        if self.looks_like_wide_string(address) {
            if let Some(text) = self.safe_read_wide_c_string_auto(address) {
                return Some(text);
            }
        }
        self.safe_read_ansi_c_string_auto(address)
            .or_else(|| self.safe_read_wide_c_string_auto(address))
    }

    fn looks_like_wide_string(&self, address: u64) -> bool {
        let Ok(bytes) = self.read_bytes_from_memory(address, 16) else {
            return false;
        };
        let mut inspected = 0usize;
        let mut odd_zeroes = 0usize;
        for pair in bytes.chunks_exact(2) {
            if pair == [0, 0] {
                break;
            }
            inspected += 1;
            if pair[1] == 0 {
                odd_zeroes += 1;
            }
        }
        inspected >= 2 && odd_zeroes * 2 >= inspected
    }

    fn sanitize_api_log_text(&self, value: &str, auto: bool) -> Option<String> {
        let text = self.truncate_api_log_text(value);
        let total = text.chars().count();
        if total == 0 {
            return None;
        }
        let printable = text
            .chars()
            .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
            .count();
        let threshold = if auto { 85 } else { 55 };
        (printable * 100 >= total * threshold).then_some(text)
    }

    fn sanitize_auto_api_log_text(&self, value: &str) -> Option<String> {
        self.sanitize_api_log_text(value, true)
    }

    pub(super) fn sanitize_explicit_api_log_text(&self, value: &str) -> Option<String> {
        self.sanitize_api_log_text(value, false)
    }

    fn truncate_api_log_text(&self, value: &str) -> String {
        let limit = self.config.api_log_string_limit.max(16);
        let mut chars = value.chars();
        let truncated = chars.by_ref().take(limit).collect::<String>();
        if chars.next().is_some() {
            format!("{truncated}...")
        } else {
            truncated
        }
    }
}

impl VirtualExecutionEngine {
    pub(super) fn log_process_exit(&mut self, reason: &str) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("PROCESS_EXIT") {
            return Ok(());
        }
        let thread_counts = self.thread_state_counts();
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(0u64));
        fields.insert("exit_code".to_string(), json!(self.exit_code));
        fields.insert("reason".to_string(), json!(reason));
        fields.insert("source".to_string(), json!("main"));
        if let Some(main_tid) = self.main_thread_tid {
            fields.insert("main_tid".to_string(), json!(main_tid));
            if let Some(state) = self.scheduler.thread_state(main_tid) {
                fields.insert("main_thread_state".to_string(), json!(state));
            }
        }
        fields.insert(
            "live_threads".to_string(),
            json!(thread_counts
                .iter()
                .filter(|(state, _)| state.as_str() != "terminated")
                .map(|(_, count)| *count)
                .sum::<u64>()),
        );
        fields.insert(
            "thread_states".to_string(),
            Self::thread_state_counts_value(&thread_counts),
        );
        self.api_logger.log_event(
            "PROCESS_EXIT",
            self.current_process_id(),
            self.current_log_tid(),
            self.time.current().tick_ms,
            self.instruction_count,
            fields,
        )
    }

    pub(super) fn log_run_stop(&mut self, reason: RunStopReason) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("RUN_STOP") {
            return Ok(());
        }
        let thread_counts = self.thread_state_counts();
        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!(reason.as_str()));
        fields.insert(
            "instruction_budget".to_string(),
            json!(self.config.max_instructions.max(1)),
        );
        fields.insert("exit_code".to_string(), json!(self.exit_code));
        if let Some(main_tid) = self.main_thread_tid {
            fields.insert("main_tid".to_string(), json!(main_tid));
            if let Some(state) = self.scheduler.thread_state(main_tid) {
                fields.insert("main_thread_state".to_string(), json!(state));
            }
        }
        fields.insert(
            "live_threads".to_string(),
            json!(thread_counts
                .iter()
                .filter(|(state, _)| state.as_str() != "terminated")
                .map(|(_, count)| *count)
                .sum::<u64>()),
        );
        fields.insert(
            "thread_states".to_string(),
            Self::thread_state_counts_value(&thread_counts),
        );
        self.log_runtime_event("RUN_STOP", fields)
    }

    pub(super) fn log_api_hotspot_summary(&mut self) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("API_HOTSPOT") || self.api_call_counts.is_empty() {
            return Ok(());
        }
        let total_calls = self
            .api_call_counts
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        let mut hottest = self
            .api_call_counts
            .iter()
            .map(|(target, count)| (target.clone(), *count))
            .collect::<Vec<_>>();
        hottest.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        let top_calls = hottest
            .into_iter()
            .take(10)
            .map(|(target, count)| json!({ "target": target, "count": count }))
            .collect::<Vec<_>>();
        let mut fields = Map::new();
        fields.insert("total_calls".to_string(), json!(total_calls));
        fields.insert(
            "unique_targets".to_string(),
            json!(self.api_call_counts.len() as u64),
        );
        fields.insert("top_calls".to_string(), json!(top_calls));
        self.log_runtime_event("API_HOTSPOT", fields)
    }

    pub(super) fn log_user32_hotspot_summary(&mut self) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("USER32_HOTSPOT") {
            return Ok(());
        }
        let state = &self.user32_state;
        let mut fields = Map::new();
        fields.insert(
            "get_message_calls".to_string(),
            json!(state.get_message_calls),
        );
        fields.insert(
            "peek_message_calls".to_string(),
            json!(state.peek_message_calls),
        );
        fields.insert(
            "translate_message_calls".to_string(),
            json!(state.translate_message_calls),
        );
        fields.insert(
            "dispatch_message_calls".to_string(),
            json!(state.dispatch_message_calls),
        );
        fields.insert("set_timer_calls".to_string(), json!(state.set_timer_calls));
        fields.insert(
            "kill_timer_calls".to_string(),
            json!(state.kill_timer_calls),
        );
        fields.insert(
            "synthetic_timer_messages".to_string(),
            json!(state.synthetic_timer_messages),
        );
        fields.insert(
            "synthetic_idle_messages".to_string(),
            json!(state.synthetic_idle_messages),
        );
        fields.insert(
            "hook_callback_dispatches".to_string(),
            json!(state.hook_callback_dispatches),
        );
        fields.insert(
            "active_timers".to_string(),
            json!(self.user32_active_timer_count()),
        );
        fields.insert(
            "active_hooks".to_string(),
            json!(self.user32_active_hook_count()),
        );
        self.log_runtime_event("USER32_HOTSPOT", fields)
    }

    pub(super) fn log_emu_stop(
        &mut self,
        phase: &str,
        pc: u64,
        error: &str,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("EMU_STOP") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("phase".to_string(), json!(phase));
        fields.insert("error".to_string(), json!(error));
        fields.insert("pc".to_string(), json!(pc));
        self.api_logger.log_event(
            "EMU_STOP",
            self.current_process_id(),
            self.current_log_tid(),
            self.time.current().tick_ms,
            self.instruction_count,
            fields,
        )
    }

    pub(super) fn log_runtime_event_immediate(
        &mut self,
        marker: &str,
        fields: Map<String, serde_json::Value>,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker(marker) {
            return Ok(());
        }
        self.api_logger.log_event(
            marker,
            self.current_process_id(),
            self.current_log_tid(),
            self.time.current().tick_ms,
            self.instruction_count,
            fields,
        )?;
        self.api_logger.flush()
    }

    pub(super) fn log_runtime_event(
        &mut self,
        marker: &str,
        fields: Map<String, serde_json::Value>,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker(marker) {
            return Ok(());
        }
        self.api_logger.log_event(
            marker,
            self.current_process_id(),
            self.current_log_tid(),
            self.time.current().tick_ms,
            self.instruction_count,
            fields,
        )
    }

    fn thread_state_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::<String, u64>::new();
        for thread in self.scheduler.thread_snapshots() {
            *counts.entry(thread.state.to_string()).or_insert(0) += 1;
        }
        counts
    }

    pub(super) fn dll_reason_name(reason: u64) -> &'static str {
        match reason {
            DLL_PROCESS_ATTACH => "process_attach",
            DLL_PROCESS_DETACH => "process_detach",
            DLL_THREAD_ATTACH => "thread_attach",
            DLL_THREAD_DETACH => "thread_detach",
            _ => "unknown",
        }
    }

    fn thread_state_counts_value(counts: &BTreeMap<String, u64>) -> serde_json::Value {
        let mut fields = Map::new();
        for (state, count) in counts {
            fields.insert(state.clone(), json!(count));
        }
        serde_json::Value::Object(fields)
    }

    pub(super) fn resolve_run_stop_reason(&mut self) -> RunStopReason {
        if let Some(reason) = self.stop_reason {
            return reason;
        }
        let reason = if self.process_exit_requested {
            RunStopReason::ProcessExit
        } else if !self.scheduler.has_live_threads() {
            RunStopReason::AllThreadsTerminated
        } else if self
            .main_thread_tid
            .and_then(|tid| self.scheduler.thread_state(tid))
            == Some("terminated")
        {
            RunStopReason::MainThreadTerminated
        } else if self.instruction_count >= self.config.max_instructions.max(1) {
            RunStopReason::InstructionBudgetExhausted
        } else if self.loaded {
            RunStopReason::SchedulerIdle
        } else {
            RunStopReason::RunComplete
        };
        self.stop_reason = Some(reason);
        reason
    }

    pub(super) fn add_address_ref_fields(
        &self,
        fields: &mut Map<String, serde_json::Value>,
        prefix: &str,
        address: u64,
    ) {
        let reference = self.address_ref(address);
        fields.insert(format!("{prefix}_owner"), json!(reference.owner));
        if let Some(module) = reference.module {
            fields.insert(format!("{prefix}_module"), json!(module));
        }
        if let Some(module_base) = reference.module_base {
            fields.insert(format!("{prefix}_module_base"), json!(module_base));
        }
        if let Some(rva) = reference.rva {
            fields.insert(format!("{prefix}_rva"), json!(rva));
        }
        if let Some(module_path) = reference.module_path {
            fields.insert(format!("{prefix}_module_path"), json!(module_path));
        }
        if let Some(region) = reference.region {
            fields.insert(format!("{prefix}_region"), json!(region));
        }
        if let Some(region_base) = reference.region_base {
            fields.insert(format!("{prefix}_region_base"), json!(region_base));
        }
        if let Some(region_offset) = reference.region_offset {
            fields.insert(format!("{prefix}_region_offset"), json!(region_offset));
        }
    }

    pub(super) fn register_map_value(registers: &BTreeMap<String, u64>) -> serde_json::Value {
        let mut values = Map::new();
        for (name, value) in registers {
            values.insert(name.clone(), json!(value));
        }
        serde_json::Value::Object(values)
    }

    pub(super) fn register_ref_map_value(
        &self,
        registers: &BTreeMap<String, u64>,
    ) -> serde_json::Value {
        let mut values = Map::new();
        for (name, value) in registers {
            if *value == 0 {
                continue;
            }
            let reference = self.address_ref(*value);
            if reference.owner == "unknown" {
                continue;
            }
            values.insert(name.clone(), reference.to_json_value());
        }
        serde_json::Value::Object(values)
    }

    pub(super) fn word_map_value(words: &BTreeMap<String, u64>) -> serde_json::Value {
        let mut values = Map::new();
        for (name, value) in words {
            values.insert(name.clone(), json!(value));
        }
        serde_json::Value::Object(values)
    }
}

impl VirtualExecutionEngine {
    fn format_native_delta(before: u64, after: u64) -> String {
        if after >= before {
            format!("+0x{:X}", after - before)
        } else {
            format!("-0x{:X}", before - after)
        }
    }

    fn native_loop_delta_entry_value(&self, delta: &LoopValueDelta) -> serde_json::Value {
        let mut entry = Map::new();
        entry.insert("before".to_string(), json!(delta.before));
        entry.insert("after".to_string(), json!(delta.after));
        entry.insert(
            "delta".to_string(),
            json!(Self::format_native_delta(delta.before, delta.after)),
        );
        let before_ref = self.address_ref(delta.before);
        if before_ref.owner != "unknown" && before_ref.owner != "NULL" {
            entry.insert("before_ref".to_string(), before_ref.to_json_value());
        }
        let after_ref = self.address_ref(delta.after);
        if after_ref.owner != "unknown" && after_ref.owner != "NULL" {
            entry.insert("after_ref".to_string(), after_ref.to_json_value());
        }
        serde_json::Value::Object(entry)
    }

    fn native_loop_delta_entries_value(
        &self,
        deltas: &BTreeMap<String, LoopValueDelta>,
    ) -> serde_json::Value {
        let mut values = Map::new();
        for (name, delta) in deltas {
            values.insert(name.clone(), self.native_loop_delta_entry_value(delta));
        }
        serde_json::Value::Object(values)
    }

    fn native_loop_state_delta_value(&self, delta: &LoopStateDelta) -> serde_json::Value {
        let mut record = Map::new();
        record.insert(
            "registers".to_string(),
            self.native_loop_delta_entries_value(&delta.registers),
        );
        record.insert(
            "stack_words".to_string(),
            self.native_loop_delta_entries_value(&delta.stack_words),
        );
        serde_json::Value::Object(record)
    }

    fn native_loop_phase_deltas_value(&self, phase_deltas: &[LoopPhaseDelta]) -> serde_json::Value {
        serde_json::Value::Array(
            phase_deltas
                .iter()
                .map(|phase_delta| {
                    let mut record = Map::new();
                    record.insert("phase".to_string(), json!(phase_delta.phase));
                    record.insert("pc".to_string(), json!(phase_delta.pc));
                    record.insert("size".to_string(), json!(phase_delta.size));
                    record.insert(
                        "changed_values".to_string(),
                        json!(phase_delta.change_count()),
                    );
                    record.insert(
                        "pc_ref".to_string(),
                        self.address_ref(phase_delta.pc).to_json_value(),
                    );
                    record.insert(
                        "state_delta".to_string(),
                        self.native_loop_state_delta_value(&phase_delta.state_delta),
                    );
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    fn native_loop_phase_sequence_value(
        &self,
        phase_summaries: &[LoopPhaseSummary],
    ) -> serde_json::Value {
        serde_json::Value::Array(
            phase_summaries
                .iter()
                .map(|phase_summary| {
                    let mut record = Map::new();
                    record.insert("phase".to_string(), json!(phase_summary.phase));
                    record.insert("pc".to_string(), json!(phase_summary.pc));
                    record.insert("size".to_string(), json!(phase_summary.size));
                    record.insert(
                        "changed_values".to_string(),
                        json!(phase_summary.change_count()),
                    );
                    record.insert(
                        "changed_registers".to_string(),
                        serde_json::Value::Array(
                            phase_summary
                                .changed_registers
                                .iter()
                                .map(|name| json!(name))
                                .collect(),
                        ),
                    );
                    record.insert(
                        "changed_stack_words".to_string(),
                        serde_json::Value::Array(
                            phase_summary
                                .changed_stack_words
                                .iter()
                                .map(|name| json!(name))
                                .collect(),
                        ),
                    );
                    record.insert(
                        "pc_ref".to_string(),
                        self.address_ref(phase_summary.pc).to_json_value(),
                    );
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    fn native_loop_register_hotspots_value(
        &self,
        phase_summaries: &[LoopPhaseSummary],
        state_delta: Option<&LoopStateDelta>,
    ) -> serde_json::Value {
        let mut hotspots = BTreeMap::<String, Vec<usize>>::new();
        for phase_summary in phase_summaries {
            for name in &phase_summary.changed_registers {
                hotspots
                    .entry(name.clone())
                    .or_default()
                    .push(phase_summary.phase);
            }
        }
        let mut entries = hotspots.into_iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            right
                .1
                .len()
                .cmp(&left.1.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        serde_json::Value::Array(
            entries
                .into_iter()
                .map(|(name, phases)| {
                    let mut record = Map::new();
                    record.insert("name".to_string(), json!(name));
                    record.insert("phase_hits".to_string(), json!(phases.len()));
                    record.insert(
                        "phases".to_string(),
                        serde_json::Value::Array(
                            phases.iter().copied().map(|phase| json!(phase)).collect(),
                        ),
                    );
                    if let Some(delta) = state_delta.and_then(|delta| delta.registers.get(&name)) {
                        record.insert(
                            "loop_start_delta".to_string(),
                            self.native_loop_delta_entry_value(delta),
                        );
                    }
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    fn native_loop_stack_hotspots_value(
        &self,
        phase_summaries: &[LoopPhaseSummary],
        state_delta: Option<&LoopStateDelta>,
    ) -> serde_json::Value {
        let mut hotspots = BTreeMap::<String, Vec<usize>>::new();
        for phase_summary in phase_summaries {
            for name in &phase_summary.changed_stack_words {
                hotspots
                    .entry(name.clone())
                    .or_default()
                    .push(phase_summary.phase);
            }
        }
        let mut entries = hotspots.into_iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            right
                .1
                .len()
                .cmp(&left.1.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        serde_json::Value::Array(
            entries
                .into_iter()
                .map(|(name, phases)| {
                    let mut record = Map::new();
                    record.insert("name".to_string(), json!(name));
                    record.insert("phase_hits".to_string(), json!(phases.len()));
                    record.insert(
                        "phases".to_string(),
                        serde_json::Value::Array(
                            phases.iter().copied().map(|phase| json!(phase)).collect(),
                        ),
                    );
                    if let Some(delta) = state_delta.and_then(|delta| delta.stack_words.get(&name))
                    {
                        record.insert(
                            "loop_start_delta".to_string(),
                            self.native_loop_delta_entry_value(delta),
                        );
                    }
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    pub(super) fn native_loop_value(&self, snapshot: &NativeLoopSnapshot) -> serde_json::Value {
        let mut record = Map::new();
        record.insert("period".to_string(), json!(snapshot.period));
        record.insert("repeats".to_string(), json!(snapshot.repeats));
        record.insert(
            "covered_blocks".to_string(),
            json!(snapshot.repeats.saturating_mul(snapshot.period as u64)),
        );
        record.insert(
            "sequence".to_string(),
            serde_json::Value::Array(
                snapshot
                    .blocks
                    .iter()
                    .map(|(pc, size)| {
                        let mut block = Map::new();
                        block.insert("pc".to_string(), json!(pc));
                        block.insert("size".to_string(), json!(size));
                        block.insert("pc_ref".to_string(), self.address_ref(*pc).to_json_value());
                        serde_json::Value::Object(block)
                    })
                    .collect(),
            ),
        );
        if !snapshot.phase_summaries.is_empty() {
            record.insert(
                "phase_sequence".to_string(),
                self.native_loop_phase_sequence_value(&snapshot.phase_summaries),
            );
            record.insert(
                "register_hotspots".to_string(),
                self.native_loop_register_hotspots_value(
                    &snapshot.phase_summaries,
                    snapshot.state_delta.as_ref(),
                ),
            );
            record.insert(
                "stack_hotspots".to_string(),
                self.native_loop_stack_hotspots_value(
                    &snapshot.phase_summaries,
                    snapshot.state_delta.as_ref(),
                ),
            );
        }
        if let Some(state_delta) = snapshot.state_delta.as_ref() {
            record.insert(
                "state_delta".to_string(),
                self.native_loop_state_delta_value(state_delta),
            );
        }
        if !snapshot.phase_deltas.is_empty() {
            record.insert(
                "phase_deltas".to_string(),
                self.native_loop_phase_deltas_value(&snapshot.phase_deltas),
            );
        }
        serde_json::Value::Object(record)
    }
}

impl VirtualExecutionEngine {
    fn native_hot_blocks_value(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.native_trace
                .top_blocks(NATIVE_PROGRESS_TOP_BLOCK_LIMIT)
                .into_iter()
                .map(|((pc, size), hits)| {
                    let mut block = Map::new();
                    block.insert("pc".to_string(), json!(pc));
                    block.insert("size".to_string(), json!(size));
                    block.insert("hits".to_string(), json!(hits));
                    let reference = self.address_ref(pc);
                    block.insert("pc_ref".to_string(), reference.to_json_value());
                    serde_json::Value::Object(block)
                })
                .collect(),
        )
    }

    pub(super) fn log_instruction_budget_exhausted(
        &mut self,
        phase: &str,
        pc: u64,
    ) -> Result<(), VmError> {
        if !self.api_logger.enabled() {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("phase".to_string(), json!(phase));
        fields.insert(
            "instruction_budget".to_string(),
            json!(self.config.max_instructions.max(1)),
        );
        fields.insert("pc".to_string(), json!(pc));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event_immediate("INSTRUCTION_BUDGET", fields)
    }

    pub(super) fn log_native_progress(&mut self, pc: u64, size: u32) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("NATIVE_PROGRESS")
            || self.native_trace.total_blocks() == 0
        {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("size".to_string(), json!(size));
        fields.insert(
            "blocks_seen".to_string(),
            json!(self.native_trace.total_blocks()),
        );
        fields.insert(
            "unique_blocks".to_string(),
            json!(self.native_trace.unique_blocks()),
        );
        fields.insert("hot_blocks".to_string(), self.native_hot_blocks_value());
        if let Some(active_loop) = self.native_trace.active_loop() {
            fields.insert(
                "active_loop".to_string(),
                self.native_loop_value(&active_loop),
            );
        }
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event("NATIVE_PROGRESS", fields)
    }

    pub(super) fn log_native_summary(&mut self, reason: RunStopReason) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("NATIVE_SUMMARY") || self.native_trace.total_blocks() == 0
        {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!(reason.as_str()));
        fields.insert(
            "blocks_seen".to_string(),
            json!(self.native_trace.total_blocks()),
        );
        fields.insert(
            "unique_blocks".to_string(),
            json!(self.native_trace.unique_blocks()),
        );
        fields.insert("hot_blocks".to_string(), self.native_hot_blocks_value());
        if let Some(active_loop) = self.native_trace.active_loop() {
            fields.insert(
                "active_loop".to_string(),
                self.native_loop_value(&active_loop),
            );
        }
        self.log_runtime_event("NATIVE_SUMMARY", fields)
    }

    pub(super) fn log_native_loop(&mut self, snapshot: &NativeLoopSnapshot) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("NATIVE_LOOP") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("loop".to_string(), self.native_loop_value(snapshot));
        self.log_runtime_event("NATIVE_LOOP", fields)
    }

    pub(super) fn log_native_block(
        &mut self,
        pc: u64,
        size: u32,
        snapshot: Option<&NativeBlockSnapshot>,
    ) -> Result<(), VmError> {
        if !self.api_logger.native_trace_sampling_enabled() {
            return Ok(());
        }
        let update = self
            .native_trace
            .record_block(self.instruction_count, pc, size, snapshot);
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("size".to_string(), json!(size));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event("NATIVE_BLOCK", fields)?;
        if let Some(loop_snapshot) = update.loop_snapshot.as_ref() {
            self.log_native_loop(loop_snapshot)?;
        }
        if update.should_log_progress {
            self.log_native_progress(pc, size)?;
        }
        Ok(())
    }

    pub(super) fn log_native_fault(
        &mut self,
        kind: &str,
        access: &str,
        pc: u64,
        address: u64,
        size: usize,
        registers: Option<&BTreeMap<String, u64>>,
        detail: Option<&str>,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("NATIVE_FAULT") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("kind".to_string(), json!(kind));
        fields.insert("access".to_string(), json!(access));
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(size));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.add_address_ref_fields(&mut fields, "address", address);
        if let Ok(bytes) = self.modules.memory().read(pc, 16) {
            fields.insert(
                "pc_bytes".to_string(),
                json!(Self::format_runtime_bytes(&bytes)),
            );
        }
        if let Some(registers) = registers {
            fields.insert("registers".to_string(), Self::register_map_value(registers));
            fields.insert(
                "register_refs".to_string(),
                self.register_ref_map_value(registers),
            );
        }
        if let Some(detail) = detail {
            fields.insert("detail".to_string(), json!(detail));
        }
        self.log_runtime_event_immediate("NATIVE_FAULT", fields)
    }

    pub(super) fn log_native_fault_window(
        &mut self,
        snapshots: &VecDeque<NativeBlockSnapshot>,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("NATIVE_TRACE_WINDOW") || snapshots.is_empty() {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("blocks".to_string(), json!(snapshots.len()));
        fields.insert(
            "window".to_string(),
            serde_json::Value::Array(
                snapshots
                    .iter()
                    .map(|snapshot| {
                        let mut block = Map::new();
                        block.insert("pc".to_string(), json!(snapshot.pc));
                        block.insert("size".to_string(), json!(snapshot.size));
                        block.insert(
                            "registers".to_string(),
                            Self::register_map_value(&snapshot.registers),
                        );
                        block.insert(
                            "register_refs".to_string(),
                            self.register_ref_map_value(&snapshot.registers),
                        );
                        block.insert(
                            "stack_words".to_string(),
                            Self::word_map_value(&snapshot.stack_words),
                        );
                        serde_json::Value::Object(block)
                    })
                    .collect(),
            ),
        );
        self.log_runtime_event_immediate("NATIVE_TRACE_WINDOW", fields)
    }

    pub(super) fn log_native_code_write(
        &mut self,
        address: u64,
        size: usize,
        bytes: &[u8],
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("NATIVE_CODE_WRITE") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(size));
        fields.insert(
            "bytes_preview".to_string(),
            json!(Self::format_runtime_bytes(bytes)),
        );
        self.add_address_ref_fields(&mut fields, "address", address);
        self.log_runtime_event("NATIVE_CODE_WRITE", fields)
    }
}

impl VirtualExecutionEngine {
    pub(super) fn log_seh_dispatch(
        &mut self,
        fault: UnicornFault,
        registration: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("access".to_string(), json!(fault.access.as_str()));
        fields.insert("pc".to_string(), json!(fault.pc));
        fields.insert("address".to_string(), json!(fault.address));
        fields.insert("size".to_string(), json!(fault.size));
        fields.insert("registration".to_string(), json!(registration));
        self.add_address_ref_fields(&mut fields, "pc", fault.pc);
        self.add_address_ref_fields(&mut fields, "address", fault.address);
        self.add_address_ref_fields(&mut fields, "registration", registration);
        self.log_runtime_event_immediate("SEH_DISPATCH", fields)
    }

    pub(super) fn log_seh_handler(
        &mut self,
        registration: u64,
        handler: u64,
        disposition: u32,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("registration".to_string(), json!(registration));
        fields.insert("handler".to_string(), json!(handler));
        fields.insert("disposition".to_string(), json!(disposition));
        self.add_address_ref_fields(&mut fields, "registration", registration);
        self.add_address_ref_fields(&mut fields, "handler", handler);
        self.log_runtime_event_immediate("SEH_HANDLER", fields)
    }

    pub(super) fn log_seh_resume(
        &mut self,
        context_record: u64,
        registers: &BTreeMap<String, u64>,
    ) -> Result<(), VmError> {
        let pc = if self.arch.is_x86() {
            registers.get("eip").copied().unwrap_or(0)
        } else {
            registers.get("rip").copied().unwrap_or(0)
        };
        let mut fields = Map::new();
        fields.insert("context_record".to_string(), json!(context_record));
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("registers".to_string(), Self::register_map_value(registers));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.add_address_ref_fields(&mut fields, "context", context_record);
        self.log_runtime_event_immediate("SEH_RESUME", fields)
    }

    pub(super) fn log_x64_seh_dispatch(
        &mut self,
        fault: UnicornFault,
        exception_record: u64,
        context_record: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("access".to_string(), json!(fault.access.as_str()));
        fields.insert("pc".to_string(), json!(fault.pc));
        fields.insert("address".to_string(), json!(fault.address));
        fields.insert("size".to_string(), json!(fault.size));
        fields.insert("exception_record".to_string(), json!(exception_record));
        fields.insert("context_record".to_string(), json!(context_record));
        self.add_address_ref_fields(&mut fields, "pc", fault.pc);
        self.add_address_ref_fields(&mut fields, "address", fault.address);
        self.add_address_ref_fields(&mut fields, "exception", exception_record);
        self.add_address_ref_fields(&mut fields, "context", context_record);
        self.log_runtime_event_immediate("SEH_X64_DISPATCH", fields)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn log_x64_seh_frame(
        &mut self,
        control_pc: u64,
        function_entry: u64,
        unwind_info: u64,
        establisher_frame: u64,
        handler: Option<u64>,
        handler_data: Option<u64>,
        flags: u8,
        leaf: bool,
        caller_pc: u64,
        caller_sp: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("control_pc".to_string(), json!(control_pc));
        fields.insert("function_entry".to_string(), json!(function_entry));
        fields.insert("unwind_info".to_string(), json!(unwind_info));
        fields.insert("establisher_frame".to_string(), json!(establisher_frame));
        fields.insert("handler".to_string(), json!(handler.unwrap_or(0)));
        fields.insert("handler_data".to_string(), json!(handler_data.unwrap_or(0)));
        fields.insert("flags".to_string(), json!(flags));
        fields.insert("leaf".to_string(), json!(leaf));
        fields.insert("caller_pc".to_string(), json!(caller_pc));
        fields.insert("caller_sp".to_string(), json!(caller_sp));
        self.add_address_ref_fields(&mut fields, "control_pc", control_pc);
        self.add_address_ref_fields(&mut fields, "function_entry", function_entry);
        self.add_address_ref_fields(&mut fields, "unwind_info", unwind_info);
        self.add_address_ref_fields(&mut fields, "establisher_frame", establisher_frame);
        self.add_address_ref_fields(&mut fields, "handler", handler.unwrap_or(0));
        self.add_address_ref_fields(&mut fields, "handler_data", handler_data.unwrap_or(0));
        self.add_address_ref_fields(&mut fields, "caller_pc", caller_pc);
        self.add_address_ref_fields(&mut fields, "caller_sp", caller_sp);
        self.log_runtime_event_immediate("SEH_X64_FRAME", fields)
    }

    pub(super) fn log_x64_seh_unhandled(
        &mut self,
        exception_code: u32,
        control_pc: u64,
        establisher_frame: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("exception_code".to_string(), json!(exception_code));
        fields.insert(
            "exception_text".to_string(),
            json!(Self::format_exception_code_for_log(exception_code)),
        );
        fields.insert("control_pc".to_string(), json!(control_pc));
        fields.insert("establisher_frame".to_string(), json!(establisher_frame));
        self.add_address_ref_fields(&mut fields, "control_pc", control_pc);
        self.add_address_ref_fields(&mut fields, "establisher_frame", establisher_frame);
        self.log_runtime_event_immediate("SEH_X64_UNHANDLED", fields)
    }

    pub(super) fn log_module_event(
        &mut self,
        marker: &str,
        module: &ModuleRecord,
        source: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("size".to_string(), json!(module.size));
        fields.insert("entrypoint".to_string(), json!(module.entrypoint));
        fields.insert("synthetic".to_string(), json!(module.synthetic));
        if let Some(path) = module.path.as_ref() {
            fields.insert(
                "path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        self.log_runtime_event(marker, fields)
    }

    pub(super) fn log_module_notification(
        &mut self,
        module: &ModuleRecord,
        reason: u64,
        phase: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("entrypoint".to_string(), json!(module.entrypoint));
        fields.insert("reason".to_string(), json!(Self::dll_reason_name(reason)));
        fields.insert("phase".to_string(), json!(phase));
        fields.insert("routine".to_string(), json!("DllMain"));
        fields.insert("synthetic".to_string(), json!(module.synthetic));
        if let Some(path) = module.path.as_ref() {
            fields.insert(
                "path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        self.add_address_ref_fields(&mut fields, "entrypoint", module.entrypoint);
        self.log_runtime_event("DLL_NOTIFICATION", fields)
    }

    pub(super) fn log_entry_invoke(
        &mut self,
        module: &ModuleRecord,
        address: u64,
        arguments: &[u64],
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert(
            "invocation".to_string(),
            json!(match self.entry_invocation {
                EntryInvocation::NativeEntrypoint => "native_entrypoint",
                EntryInvocation::Export => "export",
            }),
        );
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("address".to_string(), json!(address));
        fields.insert("argc".to_string(), json!(arguments.len()));
        fields.insert("args".to_string(), json!(arguments));
        if let Some(path) = module.path.as_ref() {
            fields.insert(
                "path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        if let Some(export) = self.config.entry_export.as_deref() {
            fields.insert("export".to_string(), json!(export));
        }
        if let Some(ordinal) = self.config.entry_ordinal {
            fields.insert("ordinal".to_string(), json!(ordinal));
        }
        self.add_address_ref_fields(&mut fields, "address", address);
        self.log_runtime_event("ENTRY_INVOKE", fields)
    }

    pub(super) fn log_tls_callback_event(
        &mut self,
        module: &ModuleRecord,
        callback: u64,
        reason: u64,
        phase: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("callback".to_string(), json!(callback));
        fields.insert("reason".to_string(), json!(Self::dll_reason_name(reason)));
        fields.insert("phase".to_string(), json!(phase));
        fields.insert("synthetic".to_string(), json!(module.synthetic));
        self.add_address_ref_fields(&mut fields, "callback", callback);
        self.log_runtime_event("TLS_CALLBACK", fields)
    }

    pub(super) fn log_thread_event(
        &mut self,
        marker: &str,
        tid: u32,
        handle: u32,
        start_address: u64,
        parameter: u64,
        state: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("thread_tid".to_string(), json!(tid));
        fields.insert("thread_handle".to_string(), json!(handle));
        fields.insert("start_address".to_string(), json!(start_address));
        fields.insert("parameter".to_string(), json!(parameter));
        fields.insert("state".to_string(), json!(state));
        self.log_runtime_event(marker, fields)
    }

    pub(super) fn log_heap_event(
        &mut self,
        marker: &str,
        heap: u32,
        address: u64,
        size: u64,
        source: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("heap".to_string(), json!(heap));
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(size));
        fields.insert("source".to_string(), json!(source));
        self.log_runtime_event(marker, fields)
    }

    pub(super) fn log_file_event(
        &mut self,
        marker: &str,
        handle: u32,
        path: &str,
        bytes: Option<u64>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(path));
        if let Some(bytes) = bytes {
            fields.insert("bytes".to_string(), json!(bytes));
        }
        self.log_runtime_event(marker, fields)
    }

    pub(super) fn log_file_write_event(
        &mut self,
        handle: u32,
        path: &str,
        bytes: &[u8],
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(path));
        fields.insert("bytes".to_string(), json!(bytes.len()));
        Self::add_payload_preview_field(&mut fields, bytes);
        self.log_runtime_event("FILE_WRITE", fields)
    }

    pub(super) fn log_http_connect_event(
        &mut self,
        source: &str,
        connection_handle: u32,
    ) -> Result<(), VmError> {
        let Some(connection) = self.network.get_connection(connection_handle) else {
            return Ok(());
        };
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("connection_handle".to_string(), json!(connection_handle));
        fields.insert(
            "session_handle".to_string(),
            json!(connection.session_handle),
        );
        fields.insert("host".to_string(), json!(connection.server));
        fields.insert("port".to_string(), json!(connection.port));
        fields.insert("service".to_string(), json!(connection.service));
        if !connection.username.is_empty() {
            fields.insert("username".to_string(), json!(connection.username));
        }
        self.log_runtime_event("HTTP_CONNECT", fields)
    }

    pub(super) fn log_http_request_event(
        &mut self,
        source: &str,
        request_handle: u32,
    ) -> Result<(), VmError> {
        let Some(request) = self.network.get_request(request_handle) else {
            return Ok(());
        };
        let route = self.network.request_route(request_handle);
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("request_handle".to_string(), json!(request_handle));
        fields.insert("parent_handle".to_string(), json!(request.parent_handle));
        fields.insert("verb".to_string(), json!(request.verb));
        fields.insert("target".to_string(), json!(request.target));
        fields.insert("version".to_string(), json!(request.version));
        fields.insert("sent".to_string(), json!(request.sent));
        if !request.referrer.is_empty() {
            fields.insert("referrer".to_string(), json!(request.referrer));
        }
        if !request.headers.is_empty() {
            fields.insert("headers".to_string(), json!(request.headers));
        }
        if let Some((host, target, verb)) = route {
            if !host.is_empty() {
                fields.insert("host".to_string(), json!(host));
            }
            if target != request.target {
                fields.insert("normalized_target".to_string(), json!(target));
            }
            if verb != request.verb {
                fields.insert("normalized_verb".to_string(), json!(verb));
            }
        }
        if let Some(connection) = self.network.get_connection(request.parent_handle) {
            fields.insert("port".to_string(), json!(connection.port));
            fields.insert("service".to_string(), json!(connection.service));
        }
        if !request.request_body.is_empty() {
            fields.insert("body_len".to_string(), json!(request.request_body.len()));
            Self::add_payload_preview_field(&mut fields, &request.request_body);
        }
        self.log_runtime_event("HTTP_REQUEST", fields)
    }

    pub(super) fn log_artifact_hide(
        &mut self,
        artifact_type: &str,
        operation: &str,
        requested: &str,
        rule: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("artifact_type".to_string(), json!(artifact_type));
        fields.insert("operation".to_string(), json!(operation));
        fields.insert("requested".to_string(), json!(requested));
        fields.insert("rule".to_string(), json!(rule));
        self.log_runtime_event("ARTIFACT_HIDE", fields)
    }

    pub(super) fn log_unsupported_import(
        &mut self,
        importing_module: &ModuleRecord,
        target_module: &str,
        target_function: &str,
        thunk: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert(
            "importing_module".to_string(),
            json!(importing_module.name.clone()),
        );
        if let Some(path) = importing_module.path.as_ref() {
            fields.insert(
                "importing_path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        fields.insert("target_module".to_string(), json!(target_module));
        fields.insert("target_function".to_string(), json!(target_function));
        fields.insert("thunk".to_string(), json!(thunk));
        fields.insert(
            "reason".to_string(),
            json!("missing hook definition for synthetic import"),
        );
        self.log_runtime_event_immediate("UNSUPPORTED_IMPORT", fields)
    }

    pub(super) fn log_unsupported_bound_stub(
        &mut self,
        address: u64,
        target_module: &str,
        target_function: &str,
        reason: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(address));
        fields.insert("target_module".to_string(), json!(target_module));
        fields.insert("target_function".to_string(), json!(target_function));
        fields.insert("reason".to_string(), json!(reason));
        self.log_runtime_event_immediate("UNSUPPORTED_HOOK", fields)
    }

    pub(super) fn log_unsupported_runtime_stub(
        &mut self,
        definition: &HookDefinition,
        pc: u64,
        reason: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("target_module".to_string(), json!(definition.module));
        fields.insert("target_function".to_string(), json!(definition.function));
        fields.insert("reason".to_string(), json!(reason));
        self.log_runtime_event_immediate("UNSUPPORTED_RUNTIME", fields)
    }
}
