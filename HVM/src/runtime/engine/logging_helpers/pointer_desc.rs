use super::*;
use crate::hooks::types::{LogPolicy, ParamDirection, ParamType, ParamTypeDiscriminant};

impl VirtualExecutionEngine {
    pub fn format_api_value(&self, kind: ApiArgKind, value: u64) -> String {
        match kind {
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

    pub fn format_param_type_value(
        &self,
        ty: &ParamType,
        dir: ParamDirection,
        value: u64,
        all_args: &[u64],
        log_policy: LogPolicy,
    ) -> Option<String> {
        if matches!(log_policy, LogPolicy::Skip) {
            return None;
        }
        let rendered = match ty {
            ParamType::Bool32 => {
                if value == 0 {
                    "FALSE".to_string()
                } else {
                    "TRUE".to_string()
                }
            }
            ParamType::I16 => format!("{}", value as u16 as i16),
            ParamType::U16 => format!("{}", value as u16),
            ParamType::I32 | ParamType::SSizeT => format!("{}", value as u32 as i32),
            ParamType::U32 => format!("{}", value as u32),
            ParamType::Hex32 => format!("0x{:X}", value as u32),
            ParamType::Hex64 => format!("0x{value:X}"),
            ParamType::I64 => format!("{}", value as i64),
            ParamType::U64 => format!("{value}"),
            ParamType::SizeT => format!("0x{:X}", value),
            ParamType::PointerSizedUInt => format!("0x{value:X}"),
            ParamType::PointerSizedInt => format!("{}", value as i64),
            ParamType::Handle | ParamType::PseudoHandle => self.describe_pointer(value, false),
            ParamType::ModuleHandle => self.describe_module_handle(value),
            ParamType::GuestPtr | ParamType::FunctionPtr => self.describe_pointer(value, false),
            ParamType::GuestPtrTo(inner) => self.describe_typed_pointer(value, *inner, dir),
            ParamType::PCStr | ParamType::PStr => self.describe_string_pointer(value, false),
            ParamType::PCWStr | ParamType::PWStr => self.describe_string_pointer(value, true),
            ParamType::ProcName => {
                if value <= 0xFFFF {
                    format!("ordinal:{value}")
                } else {
                    self.describe_string_pointer(value, false)
                }
            }
            ParamType::CountedAnsi {
                len_param,
                code_page_param,
            } => {
                let count = all_args.get(*len_param).copied().unwrap_or(0);
                let cp = code_page_param
                    .and_then(|i| all_args.get(i).copied())
                    .unwrap_or(0);
                self.describe_ansi_input_pointer(value, count, cp)
                    .unwrap_or_else(|| self.describe_pointer(value, false))
            }
            ParamType::CountedWide { len_param } => {
                let count = all_args.get(*len_param).copied().unwrap_or(0) as usize;
                self.describe_wide_counted_pointer(value, count)
                    .unwrap_or_else(|| self.describe_pointer(value, false))
            }
            ParamType::Buffer { len_param } | ParamType::ByteSlice { len_param } => {
                let len = all_args.get(*len_param).copied().unwrap_or(0);
                self.describe_buffer_pointer(value, len)
            }
            ParamType::WideBuffer { len_param } => {
                let len = all_args.get(*len_param).copied().unwrap_or(0);
                self.describe_buffer_pointer(value, len.saturating_mul(2))
            }
            ParamType::OutBuffer { .. } => self.describe_pointer(value, false),
            ParamType::GuidPtr
            | ParamType::SidPtr
            | ParamType::SecurityAttributesPtr
            | ParamType::StartupInfoPtr
            | ParamType::ProcessInformationPtr
            | ParamType::OverlappedPtr
            | ParamType::FileTimePtr
            | ParamType::SystemTimePtr
            | ParamType::OpaqueStructPtr(_) => self.describe_pointer(value, false),
            ParamType::AnsiStringStruct => self.describe_ansi_string_struct(value),
            ParamType::UnicodeStringStruct => self.describe_unicode_string_struct(value),
        };
        if matches!(log_policy, LogPolicy::Hex)
            && !matches!(ty, ParamType::Hex32 | ParamType::Hex64)
        {
            Some(format!("0x{value:X}"))
        } else {
            Some(rendered)
        }
    }

    pub fn describe_typed_pointer(
        &self,
        address: u64,
        inner: ParamTypeDiscriminant,
        dir: ParamDirection,
    ) -> String {
        if address == 0 {
            return "NULL".to_string();
        }
        if matches!(dir, ParamDirection::Out) {
            return self.describe_pointer(address, false);
        }
        let suffix = match inner {
            ParamTypeDiscriminant::U16 => {
                self.read_u16(address)
                    .ok()
                    .map(|value| match char::from_u32(value as u32) {
                        Some(ch) if !ch.is_control() => format!("->0x{value:04X}('{ch}')"),
                        _ => format!("->0x{value:04X}"),
                    })
            }
            ParamTypeDiscriminant::U32 => self
                .read_u32(address)
                .ok()
                .map(|value| format!("->0x{value:08X}")),
            ParamTypeDiscriminant::I32 => self
                .read_i32(address)
                .ok()
                .map(|value| format!("->{value}")),
            ParamTypeDiscriminant::Handle | ParamTypeDiscriminant::GuestPtr => self
                .read_pointer_value(address)
                .ok()
                .map(|value| format!("->{}", self.describe_pointer(value, false))),
            ParamTypeDiscriminant::GuidPtr | ParamTypeDiscriminant::Void => None,
        };
        match suffix {
            Some(suffix) => {
                if let Some(owner) = self.pointer_owner(address) {
                    format!("0x{address:X}<{owner}>{suffix}")
                } else {
                    format!("0x{address:X}{suffix}")
                }
            }
            None => self.describe_pointer(address, false),
        }
    }

    pub fn param_type_to_kind_str(ty: &ParamType) -> &'static str {
        match ty {
            ParamType::Bool32 => "bool32",
            ParamType::I16 => "i16",
            ParamType::U16 => "u16",
            ParamType::I32 => "i32",
            ParamType::U32 => "u32",
            ParamType::Hex32 => "hex32",
            ParamType::Hex64 => "hex64",
            ParamType::I64 => "i64",
            ParamType::U64 => "u64",
            ParamType::SizeT => "size_t",
            ParamType::SSizeT => "ssize_t",
            ParamType::PointerSizedUInt => "ptr_uint",
            ParamType::PointerSizedInt => "ptr_int",
            ParamType::Handle => "handle",
            ParamType::PseudoHandle => "pseudo_handle",
            ParamType::ModuleHandle => "module",
            ParamType::GuestPtr => "ptr",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U16) => "ptr_to_u16",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32) => "ptr_to_u32",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::I32) => "ptr_to_i32",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::Handle) => "ptr_to_handle",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr) => "ptr_to_ptr",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuidPtr) => "ptr_to_guid",
            ParamType::GuestPtrTo(ParamTypeDiscriminant::Void) => "ptr_to_void",
            ParamType::FunctionPtr => "fn_ptr",
            ParamType::PCStr => "pcstr",
            ParamType::PCWStr => "pcwstr",
            ParamType::PStr => "pstr",
            ParamType::PWStr => "pwstr",
            ParamType::ProcName => "procname",
            ParamType::CountedAnsi { .. } => "counted_ansi",
            ParamType::CountedWide { .. } => "counted_wide",
            ParamType::Buffer { .. } => "buffer",
            ParamType::OutBuffer { .. } => "out_buffer",
            ParamType::ByteSlice { .. } => "byte_slice",
            ParamType::WideBuffer { .. } => "wide_buffer",
            ParamType::GuidPtr => "guid_ptr",
            ParamType::SidPtr => "sid_ptr",
            ParamType::SecurityAttributesPtr => "security_attributes",
            ParamType::StartupInfoPtr => "startup_info",
            ParamType::ProcessInformationPtr => "process_info",
            ParamType::OverlappedPtr => "overlapped",
            ParamType::FileTimePtr => "filetime",
            ParamType::SystemTimePtr => "systemtime",
            ParamType::OpaqueStructPtr(name) => name,
            ParamType::AnsiStringStruct => "ansi_string",
            ParamType::UnicodeStringStruct => "unicode_string",
        }
    }

    pub fn describe_pointer(&self, value: u64, auto_string: bool) -> String {
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

    pub fn describe_string_pointer(&self, address: u64, wide: bool) -> String {
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

    pub fn describe_module_handle(&self, value: u64) -> String {
        if value == 0 {
            return "NULL".to_string();
        }
        if let Some(module) = self.core.modules.get_by_base(value) {
            return format!("0x{value:X}<module:{}>", module.name);
        }
        self.describe_pointer(value, false)
    }

    pub fn describe_unicode_string_struct(&self, address: u64) -> String {
        if address == 0 {
            return "NULL".to_string();
        }
        match self.safe_read_unicode_string_struct(address) {
            Some(text) => self.format_pointer_with_text(address, &text),
            None => format!("0x{address:X}<UNICODE_STRING?>"),
        }
    }

    pub fn describe_ansi_string_struct(&self, address: u64) -> String {
        if address == 0 {
            return "NULL".to_string();
        }
        match self.safe_read_ansi_string_struct(address) {
            Some(text) => self.format_pointer_with_text(address, &text),
            None => format!("0x{address:X}<ANSI_STRING?>"),
        }
    }

    pub fn describe_wide_input_pointer(&self, address: u64, count: u64) -> Option<String> {
        let text = self.safe_read_wide_input(address, count, false)?;
        Some(self.format_pointer_with_text(address, &text))
    }

    pub fn describe_wide_counted_pointer(&self, address: u64, count: usize) -> Option<String> {
        if address == 0 {
            return Some("NULL".to_string());
        }
        let text = self
            .read_wide_counted_string_from_memory(address, count)
            .ok()
            .and_then(|value| self.sanitize_explicit_api_log_text(&value))?;
        Some(self.format_pointer_with_text(address, &text))
    }

    pub fn describe_ansi_input_pointer(
        &self,
        address: u64,
        count: u64,
        code_page: u64,
    ) -> Option<String> {
        let text = self.safe_read_ansi_input(address, count, code_page, false)?;
        Some(self.format_pointer_with_text(address, &text))
    }

    pub fn describe_exception_pointers_argument(&self, address: u64) -> Option<String> {
        if address == 0 {
            return Some("NULL".to_string());
        }
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn format_pointer_with_text(&self, address: u64, text: &str) -> String {
        if let Some(owner) = self.pointer_owner(address) {
            format!("0x{address:X}<{owner}>:{}", quote_api_log_text(text))
        } else {
            format!("0x{address:X}:{}", quote_api_log_text(text))
        }
    }

    pub fn describe_buffer_pointer(&self, address: u64, byte_len: u64) -> String {
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

    pub fn api_log_binary_preview_limit(&self) -> usize {
        self.core.config.api_log_string_limit.max(24).clamp(24, 96) / 3
    }

    pub fn format_pointer_with_binary_preview(
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

    pub fn pointer_owner(&self, address: u64) -> Option<String> {
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

pub fn trim_trailing_nul(bytes: &[u8], unit: usize) -> &[u8] {
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
    pub fn safe_read_wide_input(&self, address: u64, count: u64, auto: bool) -> Option<String> {
        self.read_wide_input_string(address, count)
            .ok()
            .and_then(|value| self.sanitize_api_log_text(&value, auto))
    }

    pub fn safe_read_ansi_input(
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

    pub fn safe_read_ansi_c_string_explicit(&self, address: u64) -> Option<String> {
        self.read_c_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_explicit_api_log_text(&value))
    }

    pub fn safe_read_wide_c_string_explicit(&self, address: u64) -> Option<String> {
        self.read_wide_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_explicit_api_log_text(&value))
    }

    pub fn safe_read_ansi_c_string_auto(&self, address: u64) -> Option<String> {
        self.read_c_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_auto_api_log_text(&value))
    }

    pub fn safe_read_wide_c_string_auto(&self, address: u64) -> Option<String> {
        self.read_wide_string_from_memory(address)
            .ok()
            .and_then(|value| self.sanitize_auto_api_log_text(&value))
    }

    pub fn safe_read_unicode_string_struct(&self, address: u64) -> Option<String> {
        let length_bytes = self.read_bytes_from_memory(address, 2).ok()?;
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
        let buffer_offset = if self.core.arch.is_x86() { 4 } else { 8 };
        let buffer_ptr = if self.core.arch.is_x86() {
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
            (length / 2).min(self.core.config.api_log_string_limit.max(16)),
        )
        .ok()
        .and_then(|value| self.sanitize_explicit_api_log_text(&value))
    }

    pub fn safe_read_ansi_string_struct(&self, address: u64) -> Option<String> {
        let length_bytes = self.read_bytes_from_memory(address, 2).ok()?;
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
        let buffer_offset = if self.core.arch.is_x86() { 4 } else { 8 };
        let buffer_ptr = if self.core.arch.is_x86() {
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
                length.min(self.core.config.api_log_string_limit.max(16)),
            )
            .ok()?;
        let text = Self::decode_ascii_bytes_ignoring_errors(&bytes);
        self.sanitize_explicit_api_log_text(&text)
    }

    pub fn try_auto_string(&self, address: u64) -> Option<String> {
        if address == 0 || self.core.modules.memory().find_region(address, 1).is_none() {
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

    pub fn looks_like_wide_string(&self, address: u64) -> bool {
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

    pub fn sanitize_api_log_text(&self, value: &str, auto: bool) -> Option<String> {
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

    pub fn sanitize_auto_api_log_text(&self, value: &str) -> Option<String> {
        self.sanitize_api_log_text(value, true)
    }

    pub fn sanitize_explicit_api_log_text(&self, value: &str) -> Option<String> {
        self.sanitize_api_log_text(value, false)
    }

    pub fn truncate_api_log_text(&self, value: &str) -> String {
        let limit = self.core.config.api_log_string_limit.max(16);
        let mut chars = value.chars();
        let truncated = chars.by_ref().take(limit).collect::<String>();
        if chars.next().is_some() {
            format!("{truncated}...")
        } else {
            truncated
        }
    }
}
