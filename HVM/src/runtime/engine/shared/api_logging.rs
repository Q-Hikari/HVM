use super::*;
use crate::runtime::engine::logging_helpers::{trim_trailing_nul, ApiArgKind};

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn describe_custom_api_call_args(
        &self,
        target_module: &str,
        target_function: &str,
        args: &[u64],
    ) -> Option<Vec<ApiLogArg>> {
        let module = target_module.to_ascii_lowercase();
        let function = target_function.to_ascii_lowercase();
        match (module.as_str(), function.as_str()) {
            ("msvcrt.dll", "memcmp") => Some(vec![
                self.render_api_buffer_arg(0, "lhs", args.arg(0), args.arg(2)),
                self.render_api_buffer_arg(1, "rhs", args.arg(1), args.arg(2)),
                self.render_api_size_arg(2, "count", args.arg(2)),
            ]),
            ("msvcrt.dll", "memmove")
            | ("msvcrt.dll", "memcpy")
            | ("vcruntime140.dll", "memcpy") => Some(vec![
                self.render_api_buffer_arg(0, "dest", args.arg(0), args.arg(2)),
                self.render_api_buffer_arg(1, "src", args.arg(1), args.arg(2)),
                self.render_api_size_arg(2, "count", args.arg(2)),
            ]),
            ("msvcrt.dll", "memset") => Some(vec![
                self.render_api_buffer_arg(0, "dest", args.arg(0), args.arg(2)),
                self.render_api_byte_arg(1, "value", args.arg(1)),
                self.render_api_size_arg(2, "count", args.arg(2)),
            ]),
            ("vcruntime140.dll", "memchr") => Some(vec![
                self.render_api_buffer_arg(0, "buffer", args.arg(0), args.arg(2)),
                self.render_api_byte_arg(1, "value", args.arg(1)),
                self.render_api_size_arg(2, "count", args.arg(2)),
            ]),
            ("kernel32.dll", "widechartomultibyte") => Some(vec![
                self.render_api_arg(0, "CodePage", ApiArgKind::UInt32, args.arg(0)),
                self.render_api_arg(1, "dwFlags", ApiArgKind::Hex32, args.arg(1)),
                self.render_api_custom_arg(
                    2,
                    "lpWideCharStr",
                    "lpwstr",
                    args.arg(2),
                    self.describe_wide_input_pointer(args.arg(2), args.arg(3)),
                ),
                self.render_api_arg(3, "cchWideChar", ApiArgKind::Int32, args.arg(3)),
                self.render_api_arg(4, "lpMultiByteStr", ApiArgKind::Ptr, args.arg(4)),
                self.render_api_arg(5, "cbMultiByte", ApiArgKind::UInt32, args.arg(5)),
                self.render_api_arg(6, "lpDefaultChar", ApiArgKind::LpStr, args.arg(6)),
                self.render_api_arg(7, "lpUsedDefaultChar", ApiArgKind::Ptr, args.arg(7)),
            ]),
            ("kernel32.dll", "multibytetowidechar") => Some(vec![
                self.render_api_arg(0, "CodePage", ApiArgKind::UInt32, args.arg(0)),
                self.render_api_arg(1, "dwFlags", ApiArgKind::Hex32, args.arg(1)),
                self.render_api_custom_arg(
                    2,
                    "lpMultiByteStr",
                    "lpstr",
                    args.arg(2),
                    self.describe_ansi_input_pointer(args.arg(2), args.arg(3), args.arg(0)),
                ),
                self.render_api_arg(3, "cbMultiByte", ApiArgKind::Int32, args.arg(3)),
                self.render_api_arg(4, "lpWideCharStr", ApiArgKind::Ptr, args.arg(4)),
                self.render_api_arg(5, "cchWideChar", ApiArgKind::Int32, args.arg(5)),
            ]),
            ("kernel32.dll", "writeconsolea") => Some(vec![
                self.render_api_arg(0, "hConsoleOutput", ApiArgKind::Ptr, args.arg(0)),
                self.render_api_custom_arg(
                    1,
                    "lpBuffer",
                    "lpstr",
                    args.arg(1),
                    self.describe_ansi_input_pointer(args.arg(1), args.arg(2), 0),
                ),
                self.render_api_arg(2, "nNumberOfCharsToWrite", ApiArgKind::UInt32, args.arg(2)),
                self.render_api_arg(3, "lpNumberOfCharsWritten", ApiArgKind::Ptr, args.arg(3)),
                self.render_api_arg(4, "lpReserved", ApiArgKind::Ptr, args.arg(4)),
            ]),
            ("kernel32.dll", "writeconsolew") => Some(vec![
                self.render_api_arg(0, "hConsoleOutput", ApiArgKind::Ptr, args.arg(0)),
                self.render_api_custom_arg(
                    1,
                    "lpBuffer",
                    "lpwstr",
                    args.arg(1),
                    self.describe_wide_counted_pointer(args.arg(1) as u64, args.arg(2) as usize),
                ),
                self.render_api_arg(2, "nNumberOfCharsToWrite", ApiArgKind::UInt32, args.arg(2)),
                self.render_api_arg(3, "lpNumberOfCharsWritten", ApiArgKind::Ptr, args.arg(3)),
                self.render_api_arg(4, "lpReserved", ApiArgKind::Ptr, args.arg(4)),
            ]),
            ("msvcrt.dll", "_seh_filter_dll") | ("msvcrt.dll", "_seh_filter_exe") => Some(vec![
                self.render_api_custom_arg(
                    0,
                    "xcptnum",
                    "exception_code",
                    args.arg(0),
                    Some(Self::format_exception_code_for_log(args.arg(0) as u32)),
                ),
                self.render_api_custom_arg(
                    1,
                    "pxcptinfoptrs",
                    "exception_pointers",
                    args.arg(1),
                    self.describe_exception_pointers_argument(args.arg(1)),
                ),
            ]),
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn describe_api_return_decoded_text(
        &self,
        target_module: &str,
        target_function: &str,
        args: &[u64],
        retval: u64,
    ) -> Option<String> {
        let module = target_module.to_ascii_lowercase();
        let function = target_function.to_ascii_lowercase();
        match (module.as_str(), function.as_str()) {
            ("kernel32.dll", "widechartomultibyte") => {
                let output = args.arg(4);
                let capacity = args.arg(5) as usize;
                if output == 0 || capacity == 0 || retval == 0 {
                    return None;
                }
                let written = (retval as usize).min(capacity);
                let bytes = self.read_bytes_from_memory(output, written).ok()?;
                let text = self.decode_code_page_bytes(args.arg(0), trim_trailing_nul(&bytes, 1));
                let text = self.sanitize_explicit_api_log_text(&text)?;
                Some(format!(
                    "lpMultiByteStr={}",
                    self.format_pointer_with_text(output, &text)
                ))
            }
            ("kernel32.dll", "multibytetowidechar") => {
                let output = args.arg(4);
                let capacity = args.arg(5) as usize;
                if output == 0 || capacity == 0 || retval == 0 {
                    return None;
                }
                let written = (retval as usize).min(capacity);
                let bytes = self
                    .read_bytes_from_memory(output, written.saturating_mul(2))
                    .ok()?;
                let text = Self::decode_utf16le_bytes_ignoring_errors(trim_trailing_nul(&bytes, 2));
                let text = self.sanitize_explicit_api_log_text(&text)?;
                Some(format!(
                    "lpWideCharStr={}",
                    self.format_pointer_with_text(output, &text)
                ))
            }
            ("msvcrt.dll", "_seh_filter_dll") | ("msvcrt.dll", "_seh_filter_exe") => Some(format!(
                "filter={}",
                Self::format_seh_filter_result_for_log(retval)
            )),
            _ => None,
        }
    }
}
