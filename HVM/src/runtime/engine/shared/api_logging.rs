use super::*;
use crate::runtime::engine::logging_helpers::{
    spec, trim_trailing_nul, ApiArgKind, ApiParameterSpec,
};

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn api_parameter_specs(
        module: &str,
        function: &str,
    ) -> Vec<ApiParameterSpec> {
        let module = module.to_ascii_lowercase();
        let function = function.to_ascii_lowercase();
        match (module.as_str(), function.as_str()) {
            ("kernel32.dll", "loadlibrarya") => vec![spec("lpLibFileName", ApiArgKind::LpStr)],
            ("kernel32.dll", "loadlibraryw") => vec![spec("lpLibFileName", ApiArgKind::LpWStr)],
            ("kernel32.dll", "loadlibraryexa") => vec![
                spec("lpLibFileName", ApiArgKind::LpStr),
                spec("hFile", ApiArgKind::Ptr),
                spec("dwFlags", ApiArgKind::Hex32),
            ],
            ("kernel32.dll", "loadlibraryexw") => vec![
                spec("lpLibFileName", ApiArgKind::LpWStr),
                spec("hFile", ApiArgKind::Ptr),
                spec("dwFlags", ApiArgKind::Hex32),
            ],
            ("kernel32.dll", "getmodulehandlea") => vec![spec("lpModuleName", ApiArgKind::LpStr)],
            ("kernel32.dll", "getmodulehandlew") => vec![spec("lpModuleName", ApiArgKind::LpWStr)],
            ("kernel32.dll", "getprocaddress") => vec![
                spec("hModule", ApiArgKind::Module),
                spec("lpProcName", ApiArgKind::ProcName),
            ],
            ("kernel32.dll", "createfilea") => vec![
                spec("lpFileName", ApiArgKind::LpStr),
                spec("dwDesiredAccess", ApiArgKind::Hex32),
                spec("dwShareMode", ApiArgKind::Hex32),
                spec("lpSecurityAttributes", ApiArgKind::Ptr),
                spec("dwCreationDisposition", ApiArgKind::UInt32),
                spec("dwFlagsAndAttributes", ApiArgKind::Hex32),
                spec("hTemplateFile", ApiArgKind::Ptr),
            ],
            ("kernel32.dll", "createfilew") => vec![
                spec("lpFileName", ApiArgKind::LpWStr),
                spec("dwDesiredAccess", ApiArgKind::Hex32),
                spec("dwShareMode", ApiArgKind::Hex32),
                spec("lpSecurityAttributes", ApiArgKind::Ptr),
                spec("dwCreationDisposition", ApiArgKind::UInt32),
                spec("dwFlagsAndAttributes", ApiArgKind::Hex32),
                spec("hTemplateFile", ApiArgKind::Ptr),
            ],
            ("kernel32.dll", "createprocessa") => vec![
                spec("lpApplicationName", ApiArgKind::LpStr),
                spec("lpCommandLine", ApiArgKind::LpStr),
                spec("lpProcessAttributes", ApiArgKind::Ptr),
                spec("lpThreadAttributes", ApiArgKind::Ptr),
                spec("bInheritHandles", ApiArgKind::Bool),
                spec("dwCreationFlags", ApiArgKind::Hex32),
                spec("lpEnvironment", ApiArgKind::Ptr),
                spec("lpCurrentDirectory", ApiArgKind::LpStr),
                spec("lpStartupInfo", ApiArgKind::Ptr),
                spec("lpProcessInformation", ApiArgKind::Ptr),
            ],
            ("kernel32.dll", "createprocessw") => vec![
                spec("lpApplicationName", ApiArgKind::LpWStr),
                spec("lpCommandLine", ApiArgKind::LpWStr),
                spec("lpProcessAttributes", ApiArgKind::Ptr),
                spec("lpThreadAttributes", ApiArgKind::Ptr),
                spec("bInheritHandles", ApiArgKind::Bool),
                spec("dwCreationFlags", ApiArgKind::Hex32),
                spec("lpEnvironment", ApiArgKind::Ptr),
                spec("lpCurrentDirectory", ApiArgKind::LpWStr),
                spec("lpStartupInfo", ApiArgKind::Ptr),
                spec("lpProcessInformation", ApiArgKind::Ptr),
            ],
            ("kernel32.dll", "createmutexa") => vec![
                spec("lpMutexAttributes", ApiArgKind::Ptr),
                spec("bInitialOwner", ApiArgKind::Bool),
                spec("lpName", ApiArgKind::LpStr),
            ],
            ("kernel32.dll", "createmutexw") => vec![
                spec("lpMutexAttributes", ApiArgKind::Ptr),
                spec("bInitialOwner", ApiArgKind::Bool),
                spec("lpName", ApiArgKind::LpWStr),
            ],
            ("kernel32.dll", "createthread") => vec![
                spec("lpThreadAttributes", ApiArgKind::Ptr),
                spec("dwStackSize", ApiArgKind::UInt32),
                spec("lpStartAddress", ApiArgKind::Ptr),
                spec("lpParameter", ApiArgKind::Ptr),
                spec("dwCreationFlags", ApiArgKind::Hex32),
                spec("lpThreadId", ApiArgKind::Ptr),
            ],
            ("kernel32.dll", "resumethread") => vec![spec("hThread", ApiArgKind::Ptr)],
            ("kernel32.dll", "outputdebugstringa") => {
                vec![spec("lpOutputString", ApiArgKind::LpStr)]
            }
            ("kernel32.dll", "outputdebugstringw") => {
                vec![spec("lpOutputString", ApiArgKind::LpWStr)]
            }
            ("kernel32.dll", "lstrlena") => vec![spec("lpString", ApiArgKind::LpStr)],
            ("kernel32.dll", "lstrlenw") => vec![spec("lpString", ApiArgKind::LpWStr)],
            ("advapi32.dll", "regopenkeyexa") => vec![
                spec("hKey", ApiArgKind::Ptr),
                spec("lpSubKey", ApiArgKind::LpStr),
                spec("ulOptions", ApiArgKind::Hex32),
                spec("samDesired", ApiArgKind::Hex32),
                spec("phkResult", ApiArgKind::Ptr),
            ],
            ("advapi32.dll", "regopenkeyexw") => vec![
                spec("hKey", ApiArgKind::Ptr),
                spec("lpSubKey", ApiArgKind::LpWStr),
                spec("ulOptions", ApiArgKind::Hex32),
                spec("samDesired", ApiArgKind::Hex32),
                spec("phkResult", ApiArgKind::Ptr),
            ],
            ("advapi32.dll", "regcreatekeyexa") => vec![
                spec("hKey", ApiArgKind::Ptr),
                spec("lpSubKey", ApiArgKind::LpStr),
                spec("Reserved", ApiArgKind::Hex32),
                spec("lpClass", ApiArgKind::LpStr),
                spec("dwOptions", ApiArgKind::Hex32),
                spec("samDesired", ApiArgKind::Hex32),
                spec("lpSecurityAttributes", ApiArgKind::Ptr),
                spec("phkResult", ApiArgKind::Ptr),
                spec("lpdwDisposition", ApiArgKind::Ptr),
            ],
            ("advapi32.dll", "regcreatekeyexw") => vec![
                spec("hKey", ApiArgKind::Ptr),
                spec("lpSubKey", ApiArgKind::LpWStr),
                spec("Reserved", ApiArgKind::Hex32),
                spec("lpClass", ApiArgKind::LpWStr),
                spec("dwOptions", ApiArgKind::Hex32),
                spec("samDesired", ApiArgKind::Hex32),
                spec("lpSecurityAttributes", ApiArgKind::Ptr),
                spec("phkResult", ApiArgKind::Ptr),
                spec("lpdwDisposition", ApiArgKind::Ptr),
            ],
            ("advapi32.dll", "regqueryvalueexa") => vec![
                spec("hKey", ApiArgKind::Ptr),
                spec("lpValueName", ApiArgKind::LpStr),
                spec("lpReserved", ApiArgKind::Ptr),
                spec("lpType", ApiArgKind::Ptr),
                spec("lpData", ApiArgKind::Ptr),
                spec("lpcbData", ApiArgKind::Ptr),
            ],
            ("advapi32.dll", "regqueryvalueexw") => vec![
                spec("hKey", ApiArgKind::Ptr),
                spec("lpValueName", ApiArgKind::LpWStr),
                spec("lpReserved", ApiArgKind::Ptr),
                spec("lpType", ApiArgKind::Ptr),
                spec("lpData", ApiArgKind::Ptr),
                spec("lpcbData", ApiArgKind::Ptr),
            ],
            ("ntdll.dll", "rtlinitunicodestring") => vec![
                spec("DestinationString", ApiArgKind::Ptr),
                spec("SourceString", ApiArgKind::LpWStr),
            ],
            ("ntdll.dll", "ldrgetprocedureaddress") => vec![
                spec("ModuleHandle", ApiArgKind::Module),
                spec("FunctionName", ApiArgKind::AnsiStringPtr),
                spec("Ordinal", ApiArgKind::UInt32),
                spec("FunctionAddress", ApiArgKind::Ptr),
            ],
            ("ntdll.dll", "ldrloaddll") => vec![
                spec("SearchPath", ApiArgKind::Ptr),
                spec("LoadFlags", ApiArgKind::Ptr),
                spec("ModuleFileName", ApiArgKind::UnicodeStringPtr),
                spec("ModuleHandle", ApiArgKind::Ptr),
            ],
            ("user32.dll", "messageboxa") => vec![
                spec("hWnd", ApiArgKind::Ptr),
                spec("lpText", ApiArgKind::LpStr),
                spec("lpCaption", ApiArgKind::LpStr),
                spec("uType", ApiArgKind::Hex32),
            ],
            ("user32.dll", "messageboxw") => vec![
                spec("hWnd", ApiArgKind::Ptr),
                spec("lpText", ApiArgKind::LpWStr),
                spec("lpCaption", ApiArgKind::LpWStr),
                spec("uType", ApiArgKind::Hex32),
            ],
            ("user32.dll", "findwindowa") => vec![
                spec("lpClassName", ApiArgKind::LpStr),
                spec("lpWindowName", ApiArgKind::LpStr),
            ],
            ("user32.dll", "findwindoww") => vec![
                spec("lpClassName", ApiArgKind::LpWStr),
                spec("lpWindowName", ApiArgKind::LpWStr),
            ],
            ("user32.dll", "createwindowexa") => vec![
                spec("dwExStyle", ApiArgKind::Hex32),
                spec("lpClassName", ApiArgKind::LpStr),
                spec("lpWindowName", ApiArgKind::LpStr),
            ],
            ("user32.dll", "createwindowexw") => vec![
                spec("dwExStyle", ApiArgKind::Hex32),
                spec("lpClassName", ApiArgKind::LpWStr),
                spec("lpWindowName", ApiArgKind::LpWStr),
            ],
            ("shell32.dll", "commandlinetoargvw") => vec![
                spec("lpCmdLine", ApiArgKind::LpWStr),
                spec("pNumArgs", ApiArgKind::Ptr),
            ],
            ("shell32.dll", "shellexecutea") => vec![
                spec("hwnd", ApiArgKind::Ptr),
                spec("lpOperation", ApiArgKind::LpStr),
                spec("lpFile", ApiArgKind::LpStr),
                spec("lpParameters", ApiArgKind::LpStr),
                spec("lpDirectory", ApiArgKind::LpStr),
                spec("nShowCmd", ApiArgKind::Int32),
            ],
            ("shell32.dll", "shellexecutew") => vec![
                spec("hwnd", ApiArgKind::Ptr),
                spec("lpOperation", ApiArgKind::LpWStr),
                spec("lpFile", ApiArgKind::LpWStr),
                spec("lpParameters", ApiArgKind::LpWStr),
                spec("lpDirectory", ApiArgKind::LpWStr),
                spec("nShowCmd", ApiArgKind::Int32),
            ],
            ("ws2_32.dll", "inet_addr") => vec![spec("cp", ApiArgKind::LpStr)],
            ("ws2_32.dll", "gethostbyname") => vec![spec("name", ApiArgKind::LpStr)],
            ("ws2_32.dll", "getaddrinfo") => vec![
                spec("pNodeName", ApiArgKind::LpStr),
                spec("pServiceName", ApiArgKind::LpStr),
                spec("pHints", ApiArgKind::Ptr),
                spec("ppResult", ApiArgKind::Ptr),
            ],
            ("wininet.dll", "internetopena") => vec![
                spec("lpszAgent", ApiArgKind::LpStr),
                spec("dwAccessType", ApiArgKind::UInt32),
                spec("lpszProxy", ApiArgKind::LpStr),
                spec("lpszProxyBypass", ApiArgKind::LpStr),
                spec("dwFlags", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "internetopenw") => vec![
                spec("lpszAgent", ApiArgKind::LpWStr),
                spec("dwAccessType", ApiArgKind::UInt32),
                spec("lpszProxy", ApiArgKind::LpWStr),
                spec("lpszProxyBypass", ApiArgKind::LpWStr),
                spec("dwFlags", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "internetconnecta") => vec![
                spec("hInternet", ApiArgKind::Ptr),
                spec("lpszServerName", ApiArgKind::LpStr),
                spec("nServerPort", ApiArgKind::UInt32),
                spec("lpszUserName", ApiArgKind::LpStr),
                spec("lpszPassword", ApiArgKind::LpStr),
                spec("dwService", ApiArgKind::UInt32),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "internetconnectw") => vec![
                spec("hInternet", ApiArgKind::Ptr),
                spec("lpszServerName", ApiArgKind::LpWStr),
                spec("nServerPort", ApiArgKind::UInt32),
                spec("lpszUserName", ApiArgKind::LpWStr),
                spec("lpszPassword", ApiArgKind::LpWStr),
                spec("dwService", ApiArgKind::UInt32),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "internetopenurla") => vec![
                spec("hInternet", ApiArgKind::Ptr),
                spec("lpszUrl", ApiArgKind::LpStr),
                spec("lpszHeaders", ApiArgKind::LpStr),
                spec("dwHeadersLength", ApiArgKind::UInt32),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "internetopenurlw") => vec![
                spec("hInternet", ApiArgKind::Ptr),
                spec("lpszUrl", ApiArgKind::LpWStr),
                spec("lpszHeaders", ApiArgKind::LpWStr),
                spec("dwHeadersLength", ApiArgKind::UInt32),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "httpopenrequesta") => vec![
                spec("hConnect", ApiArgKind::Ptr),
                spec("lpszVerb", ApiArgKind::LpStr),
                spec("lpszObjectName", ApiArgKind::LpStr),
                spec("lpszVersion", ApiArgKind::LpStr),
                spec("lpszReferrer", ApiArgKind::LpStr),
                spec("lplpszAcceptTypes", ApiArgKind::Ptr),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "httpopenrequestw") => vec![
                spec("hConnect", ApiArgKind::Ptr),
                spec("lpszVerb", ApiArgKind::LpWStr),
                spec("lpszObjectName", ApiArgKind::LpWStr),
                spec("lpszVersion", ApiArgKind::LpWStr),
                spec("lpszReferrer", ApiArgKind::LpWStr),
                spec("lplpszAcceptTypes", ApiArgKind::Ptr),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("wininet.dll", "httpsendrequesta") => vec![
                spec("hRequest", ApiArgKind::Ptr),
                spec("lpszHeaders", ApiArgKind::LpStr),
                spec("dwHeadersLength", ApiArgKind::UInt32),
                spec("lpOptional", ApiArgKind::Ptr),
                spec("dwOptionalLength", ApiArgKind::UInt32),
            ],
            ("wininet.dll", "httpsendrequestw") => vec![
                spec("hRequest", ApiArgKind::Ptr),
                spec("lpszHeaders", ApiArgKind::LpWStr),
                spec("dwHeadersLength", ApiArgKind::UInt32),
                spec("lpOptional", ApiArgKind::Ptr),
                spec("dwOptionalLength", ApiArgKind::UInt32),
            ],
            ("winhttp.dll", "winhttpopen") => vec![
                spec("pszAgentW", ApiArgKind::LpWStr),
                spec("dwAccessType", ApiArgKind::UInt32),
                spec("pszProxyW", ApiArgKind::LpWStr),
                spec("pszProxyBypassW", ApiArgKind::LpWStr),
                spec("dwFlags", ApiArgKind::Hex32),
            ],
            ("winhttp.dll", "winhttpconnect") => vec![
                spec("hSession", ApiArgKind::Ptr),
                spec("pswzServerName", ApiArgKind::LpWStr),
                spec("nServerPort", ApiArgKind::UInt32),
                spec("dwReserved", ApiArgKind::Hex32),
            ],
            ("winhttp.dll", "winhttpopenrequest") => vec![
                spec("hConnect", ApiArgKind::Ptr),
                spec("pwszVerb", ApiArgKind::LpWStr),
                spec("pwszObjectName", ApiArgKind::LpWStr),
                spec("pwszVersion", ApiArgKind::LpWStr),
                spec("pwszReferrer", ApiArgKind::LpWStr),
                spec("ppwszAcceptTypes", ApiArgKind::Ptr),
                spec("dwFlags", ApiArgKind::Hex32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("winhttp.dll", "winhttpaddrequestheaders") => vec![
                spec("hRequest", ApiArgKind::Ptr),
                spec("lpszHeaders", ApiArgKind::LpWStr),
                spec("dwHeadersLength", ApiArgKind::UInt32),
                spec("dwModifiers", ApiArgKind::Hex32),
            ],
            ("winhttp.dll", "winhttpsendrequest") => vec![
                spec("hRequest", ApiArgKind::Ptr),
                spec("lpszHeaders", ApiArgKind::LpWStr),
                spec("dwHeadersLength", ApiArgKind::UInt32),
                spec("lpOptional", ApiArgKind::Ptr),
                spec("dwOptionalLength", ApiArgKind::UInt32),
                spec("dwTotalLength", ApiArgKind::UInt32),
                spec("dwContext", ApiArgKind::Hex32),
            ],
            ("winhttp.dll", "winhttpgetproxyforurl") => vec![
                spec("hSession", ApiArgKind::Ptr),
                spec("lpcwszUrl", ApiArgKind::LpWStr),
                spec("pAutoProxyOptions", ApiArgKind::Ptr),
                spec("pProxyInfo", ApiArgKind::Ptr),
            ],
            ("crypt32.dll", "certopensystemstorew") => vec![
                spec("hProv", ApiArgKind::Ptr),
                spec("szSubsystemProtocol", ApiArgKind::LpWStr),
            ],
            _ => Vec::new(),
        }
    }

    pub(in crate::runtime::engine) fn describe_custom_api_call_args(
        &self,
        definition: &HookDefinition,
        args: &[u64],
    ) -> Option<Vec<ApiLogArg>> {
        let module = definition.module.to_ascii_lowercase();
        let function = definition.function.to_ascii_lowercase();
        match (module.as_str(), function.as_str()) {
            ("msvcrt.dll", "memcmp") => Some(vec![
                self.render_api_buffer_arg(0, "lhs", arg(args, 0), arg(args, 2)),
                self.render_api_buffer_arg(1, "rhs", arg(args, 1), arg(args, 2)),
                self.render_api_size_arg(2, "count", arg(args, 2)),
            ]),
            ("msvcrt.dll", "memmove")
            | ("msvcrt.dll", "memcpy")
            | ("vcruntime140.dll", "memcpy") => Some(vec![
                self.render_api_buffer_arg(0, "dest", arg(args, 0), arg(args, 2)),
                self.render_api_buffer_arg(1, "src", arg(args, 1), arg(args, 2)),
                self.render_api_size_arg(2, "count", arg(args, 2)),
            ]),
            ("msvcrt.dll", "memset") => Some(vec![
                self.render_api_buffer_arg(0, "dest", arg(args, 0), arg(args, 2)),
                self.render_api_byte_arg(1, "value", arg(args, 1)),
                self.render_api_size_arg(2, "count", arg(args, 2)),
            ]),
            ("vcruntime140.dll", "memchr") => Some(vec![
                self.render_api_buffer_arg(0, "buffer", arg(args, 0), arg(args, 2)),
                self.render_api_byte_arg(1, "value", arg(args, 1)),
                self.render_api_size_arg(2, "count", arg(args, 2)),
            ]),
            ("kernel32.dll", "widechartomultibyte") => Some(vec![
                self.render_api_arg(0, "CodePage", ApiArgKind::UInt32, arg(args, 0)),
                self.render_api_arg(1, "dwFlags", ApiArgKind::Hex32, arg(args, 1)),
                self.render_api_custom_arg(
                    2,
                    "lpWideCharStr",
                    "lpwstr",
                    arg(args, 2),
                    self.describe_wide_input_pointer(arg(args, 2), arg(args, 3)),
                ),
                self.render_api_arg(3, "cchWideChar", ApiArgKind::Int32, arg(args, 3)),
                self.render_api_arg(4, "lpMultiByteStr", ApiArgKind::Ptr, arg(args, 4)),
                self.render_api_arg(5, "cbMultiByte", ApiArgKind::UInt32, arg(args, 5)),
                self.render_api_arg(6, "lpDefaultChar", ApiArgKind::LpStr, arg(args, 6)),
                self.render_api_arg(7, "lpUsedDefaultChar", ApiArgKind::Ptr, arg(args, 7)),
            ]),
            ("kernel32.dll", "multibytetowidechar") => Some(vec![
                self.render_api_arg(0, "CodePage", ApiArgKind::UInt32, arg(args, 0)),
                self.render_api_arg(1, "dwFlags", ApiArgKind::Hex32, arg(args, 1)),
                self.render_api_custom_arg(
                    2,
                    "lpMultiByteStr",
                    "lpstr",
                    arg(args, 2),
                    self.describe_ansi_input_pointer(arg(args, 2), arg(args, 3), arg(args, 0)),
                ),
                self.render_api_arg(3, "cbMultiByte", ApiArgKind::Int32, arg(args, 3)),
                self.render_api_arg(4, "lpWideCharStr", ApiArgKind::Ptr, arg(args, 4)),
                self.render_api_arg(5, "cchWideChar", ApiArgKind::Int32, arg(args, 5)),
            ]),
            ("kernel32.dll", "writeconsolea") => Some(vec![
                self.render_api_arg(0, "hConsoleOutput", ApiArgKind::Ptr, arg(args, 0)),
                self.render_api_custom_arg(
                    1,
                    "lpBuffer",
                    "lpstr",
                    arg(args, 1),
                    self.describe_ansi_input_pointer(arg(args, 1), arg(args, 2), 0),
                ),
                self.render_api_arg(2, "nNumberOfCharsToWrite", ApiArgKind::UInt32, arg(args, 2)),
                self.render_api_arg(3, "lpNumberOfCharsWritten", ApiArgKind::Ptr, arg(args, 3)),
                self.render_api_arg(4, "lpReserved", ApiArgKind::Ptr, arg(args, 4)),
            ]),
            ("kernel32.dll", "writeconsolew") => Some(vec![
                self.render_api_arg(0, "hConsoleOutput", ApiArgKind::Ptr, arg(args, 0)),
                self.render_api_custom_arg(
                    1,
                    "lpBuffer",
                    "lpwstr",
                    arg(args, 1),
                    self.describe_wide_counted_pointer(arg(args, 1) as u64, arg(args, 2) as usize),
                ),
                self.render_api_arg(2, "nNumberOfCharsToWrite", ApiArgKind::UInt32, arg(args, 2)),
                self.render_api_arg(3, "lpNumberOfCharsWritten", ApiArgKind::Ptr, arg(args, 3)),
                self.render_api_arg(4, "lpReserved", ApiArgKind::Ptr, arg(args, 4)),
            ]),
            ("msvcrt.dll", "_seh_filter_dll") | ("msvcrt.dll", "_seh_filter_exe") => Some(vec![
                self.render_api_custom_arg(
                    0,
                    "xcptnum",
                    "exception_code",
                    arg(args, 0),
                    Some(Self::format_exception_code_for_log(arg(args, 0) as u32)),
                ),
                self.render_api_custom_arg(
                    1,
                    "pxcptinfoptrs",
                    "exception_pointers",
                    arg(args, 1),
                    self.describe_exception_pointers_argument(arg(args, 1)),
                ),
            ]),
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn describe_api_return_decoded_text(
        &self,
        definition: &HookDefinition,
        args: &[u64],
        retval: u64,
    ) -> Option<String> {
        let module = definition.module.to_ascii_lowercase();
        let function = definition.function.to_ascii_lowercase();
        match (module.as_str(), function.as_str()) {
            ("kernel32.dll", "widechartomultibyte") => {
                let output = arg(args, 4);
                let capacity = arg(args, 5) as usize;
                if output == 0 || capacity == 0 || retval == 0 {
                    return None;
                }
                let written = (retval as usize).min(capacity);
                let bytes = self.read_bytes_from_memory(output, written).ok()?;
                let text = self.decode_code_page_bytes(arg(args, 0), trim_trailing_nul(&bytes, 1));
                let text = self.sanitize_explicit_api_log_text(&text)?;
                Some(format!(
                    "lpMultiByteStr={}",
                    self.format_pointer_with_text(output, &text)
                ))
            }
            ("kernel32.dll", "multibytetowidechar") => {
                let output = arg(args, 4);
                let capacity = arg(args, 5) as usize;
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
