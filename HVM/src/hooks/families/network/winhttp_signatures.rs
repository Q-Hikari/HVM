//! Full `HookSignature` table for `winhttp.dll` functions.
//!
//! Covers WinHTTP API: session management, connection, HTTP requests,
//! data transfer, proxy configuration, and option management.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static WINHTTP_SIGNATURES: &[HookSignature] = &[
    // ── Session Initialization ────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpOpen",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszAgentW", PCWStr),
            ParamSpec::new("dwAccessType", U32),
            ParamSpec::new("pszProxyW", PCWStr),
            ParamSpec::new("pszProxyBypassW", PCWStr),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    // ── Connection Management ─────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpConnect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hSession", Handle),
            ParamSpec::new("pswzServerName", PCWStr),
            ParamSpec::new("nServerPort", U16),
            ParamSpec::new("dwReserved", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    // ── HTTP Request ──────────────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpOpenRequest",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hConnect", Handle),
            ParamSpec::new("pwszVerb", PCWStr),
            ParamSpec::new("pwszObjectName", PCWStr),
            ParamSpec::new("pwszVersion", PCWStr),
            ParamSpec::new("pwszReferrer", PCWStr),
            ParamSpec::new("ppwszAcceptTypes", GuestPtr),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpAddRequestHeaders",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::new("pwszHeaders", PCWStr),
            ParamSpec::new("dwHeadersLength", U32),
            ParamSpec::new("dwModifiers", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpSendRequest",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::new("pwszHeaders", PCWStr),
            ParamSpec::new("dwHeadersLength", U32),
            ParamSpec::new("lpOptional", GuestPtr),
            ParamSpec::new("dwOptionalLength", U32),
            ParamSpec::new("dwTotalLength", U32),
            ParamSpec::new("dwContext", PointerSizedUInt),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Data Transfer ─────────────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpWriteData",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::new("lpBuffer", GuestPtr),
            ParamSpec::new("dwNumberOfBytesToWrite", U32),
            ParamSpec::with_dir("lpdwNumberOfBytesWritten", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpReceiveResponse",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::new("lpReserved", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpReadData",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::new("lpBuffer", GuestPtr),
            ParamSpec::new("dwNumberOfBytesToRead", U32),
            ParamSpec::with_dir("lpdwNumberOfBytesRead", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Data Query ────────────────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpQueryDataAvailable",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::with_dir("lpdwNumberOfBytesAvailable", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpQueryHeaders",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRequest", Handle),
            ParamSpec::new("dwInfoLevel", U32),
            ParamSpec::new("pwszName", PCWStr),
            ParamSpec::new("lpBuffer", GuestPtr),
            ParamSpec::with_dir("lpdwBufferLength", GuestPtr, InOut),
            ParamSpec::with_dir("lpdwIndex", GuestPtr, InOut),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Options ───────────────────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpSetOption",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hInternet", Handle),
            ParamSpec::new("dwOption", U32),
            ParamSpec::new("lpBuffer", GuestPtr),
            ParamSpec::new("dwBufferLength", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpQueryOption",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hInternet", Handle),
            ParamSpec::new("dwOption", U32),
            ParamSpec::new("lpBuffer", GuestPtr),
            ParamSpec::with_dir("lpdwBufferLength", GuestPtr, InOut),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Timeouts ──────────────────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpSetTimeouts",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hInternet", Handle),
            ParamSpec::new("dwResolveTimeout", I32),
            ParamSpec::new("dwConnectTimeout", I32),
            ParamSpec::new("dwSendTimeout", I32),
            ParamSpec::new("dwReceiveTimeout", I32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Proxy Configuration ───────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpGetIEProxyConfigForCurrentUser",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::with_dir("pProxyConfig", GuestPtr, Out)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpGetProxyForUrl",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hSession", Handle),
            ParamSpec::new("lpcwszUrl", PCWStr),
            ParamSpec::new("pAutoProxyOptions", GuestPtr),
            ParamSpec::with_dir("pProxyInfo", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Handle Management ─────────────────────────────────────────────────
    HookSignature {
        module: "winhttp.dll",
        function: "WinHttpCloseHandle",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hInternet", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
