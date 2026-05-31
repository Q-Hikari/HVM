//! Full `HookSignature` table for `dnsapi.dll` functions.
//!
//! Covers DNS Client API: query, record management, name comparison,
// validation, and cache control.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static DNSAPI_SIGNATURES: &[HookSignature] = &[
    // ── DNS Query ─────────────────────────────────────────────────────────
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsQuery_A",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName", PCStr),
            ParamSpec::new("wType", U16),
            ParamSpec::new("Options", U32),
            ParamSpec::new("pExtra", GuestPtr),
            ParamSpec::new("ppQueryResults", GuestPtr),
            ParamSpec::new("pReserved", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsQuery_W",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName", PCWStr),
            ParamSpec::new("wType", U16),
            ParamSpec::new("Options", U32),
            ParamSpec::new("pExtra", GuestPtr),
            ParamSpec::new("ppQueryResults", GuestPtr),
            ParamSpec::new("pReserved", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsQuery_UTF8",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName", PCStr),
            ParamSpec::new("wType", U16),
            ParamSpec::new("Options", U32),
            ParamSpec::new("pExtra", GuestPtr),
            ParamSpec::new("ppQueryResults", GuestPtr),
            ParamSpec::new("pReserved", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Record List Free ──────────────────────────────────────────────────
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsRecordListFree",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pRecordList", GuestPtr),
            ParamSpec::new("FreeType", U32),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsFree",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pData", GuestPtr),
            ParamSpec::new("FreeType", U32),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    // ── Name Comparison ───────────────────────────────────────────────────
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsNameCompare_A",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName1", PCStr),
            ParamSpec::new("pszName2", PCStr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsNameCompare_W",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName1", PCWStr),
            ParamSpec::new("pszName2", PCWStr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Name Validation ───────────────────────────────────────────────────
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsValidateName_A",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName", PCStr),
            ParamSpec::new("Format", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsValidateName_W",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszName", PCWStr),
            ParamSpec::new("Format", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Cache Control ─────────────────────────────────────────────────────
    HookSignature {
        module: "dnsapi.dll",
        function: "DnsFlushResolverCache",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
