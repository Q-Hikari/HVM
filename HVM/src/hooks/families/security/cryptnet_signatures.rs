//! Full `HookSignature` table for `cryptnet.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{
    HookFlags, LogicalAbi, ParamDirection::*, ParamType::*, ParamTypeDiscriminant,
};

pub(super) static CRYPTNET_SIGNATURES: &[HookSignature] = &[
    // ── URL-based Cryptographic Retrieval ─────────────────────────────────
    HookSignature {
        module: "cryptnet.dll",
        function: "CryptRetrieveObjectByUrlA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszUrl", PCStr),
            ParamSpec::new("pszObjectOid", GuestPtr),
            ParamSpec::new("dwRetrievalFlags", Hex32),
            ParamSpec::new("dwTimeout", U32),
            ParamSpec::with_dir("ppvObject", GuestPtr, Out),
            ParamSpec::new("hAsyncRetrieve", Handle),
            ParamSpec::new("pCredentials", GuestPtr),
            ParamSpec::new("pvVerify", GuestPtr),
            ParamSpec::new("pAuxInfo", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptnet.dll",
        function: "CryptRetrieveObjectByUrlW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszUrl", PCWStr),
            ParamSpec::new("pszObjectOid", GuestPtr),
            ParamSpec::new("dwRetrievalFlags", Hex32),
            ParamSpec::new("dwTimeout", U32),
            ParamSpec::with_dir("ppvObject", GuestPtr, Out),
            ParamSpec::new("hAsyncRetrieve", Handle),
            ParamSpec::new("pCredentials", GuestPtr),
            ParamSpec::new("pvVerify", GuestPtr),
            ParamSpec::new("pAuxInfo", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Object URL Retrieval ──────────────────────────────────────────────
    HookSignature {
        module: "cryptnet.dll",
        function: "CryptGetObjectUrl",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszUrlOid", GuestPtr),
            ParamSpec::new("pvPara", GuestPtr),
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::with_dir("pUrlArray", GuestPtr, Out),
            ParamSpec::with_dir("pcbUrlArray", GuestPtrTo(ParamTypeDiscriminant::U32), InOut),
            ParamSpec::with_dir("pUrlInfo", GuestPtr, Out),
            ParamSpec::with_dir("pcbUrlInfo", GuestPtrTo(ParamTypeDiscriminant::U32), InOut),
            ParamSpec::new("pvReserved", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Time-Valid Object Retrieval ───────────────────────────────────────
    HookSignature {
        module: "cryptnet.dll",
        function: "CryptGetTimeValidObject",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszTimeValidOid", GuestPtr),
            ParamSpec::new("pvPara", GuestPtr),
            ParamSpec::new("hIssuerCert", Handle),
            ParamSpec::new("pftValidFor", FileTimePtr),
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("dwTimeout", U32),
            ParamSpec::with_dir("ppObject", GuestPtr, Out),
            ParamSpec::new("pCredentials", GuestPtr),
            ParamSpec::new("pExtraInfo", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
