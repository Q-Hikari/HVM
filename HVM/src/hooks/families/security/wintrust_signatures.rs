//! Full `HookSignature` table for `wintrust.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{
    HookFlags, LogicalAbi, ParamDirection::*, ParamType::*, ParamTypeDiscriminant,
};

pub(super) static WINTRUST_SIGNATURES: &[HookSignature] = &[
    // ── Trust Verification ────────────────────────────────────────────────
    HookSignature {
        module: "wintrust.dll",
        function: "WinVerifyTrust",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("pgActionID", GuidPtr),
            ParamSpec::new("pWVTData", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "WinVerifyTrustEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("pgActionID", GuidPtr),
            ParamSpec::new("pWinTrustData", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Catalog Administration ────────────────────────────────────────────
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminAcquireContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("phCatAdmin", GuestPtr, Out),
            ParamSpec::new("pgSubsystem", GuidPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminAcquireContext2",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("phCatAdmin", GuestPtr, Out),
            ParamSpec::new("pgSubsystem", GuidPtr),
            ParamSpec::new("pwszHashAlgorithm", PCWStr),
            ParamSpec::new("pStrongHashPolicy", GuestPtr),
            ParamSpec::new("dwFlags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminReleaseContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCatAdmin", Handle),
            ParamSpec::new("dwFlags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminCalcHashFromFileHandle",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hFile", Handle),
            ParamSpec::with_dir("pcbHash", GuestPtrTo(ParamTypeDiscriminant::U32), InOut),
            ParamSpec::with_dir("pbHash", GuestPtr, Out),
            ParamSpec::new("dwFlags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminCalcHashFromFileHandle2",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCatAdmin", Handle),
            ParamSpec::new("hFile", Handle),
            ParamSpec::with_dir("pcbHash", GuestPtrTo(ParamTypeDiscriminant::U32), InOut),
            ParamSpec::with_dir("pbHash", GuestPtr, Out),
            ParamSpec::new("dwFlags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminEnumCatalogFromHash",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCatAdmin", Handle),
            ParamSpec::new("pbHash", GuestPtr),
            ParamSpec::new("cbHash", U32),
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::with_dir("phCatInfo", GuestPtr, Out),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATCatalogInfoFromContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCatInfo", Handle),
            ParamSpec::with_dir("psCatInfo", GuestPtr, Out),
            ParamSpec::new("dwFlags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATAdminReleaseCatalogContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCatAdmin", Handle),
            ParamSpec::new("hCatInfo", Handle),
            ParamSpec::new("dwFlags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Trust Helper Functions ────────────────────────────────────────────
    HookSignature {
        module: "wintrust.dll",
        function: "WTHelperProvDataFromStateData",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hStateData", Handle)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "WTHelperGetProvSignerFromChain",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pProvData", GuestPtr),
            ParamSpec::new("idxSigner", U32),
            ParamSpec::new("fCounterSigner", Bool32),
            ParamSpec::new("idxCounterSigner", U32),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "WTHelperGetProvCertFromChain",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pSgnr", GuestPtr),
            ParamSpec::new("idxCert", U32),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Catalog Store ─────────────────────────────────────────────────────
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATOpen",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pwszFilePath", PCWStr),
            ParamSpec::new("fdwOpenFlags", Hex32),
            ParamSpec::new("hProv", Handle),
            ParamSpec::new("dwPublicVersion", Hex32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATClose",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hCatalog", Handle)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATEnumerateMember",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCatalog", Handle),
            ParamSpec::new("pPrevMember", GuestPtr),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wintrust.dll",
        function: "CryptCATStoreFromHandle",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hCatalog", Handle)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
];
