//! Full `HookSignature` table for `cryptui.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static CRYPTUI_SIGNATURES: &[HookSignature] = &[
    // ── Certificate UI Dialogs ────────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgViewContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwContextType", U32),
            ParamSpec::new("pvContext", GuestPtr),
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("pwszTitle", PCWStr),
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("pvReserved", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgSelectCertificateFromStore",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hCertStore", Handle),
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("pwszTitle", PCWStr),
            ParamSpec::new("pwszDisplayString", PCWStr),
            ParamSpec::new("dwDontUseColumn", Hex32),
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("pvReserved", GuestPtr),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgSelectCertificateA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertSelectInfo", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgSelectCertificateW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertSelectInfo", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Store Selection Dialogs ───────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgSelectStoreA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pStoreSelectInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgSelectStoreW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pStoreSelectInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Certificate Manager ───────────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgCertMgr",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertMgrInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Certificate View Dialogs ──────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgViewCertificateA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pCertViewInfo", GuestPtr),
            ParamSpec::new("pfPropertiesChanged", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgViewCertificateW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pCertViewInfo", GuestPtr),
            ParamSpec::new("pfPropertiesChanged", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Certificate Properties Pages ──────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgViewCertificatePropertiesA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertViewPropertiesInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIDlgViewCertificatePropertiesW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertViewPropertiesInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIGetCertificatePropertiesPagesA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertViewPropertiesInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIGetCertificatePropertiesPagesW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCertViewPropertiesInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Signature View Pages ──────────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIGetViewSignaturesPagesA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pSigViewInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIGetViewSignaturesPagesW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pSigViewInfo", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Digital Signing Wizard ────────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIWizDigitalSign",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("pwszWizardTitle", PCWStr),
            ParamSpec::new("pDigitalSignInfo", GuestPtr),
            ParamSpec::with_dir("ppSignContext", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIWizFreeDigitalSignContext",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pSignContext", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Export / Import Wizards ───────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIWizExport",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("pwszWizardTitle", PCWStr),
            ParamSpec::new("pExportInfo", GuestPtr),
            ParamSpec::new("pvoid", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIWizImport",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("pwszWizardTitle", PCWStr),
            ParamSpec::new("pImportInfo", GuestPtr),
            ParamSpec::new("hDestCertStore", Handle),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Certificate Manager Launch ────────────────────────────────────────
    HookSignature {
        module: "cryptui.dll",
        function: "CryptUIStartCertMgr",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pwszTitle", PCWStr),
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("dwFlags", Hex32),
            ParamSpec::new("pvReserved", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
