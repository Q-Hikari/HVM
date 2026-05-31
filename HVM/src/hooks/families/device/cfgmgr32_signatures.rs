//! Full `HookSignature` table for `cfgmgr32.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static CFGMGR32_SIGNATURES: &[HookSignature] = &[
    // ── Device Node Location ────────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Locate_DevNodeA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pdnDevInst", U32, Out),
            ParamSpec::new("pDeviceID", PCStr),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Locate_DevNodeW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pdnDevInst", U32, Out),
            ParamSpec::new("pDeviceID", PCWStr),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Device ID Retrieval ─────────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_IDA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::with_dir("Buffer", PStr, Out),
            ParamSpec::new("BufferLen", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_IDW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::with_dir("Buffer", PWStr, Out),
            ParamSpec::new("BufferLen", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_ID_Size",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pulLen", U32, Out),
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Device Tree Traversal ───────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Parent",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pdnDevInst", U32, Out),
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Child",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pdnDevInst", U32, Out),
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Sibling",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pdnDevInst", U32, Out),
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Device Node Status ──────────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_DevNode_Status",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pulStatus", U32, Out),
            ParamSpec::with_dir("pulProblemNumber", U32, Out),
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Registry Property Access ────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_DevNode_Registry_PropertyA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulProperty", U32),
            ParamSpec::new("pulRegDataType", GuestPtr),
            ParamSpec::with_dir("Buffer", OutBuffer { len_param: 4 }, Out),
            ParamSpec::with_dir("pulLength", U32, InOut),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_DevNode_Registry_PropertyW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dnDevInst", U32),
            ParamSpec::new("ulProperty", U32),
            ParamSpec::new("pulRegDataType", GuestPtr),
            ParamSpec::with_dir("Buffer", OutBuffer { len_param: 4 }, Out),
            ParamSpec::with_dir("pulLength", U32, InOut),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Error Mapping ───────────────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_MapCrToWin32Err",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("cmReturnCode", U32),
            ParamSpec::new("dwDefaultError", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Device ID List ──────────────────────────────────────────────────
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_ID_List_SizeA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pulLen", U32, Out),
            ParamSpec::new("pszFilter", PCStr),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_ID_List_SizeW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("pulLen", U32, Out),
            ParamSpec::new("pszFilter", PCWStr),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_ID_ListA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszFilter", PCStr),
            ParamSpec::with_dir("Buffer", OutBuffer { len_param: 2 }, Out),
            ParamSpec::new("BufferLen", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "cfgmgr32.dll",
        function: "CM_Get_Device_ID_ListW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszFilter", PCWStr),
            ParamSpec::with_dir("Buffer", WideBuffer { len_param: 2 }, Out),
            ParamSpec::new("BufferLen", U32),
            ParamSpec::new("ulFlags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
