//! Full `HookSignature` table for `setupapi.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static SETUPAPI_SIGNATURES: &[HookSignature] = &[
    // ── Device Information Set ───────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetClassDevsA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("ClassGuid", GuidPtr),
            ParamSpec::new("Enumerator", PCStr),
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetClassDevsW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("ClassGuid", GuidPtr),
            ParamSpec::new("Enumerator", PCWStr),
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiDestroyDeviceInfoList",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("DeviceInfoSet", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Device Enumeration ───────────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiEnumDeviceInfo",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("MemberIndex", U32),
            ParamSpec::with_dir("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA"), InOut),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Device Registry Property ─────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetDeviceRegistryPropertyA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA")),
            ParamSpec::new("Property", U32),
            ParamSpec::new("PropertyRegDataType", GuestPtr),
            ParamSpec::with_dir("PropertyBuffer", OutBuffer { len_param: 5 }, Out),
            ParamSpec::new("PropertyBufferSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetDeviceRegistryPropertyW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA")),
            ParamSpec::new("Property", U32),
            ParamSpec::new("PropertyRegDataType", GuestPtr),
            ParamSpec::with_dir("PropertyBuffer", OutBuffer { len_param: 5 }, Out),
            ParamSpec::new("PropertyBufferSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Device Instance ID ───────────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetDeviceInstanceIdA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA")),
            ParamSpec::with_dir("DeviceInstanceId", OutBuffer { len_param: 3 }, Out),
            ParamSpec::new("DeviceInstanceIdSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetDeviceInstanceIdW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA")),
            ParamSpec::with_dir("DeviceInstanceId", WideBuffer { len_param: 3 }, Out),
            ParamSpec::new("DeviceInstanceIdSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Device Registry Key ──────────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiOpenDevRegKey",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA")),
            ParamSpec::new("Scope", U32),
            ParamSpec::new("HwProfile", U32),
            ParamSpec::new("KeyType", U32),
            ParamSpec::new("samDesired", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    // ── Device Interface ─────────────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiEnumDeviceInterfaces",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new("DeviceInfoData", OpaqueStructPtr("SP_DEVINFO_DATA")),
            ParamSpec::new("InterfaceClassGuid", GuidPtr),
            ParamSpec::new("MemberIndex", U32),
            ParamSpec::with_dir(
                "DeviceInfoData",
                OpaqueStructPtr("SP_DEVICE_INTERFACE_DATA"),
                InOut,
            ),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetDeviceInterfaceDetailA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new(
                "DeviceInterfaceData",
                OpaqueStructPtr("SP_DEVICE_INTERFACE_DATA"),
            ),
            ParamSpec::with_dir(
                "DeviceInterfaceDetailData",
                OpaqueStructPtr("SP_DEVICE_INTERFACE_DETAIL_DATA_A"),
                InOut,
            ),
            ParamSpec::new("DeviceInterfaceDetailDataSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
            ParamSpec::new("DeviceInfoData", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetDeviceInterfaceDetailW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("DeviceInfoSet", Handle),
            ParamSpec::new(
                "DeviceInterfaceData",
                OpaqueStructPtr("SP_DEVICE_INTERFACE_DATA"),
            ),
            ParamSpec::with_dir(
                "DeviceInterfaceDetailData",
                OpaqueStructPtr("SP_DEVICE_INTERFACE_DETAIL_DATA_W"),
                InOut,
            ),
            ParamSpec::new("DeviceInterfaceDetailDataSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
            ParamSpec::new("DeviceInfoData", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Class GUID from Name ─────────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiClassGuidsFromNameA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("ClassName", PCStr),
            ParamSpec::with_dir("ClassGuidList", OutBuffer { len_param: 2 }, Out),
            ParamSpec::new("ClassGuidListSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiClassGuidsFromNameW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("ClassName", PCWStr),
            ParamSpec::with_dir("ClassGuidList", OutBuffer { len_param: 2 }, Out),
            ParamSpec::new("ClassGuidListSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── INF Class ────────────────────────────────────────────────────────
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetINFClassA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("InfName", PCStr),
            ParamSpec::with_dir("ClassGuid", GuidPtr, Out),
            ParamSpec::with_dir("ClassName", OutBuffer { len_param: 3 }, Out),
            ParamSpec::new("ClassNameSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "setupapi.dll",
        function: "SetupDiGetINFClassW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("InfName", PCWStr),
            ParamSpec::with_dir("ClassGuid", GuidPtr, Out),
            ParamSpec::with_dir("ClassName", WideBuffer { len_param: 3 }, Out),
            ParamSpec::new("ClassNameSize", U32),
            ParamSpec::new("RequiredSize", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
