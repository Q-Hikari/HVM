//! Full `HookSignature` table for `api-ms-win-core-featurestaging-l1-1-0.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

const MODULE: &str = "api-ms-win-core-featurestaging-l1-1-0.dll";

pub(super) static FEATURESTAGING_SIGNATURES: &[HookSignature] = &[
    // ── Feature Staging ───────────────────────────────────────────────────
    HookSignature {
        module: MODULE,
        function: "RecordFeatureUsage",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("featureId", GuestPtr),
            ParamSpec::new("kind", U32),
            ParamSpec::new("addendum", PCWStr),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: MODULE,
        function: "SubscribeFeatureStateChangeNotification",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("subscription", GuestPtr),
            ParamSpec::with_dir("notification", GuestPtr, Out),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: MODULE,
        function: "UnsubscribeFeatureStateChangeNotification",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("notification", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
];
