//! Full `HookSignature` table for `imm32.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static IMM32_SIGNATURES: &[HookSignature] = &[
    // ── Input Method Manager ──────────────────────────────────────────────
    HookSignature {
        module: "imm32.dll",
        function: "ImmGetContext",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "imm32.dll",
        function: "ImmGetOpenStatus",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hIMC", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "imm32.dll",
        function: "ImmReleaseContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hIMC", Handle),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
