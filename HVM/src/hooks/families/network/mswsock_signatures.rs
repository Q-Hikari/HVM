//! Full `HookSignature` table for `mswsock.dll` functions.
//!
//! Covers Microsoft Winsock extensions: file transmission over sockets.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static MSWSOCK_SIGNATURES: &[HookSignature] = &[
    // ── TransmitFile ──────────────────────────────────────────────────────
    HookSignature {
        module: "mswsock.dll",
        function: "TransmitFile",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hSocket", Handle),
            ParamSpec::new("hFile", Handle),
            ParamSpec::new("nNumberOfBytesToWrite", U32),
            ParamSpec::new("nNumberOfBytesPerSend", U32),
            ParamSpec::new("lpOverlapped", GuestPtr),
            ParamSpec::new("lpTransmitBuffers", GuestPtr),
            ParamSpec::new("dwReserved", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
