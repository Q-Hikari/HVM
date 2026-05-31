//! Full `HookSignature` table for `winmm.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static WINMM_SIGNATURES: &[HookSignature] = &[
    // ── Timer Functions ───────────────────────────────────────────────────
    HookSignature {
        module: "winmm.dll",
        function: "timeGetTime",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "timeBeginPeriod",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("uPeriod", U32)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "timeEndPeriod",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("uPeriod", U32)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "timeSetEvent",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("uDelay", U32),
            ParamSpec::new("uResolution", U32),
            ParamSpec::new("fptc", FunctionPtr),
            ParamSpec::new("dwUser", PointerSizedUInt),
            ParamSpec::new("fuEvent", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "timeGetDevCaps",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("ptc", GuestPtr, Out),
            ParamSpec::new("cbtc", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Device Enumeration ────────────────────────────────────────────────
    HookSignature {
        module: "winmm.dll",
        function: "waveOutGetNumDevs",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "midiOutGetNumDevs",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "joyGetNumDevs",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "mixerGetNumDevs",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── MCI (Media Control Interface) ─────────────────────────────────────
    HookSignature {
        module: "winmm.dll",
        function: "mciSendStringA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpstrCommand", PCStr),
            ParamSpec::with_dir("lpstrReturnString", PStr, Out),
            ParamSpec::new("uReturnLength", U32),
            ParamSpec::new("hwndCallback", Handle),
            ParamSpec::new("lpstrDevice", PCStr),
            ParamSpec::new("lpstrAlias", PCStr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "mciSendStringW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpstrCommand", PCWStr),
            ParamSpec::with_dir("lpstrReturnString", PWStr, Out),
            ParamSpec::new("uReturnLength", U32),
            ParamSpec::new("hwndCallback", Handle),
            ParamSpec::new("lpstrDevice", PCWStr),
            ParamSpec::new("lpstrAlias", PCWStr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Sound Playback ────────────────────────────────────────────────────
    HookSignature {
        module: "winmm.dll",
        function: "PlaySoundA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszSound", PCStr),
            ParamSpec::new("hmod", ModuleHandle),
            ParamSpec::new("fdwSound", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "PlaySoundW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszSound", PCWStr),
            ParamSpec::new("hmod", ModuleHandle),
            ParamSpec::new("fdwSound", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "sndPlaySoundA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszSound", PCStr),
            ParamSpec::new("fuSound", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "sndPlaySoundW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszSound", PCWStr),
            ParamSpec::new("fuSound", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Waveform Audio ────────────────────────────────────────────────────
    HookSignature {
        module: "winmm.dll",
        function: "waveOutOpen",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("phwo", Handle, Out),
            ParamSpec::new("uDeviceID", U32),
            ParamSpec::new("pwfx", GuestPtr),
            ParamSpec::new("dwCallback", PointerSizedUInt),
            ParamSpec::new("dwInstance", PointerSizedUInt),
            ParamSpec::new("fdwOpen", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winmm.dll",
        function: "waveOutClose",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hwo", Handle)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
