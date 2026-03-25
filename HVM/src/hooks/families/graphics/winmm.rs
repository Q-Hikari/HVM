use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "winmm.dll",
        "timeGetTime",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "timeBeginPeriod",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "timeEndPeriod",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "timeSetEvent",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "timeGetDevCaps",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "waveOutGetNumDevs",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "midiOutGetNumDevs",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "joyGetNumDevs",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "mixerGetNumDevs",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "mciSendStringA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "mciSendStringW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "PlaySoundA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "PlaySoundW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "sndPlaySoundA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "sndPlaySoundW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "waveOutOpen",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winmm.dll",
        "waveOutClose",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinmmHookLibrary;

impl HookLibrary for WinmmHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_winmm_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WinmmHookLibrary);
}
