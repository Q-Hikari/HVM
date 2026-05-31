use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("timeGetTime", LogicalAbi::WinApi),
    ("timeBeginPeriod", LogicalAbi::WinApi),
    ("timeEndPeriod", LogicalAbi::WinApi),
    ("timeSetEvent", LogicalAbi::WinApi),
    ("timeGetDevCaps", LogicalAbi::WinApi),
    ("waveOutGetNumDevs", LogicalAbi::WinApi),
    ("midiOutGetNumDevs", LogicalAbi::WinApi),
    ("joyGetNumDevs", LogicalAbi::WinApi),
    ("mixerGetNumDevs", LogicalAbi::WinApi),
    ("mciSendStringA", LogicalAbi::WinApi),
    ("mciSendStringW", LogicalAbi::WinApi),
    ("PlaySoundA", LogicalAbi::WinApi),
    ("PlaySoundW", LogicalAbi::WinApi),
    ("sndPlaySoundA", LogicalAbi::WinApi),
    ("sndPlaySoundW", LogicalAbi::WinApi),
    ("waveOutOpen", LogicalAbi::WinApi),
    ("waveOutClose", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_winmm_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("winmm.dll", &FUNCTIONS);
}
