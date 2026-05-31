use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;
use crate::runtime::scheduler::WAIT_TIMEOUT;
use crate::tests_support::LoadedTestEngine;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CancelIo", LogicalAbi::WinApi),
    ("CloseHandle", LogicalAbi::WinApi),
    ("ApplicationRecoveryFinished", LogicalAbi::WinApi),
    ("ApplicationRecoveryInProgress", LogicalAbi::WinApi),
    ("AreFileApisANSI", LogicalAbi::WinApi),
    ("CreateActCtxW", LogicalAbi::WinApi),
    ("CreateEventA", LogicalAbi::WinApi),
    ("CreateEventW", LogicalAbi::WinApi),
    ("CreateFileA", LogicalAbi::WinApi),
    ("CreateFileW", LogicalAbi::WinApi),
    ("CreateFileMappingA", LogicalAbi::WinApi),
    ("CreateFileMappingW", LogicalAbi::WinApi),
    ("CreateIoCompletionPort", LogicalAbi::WinApi),
    ("CreateNamedPipeW", LogicalAbi::WinApi),
    ("CreateDirectoryA", LogicalAbi::WinApi),
    ("CreateDirectoryW", LogicalAbi::WinApi),
    ("CreateMutexA", LogicalAbi::WinApi),
    ("CreateMutexExW", LogicalAbi::WinApi),
    ("CreateMutexW", LogicalAbi::WinApi),
    ("CreatePipe", LogicalAbi::WinApi),
    ("CreateProcessA", LogicalAbi::WinApi),
    ("CreateProcessW", LogicalAbi::WinApi),
    ("WinExec", LogicalAbi::WinApi),
    ("CreateRemoteThread", LogicalAbi::WinApi),
    ("CreateRemoteThreadEx", LogicalAbi::WinApi),
    ("CreateSemaphoreExW", LogicalAbi::WinApi),
    ("CreateSemaphoreW", LogicalAbi::WinApi),
    ("CreateThread", LogicalAbi::WinApi),
    ("TerminateThread", LogicalAbi::WinApi),
    ("CreateWaitableTimerW", LogicalAbi::WinApi),
    ("CreateToolhelp32Snapshot", LogicalAbi::WinApi),
    ("CopyFileW", LogicalAbi::WinApi),
    ("DeleteCriticalSection", LogicalAbi::WinApi),
    ("DeleteFileA", LogicalAbi::WinApi),
    ("DeleteFileW", LogicalAbi::WinApi),
    ("DeactivateActCtx", LogicalAbi::WinApi),
    ("DecodePointer", LogicalAbi::WinApi),
    ("DebugBreak", LogicalAbi::WinApi),
    ("DeviceIoControl", LogicalAbi::WinApi),
    ("DuplicateHandle", LogicalAbi::WinApi),
    ("EncodePointer", LogicalAbi::WinApi),
    ("EnterCriticalSection", LogicalAbi::WinApi),
    ("EnumSystemFirmwareTables", LogicalAbi::WinApi),
    ("EnumSystemLocalesA", LogicalAbi::WinApi),
    ("ExitThread", LogicalAbi::WinApi),
    ("ExpandEnvironmentStringsA", LogicalAbi::WinApi),
    ("ExpandEnvironmentStringsW", LogicalAbi::WinApi),
    ("ExitProcess", LogicalAbi::WinApi),
    ("FindClose", LogicalAbi::WinApi),
    ("FindFirstFileA", LogicalAbi::WinApi),
    ("FindFirstFileW", LogicalAbi::WinApi),
    ("FindFirstFileExA", LogicalAbi::WinApi),
    ("FindFirstFileExW", LogicalAbi::WinApi),
    ("FindFirstVolumeW", LogicalAbi::WinApi),
    ("FindNextFileA", LogicalAbi::WinApi),
    ("FindNextFileW", LogicalAbi::WinApi),
    ("FindNextVolumeW", LogicalAbi::WinApi),
    ("FindActCtxSectionStringW", LogicalAbi::WinApi),
    ("FindVolumeClose", LogicalAbi::WinApi),
    ("FindResourceA", LogicalAbi::WinApi),
    ("FindResourceExW", LogicalAbi::WinApi),
    ("FindResourceW", LogicalAbi::WinApi),
    ("FreeConsole", LogicalAbi::WinApi),
    ("FreeEnvironmentStringsA", LogicalAbi::WinApi),
    ("FreeEnvironmentStringsW", LogicalAbi::WinApi),
    ("FreeLibrary", LogicalAbi::WinApi),
    ("FreeLibraryAndExitThread", LogicalAbi::WinApi),
    ("FlushInstructionCache", LogicalAbi::WinApi),
    ("FreeResource", LogicalAbi::WinApi),
    ("FlsAlloc", LogicalAbi::WinApi),
    ("FlsFree", LogicalAbi::WinApi),
    ("FlsGetValue", LogicalAbi::WinApi),
    ("FlsGetValue2", LogicalAbi::WinApi),
    ("FlsSetValue", LogicalAbi::WinApi),
    ("uaw_wcsrchr", LogicalAbi::Cdecl),
    ("FlushFileBuffers", LogicalAbi::WinApi),
    ("FlushViewOfFile", LogicalAbi::WinApi),
    ("GetCommandLineA", LogicalAbi::WinApi),
    ("GetCommandLineW", LogicalAbi::WinApi),
    ("GetACP", LogicalAbi::WinApi),
    ("GetCPInfo", LogicalAbi::WinApi),
    ("GetConsoleCP", LogicalAbi::WinApi),
    ("GetConsoleMode", LogicalAbi::WinApi),
    ("GetConsoleOutputCP", LogicalAbi::WinApi),
    ("GetComputerNameA", LogicalAbi::WinApi),
    ("GetComputerNameW", LogicalAbi::WinApi),
    ("GetCurrentProcess", LogicalAbi::WinApi),
    ("GetCurrentProcessId", LogicalAbi::WinApi),
    ("ProcessIdToSessionId", LogicalAbi::WinApi),
    ("GetProcessId", LogicalAbi::WinApi),
    ("GetCurrentThread", LogicalAbi::WinApi),
    ("GetCurrentThreadId", LogicalAbi::WinApi),
    ("GetThreadTimes", LogicalAbi::WinApi),
    ("GetEnvironmentStringsA", LogicalAbi::WinApi),
    ("GetEnvironmentStringsW", LogicalAbi::WinApi),
    ("GetEnvironmentVariableA", LogicalAbi::WinApi),
    ("GetEnvironmentVariableW", LogicalAbi::WinApi),
    ("GetExitCodeProcess", LogicalAbi::WinApi),
    ("GetExitCodeThread", LogicalAbi::WinApi),
    ("FileTimeToLocalFileTime", LogicalAbi::WinApi),
    ("FileTimeToSystemTime", LogicalAbi::WinApi),
    ("GetDiskFreeSpaceExW", LogicalAbi::WinApi),
    ("GetDriveTypeA", LogicalAbi::WinApi),
    ("GetDriveTypeW", LogicalAbi::WinApi),
    ("GetFileAttributesA", LogicalAbi::WinApi),
    ("GetFileAttributesW", LogicalAbi::WinApi),
    ("GetFileAttributesExW", LogicalAbi::WinApi),
    ("GetFileInformationByHandle", LogicalAbi::WinApi),
    ("GetFileInformationByHandleEx", LogicalAbi::WinApi),
    ("GetFileTime", LogicalAbi::WinApi),
    ("GetFileSize", LogicalAbi::WinApi),
    ("GetFileSizeEx", LogicalAbi::WinApi),
    ("GetFileType", LogicalAbi::WinApi),
    ("GetLastError", LogicalAbi::WinApi),
    ("GetLogicalDriveStringsW", LogicalAbi::WinApi),
    ("GetLocalTime", LogicalAbi::WinApi),
    ("GetLocaleInfoA", LogicalAbi::WinApi),
    ("GetLocaleInfoEx", LogicalAbi::WinApi),
    ("GetLocaleInfoW", LogicalAbi::WinApi),
    ("GetModuleFileNameA", LogicalAbi::WinApi),
    ("GetModuleFileNameW", LogicalAbi::WinApi),
    ("GetModuleHandleA", LogicalAbi::WinApi),
    ("GetModuleHandleExW", LogicalAbi::WinApi),
    ("GetModuleHandleW", LogicalAbi::WinApi),
    ("QueryDosDeviceA", LogicalAbi::WinApi),
    ("QueryDosDeviceW", LogicalAbi::WinApi),
    ("GetOEMCP", LogicalAbi::WinApi),
    ("GetFullPathNameA", LogicalAbi::WinApi),
    ("GetFullPathNameW", LogicalAbi::WinApi),
    ("GetProfileIntW", LogicalAbi::WinApi),
    ("GetProcAddress", LogicalAbi::WinApi),
    ("GetPriorityClass", LogicalAbi::WinApi),
    ("GetProcessAffinityMask", LogicalAbi::WinApi),
    ("GetProcessHeap", LogicalAbi::WinApi),
    ("GetProcessTimes", LogicalAbi::WinApi),
    ("GetProcessWorkingSetSize", LogicalAbi::WinApi),
    ("GetNativeSystemInfo", LogicalAbi::WinApi),
    ("GetSystemInfo", LogicalAbi::WinApi),
    ("GetDllDirectoryW", LogicalAbi::WinApi),
    ("GetSystemDirectoryA", LogicalAbi::WinApi),
    ("GetSystemDirectoryW", LogicalAbi::WinApi),
    ("GetSystemDefaultLangID", LogicalAbi::WinApi),
    ("GetSystemFirmwareTable", LogicalAbi::WinApi),
    ("GetSystemDefaultUILanguage", LogicalAbi::WinApi),
    ("GetSystemTime", LogicalAbi::WinApi),
    ("GetSystemWindowsDirectoryA", LogicalAbi::WinApi),
    ("GetSystemWindowsDirectoryW", LogicalAbi::WinApi),
    ("GetSystemWow64DirectoryW", LogicalAbi::WinApi),
    ("GetThreadPreferredUILanguages", LogicalAbi::WinApi),
    ("GetStringTypeA", LogicalAbi::WinApi),
    ("GetStringTypeW", LogicalAbi::WinApi),
    ("GetStartupInfoA", LogicalAbi::WinApi),
    ("GetStartupInfoW", LogicalAbi::WinApi),
    ("GetStdHandle", LogicalAbi::WinApi),
    ("GetOverlappedResult", LogicalAbi::WinApi),
    ("GetQueuedCompletionStatus", LogicalAbi::WinApi),
    ("GetSystemTimeAsFileTime", LogicalAbi::WinApi),
    ("GetSystemTimePreciseAsFileTime", LogicalAbi::WinApi),
    ("GetTempFileNameA", LogicalAbi::WinApi),
    ("GetTempFileNameW", LogicalAbi::WinApi),
    ("GetTempPathA", LogicalAbi::WinApi),
    ("GetTempPathW", LogicalAbi::WinApi),
    ("GetThreadContext", LogicalAbi::WinApi),
    ("GetThreadLocale", LogicalAbi::WinApi),
    ("GetTickCount", LogicalAbi::WinApi),
    ("GetTickCount64", LogicalAbi::WinApi),
    ("GetTimeZoneInformation", LogicalAbi::WinApi),
    ("GetUserDefaultLCID", LogicalAbi::WinApi),
    ("GetUserDefaultUILanguage", LogicalAbi::WinApi),
    ("GetVersion", LogicalAbi::WinApi),
    ("GetVersionExA", LogicalAbi::WinApi),
    ("GetVersionExW", LogicalAbi::WinApi),
    ("GetVolumeInformationA", LogicalAbi::WinApi),
    ("GetVolumeInformationW", LogicalAbi::WinApi),
    ("GetCurrentDirectoryW", LogicalAbi::WinApi),
    ("GetLongPathNameW", LogicalAbi::WinApi),
    ("GetWindowsDirectoryA", LogicalAbi::WinApi),
    ("GetWindowsDirectoryW", LogicalAbi::WinApi),
    ("GlobalAddAtomW", LogicalAbi::WinApi),
    ("GlobalAlloc", LogicalAbi::WinApi),
    ("GlobalDeleteAtom", LogicalAbi::WinApi),
    ("GlobalFindAtomW", LogicalAbi::WinApi),
    ("GlobalFlags", LogicalAbi::WinApi),
    ("GlobalFree", LogicalAbi::WinApi),
    ("GlobalGetAtomNameW", LogicalAbi::WinApi),
    ("GlobalHandle", LogicalAbi::WinApi),
    ("GlobalLock", LogicalAbi::WinApi),
    ("GlobalReAlloc", LogicalAbi::WinApi),
    ("GlobalSize", LogicalAbi::WinApi),
    ("GlobalUnlock", LogicalAbi::WinApi),
    ("HeapAlloc", LogicalAbi::WinApi),
    ("HeapCreate", LogicalAbi::WinApi),
    ("HeapDestroy", LogicalAbi::WinApi),
    ("HeapFree", LogicalAbi::WinApi),
    ("HeapLock", LogicalAbi::WinApi),
    ("HeapQueryInformation", LogicalAbi::WinApi),
    ("HeapReAlloc", LogicalAbi::WinApi),
    ("HeapSetInformation", LogicalAbi::WinApi),
    ("HeapSize", LogicalAbi::WinApi),
    ("HeapUnlock", LogicalAbi::WinApi),
    ("HeapWalk", LogicalAbi::WinApi),
    ("InitializeConditionVariable", LogicalAbi::WinApi),
    ("InitOnceExecuteOnce", LogicalAbi::WinApi),
    ("InitializeCriticalSection", LogicalAbi::WinApi),
    ("InitializeCriticalSectionEx", LogicalAbi::WinApi),
    ("InitializeCriticalSectionAndSpinCount", LogicalAbi::WinApi),
    ("InitializeSListHead", LogicalAbi::WinApi),
    ("InitializeSRWLock", LogicalAbi::WinApi),
    ("AcquireSRWLockExclusive", LogicalAbi::WinApi),
    ("InterlockedFlushSList", LogicalAbi::WinApi),
    ("InterlockedCompareExchange", LogicalAbi::WinApi),
    ("InterlockedDecrement", LogicalAbi::WinApi),
    ("InterlockedExchange", LogicalAbi::WinApi),
    ("InterlockedExchangeAdd", LogicalAbi::WinApi),
    ("InterlockedIncrement", LogicalAbi::WinApi),
    ("InterlockedPushEntrySList", LogicalAbi::WinApi),
    ("IsBadReadPtr", LogicalAbi::WinApi),
    ("IsDebuggerPresent", LogicalAbi::WinApi),
    ("IsWow64Process", LogicalAbi::WinApi),
    ("IsValidCodePage", LogicalAbi::WinApi),
    ("IsValidLocale", LogicalAbi::WinApi),
    ("IsProcessorFeaturePresent", LogicalAbi::WinApi),
    ("LCMapStringA", LogicalAbi::WinApi),
    ("LCMapStringEx", LogicalAbi::WinApi),
    ("LCMapStringW", LogicalAbi::WinApi),
    ("LeaveCriticalSection", LogicalAbi::WinApi),
    ("LocalAlloc", LogicalAbi::WinApi),
    ("LocalFree", LogicalAbi::WinApi),
    ("LocalFileTimeToFileTime", LogicalAbi::WinApi),
    ("LocalReAlloc", LogicalAbi::WinApi),
    ("LoadLibraryA", LogicalAbi::WinApi),
    ("LoadLibraryExA", LogicalAbi::WinApi),
    ("LoadLibraryExW", LogicalAbi::WinApi),
    ("LoadLibraryW", LogicalAbi::WinApi),
    ("LoadResource", LogicalAbi::WinApi),
    ("LockFile", LogicalAbi::WinApi),
    ("LockResource", LogicalAbi::WinApi),
    ("lstrcmpA", LogicalAbi::WinApi),
    ("CxIZKa", LogicalAbi::WinApi),
    ("lstrcatA", LogicalAbi::WinApi),
    ("lstrcmpW", LogicalAbi::WinApi),
    ("lstrcmpiA", LogicalAbi::WinApi),
    ("lstrcatW", LogicalAbi::WinApi),
    ("lstrcmpiW", LogicalAbi::WinApi),
    ("lstrcpynA", LogicalAbi::WinApi),
    ("lstrcpyA", LogicalAbi::WinApi),
    ("lstrcpyW", LogicalAbi::WinApi),
    ("lstrlenA", LogicalAbi::WinApi),
    ("lstrlenW", LogicalAbi::WinApi),
    ("MoveFileExW", LogicalAbi::WinApi),
    ("MoveFileA", LogicalAbi::WinApi),
    ("MoveFileW", LogicalAbi::WinApi),
    ("MapViewOfFile", LogicalAbi::WinApi),
    ("MultiByteToWideChar", LogicalAbi::WinApi),
    ("OpenEventW", LogicalAbi::WinApi),
    ("OpenFileMappingA", LogicalAbi::WinApi),
    ("OpenFileMappingW", LogicalAbi::WinApi),
    ("OpenMutexA", LogicalAbi::WinApi),
    ("OpenMutexW", LogicalAbi::WinApi),
    ("OpenProcess", LogicalAbi::WinApi),
    ("OpenThread", LogicalAbi::WinApi),
    ("OpenSemaphoreW", LogicalAbi::WinApi),
    ("OutputDebugStringA", LogicalAbi::WinApi),
    ("OutputDebugStringW", LogicalAbi::WinApi),
    ("PeekNamedPipe", LogicalAbi::WinApi),
    ("PostQueuedCompletionStatus", LogicalAbi::WinApi),
    ("Process32First", LogicalAbi::WinApi),
    ("Process32FirstA", LogicalAbi::WinApi),
    ("Process32FirstW", LogicalAbi::WinApi),
    ("Process32Next", LogicalAbi::WinApi),
    ("Process32NextA", LogicalAbi::WinApi),
    ("Process32NextW", LogicalAbi::WinApi),
    ("RegisterApplicationRecoveryCallback", LogicalAbi::WinApi),
    ("RegisterApplicationRestart", LogicalAbi::WinApi),
    ("QueryFullProcessImageNameA", LogicalAbi::WinApi),
    ("QueryFullProcessImageNameW", LogicalAbi::WinApi),
    ("QueryActCtxW", LogicalAbi::WinApi),
    ("QueryPerformanceCounter", LogicalAbi::WinApi),
    ("QueryPerformanceFrequency", LogicalAbi::WinApi),
    ("QueueUserAPC", LogicalAbi::WinApi),
    ("QueueUserWorkItem", LogicalAbi::WinApi),
    ("RaiseException", LogicalAbi::WinApi),
    ("ReadFile", LogicalAbi::WinApi),
    ("ReadConsoleW", LogicalAbi::WinApi),
    ("ReleaseSRWLockExclusive", LogicalAbi::WinApi),
    ("ReleaseMutex", LogicalAbi::WinApi),
    ("ReleaseSemaphore", LogicalAbi::WinApi),
    ("RemoveDirectoryW", LogicalAbi::WinApi),
    ("ResetEvent", LogicalAbi::WinApi),
    ("ReplaceFileW", LogicalAbi::WinApi),
    ("ResumeThread", LogicalAbi::WinApi),
    ("RtlCaptureContext", LogicalAbi::WinApi),
    ("RtlLookupFunctionEntry", LogicalAbi::WinApi),
    ("RtlPcToFileHeader", LogicalAbi::WinApi),
    ("RtlRestoreContext", LogicalAbi::WinApi),
    ("RtlUnwind", LogicalAbi::WinApi),
    ("RtlUnwindEx", LogicalAbi::WinApi),
    ("RtlVirtualUnwind", LogicalAbi::WinApi),
    ("SearchPathW", LogicalAbi::WinApi),
    ("SetConsoleCtrlHandler", LogicalAbi::WinApi),
    ("SetCurrentDirectoryW", LogicalAbi::WinApi),
    ("SetDllDirectoryW", LogicalAbi::WinApi),
    ("SetErrorMode", LogicalAbi::WinApi),
    ("SetEndOfFile", LogicalAbi::WinApi),
    ("SetEvent", LogicalAbi::WinApi),
    ("SetEnvironmentVariableA", LogicalAbi::WinApi),
    ("SetEnvironmentVariableW", LogicalAbi::WinApi),
    ("SetFileAttributesW", LogicalAbi::WinApi),
    ("SetFileAttributesA", LogicalAbi::WinApi),
    ("SetFileTime", LogicalAbi::WinApi),
    ("SetFilePointer", LogicalAbi::WinApi),
    ("SetFilePointerEx", LogicalAbi::WinApi),
    ("SetHandleCount", LogicalAbi::WinApi),
    ("SetLastError", LogicalAbi::WinApi),
    ("SetProcessWorkingSetSize", LogicalAbi::WinApi),
    ("SetPriorityClass", LogicalAbi::WinApi),
    ("SetProcessAffinityMask", LogicalAbi::WinApi),
    ("SetThreadPriority", LogicalAbi::WinApi),
    ("SetThreadAffinityMask", LogicalAbi::WinApi),
    ("SetNamedPipeHandleState", LogicalAbi::WinApi),
    ("SetWaitableTimer", LogicalAbi::WinApi),
    ("SetThreadContext", LogicalAbi::WinApi),
    ("SetStdHandle", LogicalAbi::WinApi),
    ("SetUnhandledExceptionFilter", LogicalAbi::WinApi),
    ("SignalObjectAndWait", LogicalAbi::WinApi),
    ("Sleep", LogicalAbi::WinApi),
    ("SleepEx", LogicalAbi::WinApi),
    ("SwitchToThread", LogicalAbi::WinApi),
    ("SuspendThread", LogicalAbi::WinApi),
    ("SleepConditionVariableCS", LogicalAbi::WinApi),
    ("SleepConditionVariableSRW", LogicalAbi::WinApi),
    ("SizeofResource", LogicalAbi::WinApi),
    ("SystemTimeToFileTime", LogicalAbi::WinApi),
    ("SystemTimeToTzSpecificLocalTime", LogicalAbi::WinApi),
    ("ActivateActCtx", LogicalAbi::WinApi),
    ("TerminateProcess", LogicalAbi::WinApi),
    ("TlsAlloc", LogicalAbi::WinApi),
    ("TlsFree", LogicalAbi::WinApi),
    ("TlsGetValue", LogicalAbi::WinApi),
    ("TlsSetValue", LogicalAbi::WinApi),
    ("UnmapViewOfFile", LogicalAbi::WinApi),
    ("UnhandledExceptionFilter", LogicalAbi::WinApi),
    ("UnregisterApplicationRecoveryCallback", LogicalAbi::WinApi),
    ("UnregisterApplicationRestart", LogicalAbi::WinApi),
    ("UnregisterWaitEx", LogicalAbi::WinApi),
    ("UnlockFile", LogicalAbi::WinApi),
    ("WaitNamedPipeW", LogicalAbi::WinApi),
    ("ConnectNamedPipe", LogicalAbi::WinApi),
    ("DisconnectNamedPipe", LogicalAbi::WinApi),
    ("WaitForMultipleObjectsEx", LogicalAbi::WinApi),
    ("WaitForMultipleObjects", LogicalAbi::WinApi),
    ("WaitForSingleObject", LogicalAbi::WinApi),
    ("WaitForSingleObjectEx", LogicalAbi::WinApi),
    ("WaitOnAddress", LogicalAbi::WinApi),
    ("WakeAllConditionVariable", LogicalAbi::WinApi),
    ("WakeConditionVariable", LogicalAbi::WinApi),
    ("WakeByAddressAll", LogicalAbi::WinApi),
    ("WakeByAddressSingle", LogicalAbi::WinApi),
    ("WritePrivateProfileStringW", LogicalAbi::WinApi),
    ("WritePrivateProfileStringA", LogicalAbi::WinApi),
    ("GetPrivateProfileStringW", LogicalAbi::WinApi),
    ("GetPrivateProfileStringA", LogicalAbi::WinApi),
    ("GetPrivateProfileIntW", LogicalAbi::WinApi),
    ("WideCharToMultiByte", LogicalAbi::WinApi),
    ("WaitForDebugEvent", LogicalAbi::WinApi),
    ("VirtualAlloc", LogicalAbi::WinApi),
    ("VirtualAllocEx", LogicalAbi::WinApi),
    ("VirtualFree", LogicalAbi::WinApi),
    ("VirtualFreeEx", LogicalAbi::WinApi),
    ("VirtualProtect", LogicalAbi::WinApi),
    ("VirtualProtectEx", LogicalAbi::WinApi),
    ("VirtualQuery", LogicalAbi::WinApi),
    ("VirtualQueryEx", LogicalAbi::WinApi),
    ("ReadProcessMemory", LogicalAbi::WinApi),
    ("WriteProcessMemory", LogicalAbi::WinApi),
    ("WriteConsoleA", LogicalAbi::WinApi),
    ("WriteConsoleW", LogicalAbi::WinApi),
    ("WriteFile", LogicalAbi::WinApi),
    ("ContinueDebugEvent", LogicalAbi::WinApi),
    ("InitializeProcThreadAttributeList", LogicalAbi::WinApi),
    ("UpdateProcThreadAttribute", LogicalAbi::WinApi),
    ("DeleteProcThreadAttributeList", LogicalAbi::WinApi),
    ("CompareStringW", LogicalAbi::WinApi),
    ("EnumSystemLocalesW", LogicalAbi::WinApi),
    ("FormatMessageA", LogicalAbi::WinApi),
    ("FormatMessageW", LogicalAbi::WinApi),
    ("MulDiv", LogicalAbi::WinApi),
    ("TryEnterCriticalSection", LogicalAbi::WinApi),
    ("VerLanguageNameW", LogicalAbi::WinApi),
    ("VerSetConditionMask", LogicalAbi::WinApi),
    ("VerifyVersionInfoA", LogicalAbi::WinApi),
    ("VerifyVersionInfoW", LogicalAbi::WinApi),
    ("AddVectoredExceptionHandler", LogicalAbi::WinApi),
    ("RemoveVectoredExceptionHandler", LogicalAbi::WinApi),
    ("AddAtomW", LogicalAbi::WinApi),
    ("CompareFileTime", LogicalAbi::WinApi),
    ("CompareStringOrdinal", LogicalAbi::WinApi),
    ("DeleteAtom", LogicalAbi::WinApi),
    ("EnumDateFormatsExW", LogicalAbi::WinApi),
    ("EnumTimeFormatsW", LogicalAbi::WinApi),
    ("FileTimeToDosDateTime", LogicalAbi::WinApi),
    ("GetDateFormatW", LogicalAbi::WinApi),
    ("GetNumberFormatEx", LogicalAbi::WinApi),
    ("GetShortPathNameW", LogicalAbi::WinApi),
    ("GetTimeFormatW", LogicalAbi::WinApi),
];

/// Registers the currently supported `kernel32.dll` hook definitions.
pub fn register_kernel32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("kernel32.dll", &FUNCTIONS);
    super::kernel32_signatures::register_all(registry);
    registry
        .register_signatures(super::super::crt::variadic_signatures::KERNEL32_VARIADIC_SIGNATURES);
}

#[cfg(test)]
mod tests {
    use super::register_kernel32_hooks;
    use crate::hooks::registry::HookRegistry;
    use crate::hooks::signature::ReturnSpec;

    #[test]
    fn registers_wpscloudsvr_kernel32_imports() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);

        for function in [
            "GetSystemWow64DirectoryW",
            "QueueUserWorkItem",
            "UnregisterWaitEx",
            "SetDllDirectoryW",
            "GetDllDirectoryW",
            "GetSystemTime",
            "SetNamedPipeHandleState",
            "WaitNamedPipeW",
            "GetOverlappedResult",
            "ConnectNamedPipe",
            "DisconnectNamedPipe",
            "CreateNamedPipeW",
            "CreateIoCompletionPort",
            "GetQueuedCompletionStatus",
            "PostQueuedCompletionStatus",
            "GetLongPathNameW",
            "ProcessIdToSessionId",
            "ReleaseSRWLockExclusive",
            "AcquireSRWLockExclusive",
            "InterlockedPushEntrySList",
            "SetConsoleCtrlHandler",
        ] {
            assert!(
                registry.has_signature_for("kernel32.dll", function),
                "missing kernel32 registration for {function}"
            );
        }
    }

    #[test]
    fn bool_returning_kernel32_hooks_keep_bool_return_specs() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);

        for function in [
            "InitializeCriticalSectionAndSpinCount",
            "SleepConditionVariableCS",
            "SleepConditionVariableSRW",
        ] {
            let signature = registry
                .signature("kernel32.dll", function)
                .unwrap_or_else(|| panic!("missing {function} signature"));
            assert_eq!(signature.ret, ReturnSpec::Bool32, "{function}");
        }
    }
}

/// Exposes test-only `kernel32.dll` helpers over the loaded Rust runtime scaffold.
#[derive(Debug)]
pub struct Kernel32Api<'a> {
    engine: &'a mut LoadedTestEngine,
}

impl<'a> Kernel32Api<'a> {
    /// Builds a `kernel32.dll` helper bound to one loaded test engine.
    pub(crate) fn new(engine: &'a mut LoadedTestEngine) -> Self {
        Self { engine }
    }

    /// Creates a virtual thread through the scheduler and returns its handle and TID.
    pub fn create_thread_for_test(
        &mut self,
        start_address: u64,
        parameter: u64,
        suspended: bool,
    ) -> Option<(u32, u32)> {
        let thread = self.engine.scheduler_mut().create_virtual_thread(
            start_address,
            parameter,
            suspended,
        )?;
        Some((thread.handle, thread.tid))
    }

    /// Creates an event dispatcher object and returns its handle.
    pub fn create_event_for_test(
        &mut self,
        manual_reset: bool,
        initial_state: bool,
    ) -> Option<u32> {
        self.engine
            .scheduler_mut()
            .create_event(manual_reset, initial_state)
            .map(|event| event.handle)
    }

    /// Waits on one dispatcher object through the scheduler surface.
    pub fn wait_for_single_object_for_test(&mut self, handle: u32, timeout_ms: u32) -> u32 {
        self.engine
            .scheduler_mut()
            .wait_for_single_object(handle, timeout_ms)
    }

    /// Waits on one object for the main test thread, supporting alertable APC resumption.
    pub fn wait_for_single_object_ex_for_main_thread(
        &mut self,
        handle: u32,
        timeout_ms: u32,
        alertable: bool,
    ) -> u32 {
        if !alertable {
            return self.wait_for_single_object_for_test(handle, timeout_ms);
        }

        let main_tid = self.engine.main_thread_tid();
        if let Some(result) = self.engine.scheduler_mut().resume_wait_result(main_tid) {
            return result;
        }

        let immediate = self.wait_for_single_object_for_test(handle, timeout_ms);
        if immediate != WAIT_TIMEOUT {
            return immediate;
        }

        let _ = self
            .engine
            .scheduler_mut()
            .begin_alertable_wait(main_tid, handle, timeout_ms);
        WAIT_TIMEOUT
    }

    /// Signals one event object through the scheduler surface.
    pub fn set_event_for_test(&mut self, handle: u32) -> Option<()> {
        self.engine.scheduler_mut().set_event(handle)
    }

    /// Returns the current `GetLastError` value tracked by the test engine.
    pub fn get_last_error_for_test(&self) -> u32 {
        self.engine.last_error()
    }

    /// Updates the current `SetLastError` value tracked by the test engine.
    pub fn set_last_error_for_test(&mut self, value: u32) {
        self.engine.set_last_error(value);
    }

    /// Returns the mirrored command line string exposed by the test engine.
    pub fn command_line_for_test(&self) -> &str {
        self.engine.command_line()
    }
}
