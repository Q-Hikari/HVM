use crate::hooks::base::{CallConv, HookDefinition, HookLibrary};
use crate::hooks::registry::HookRegistry;
use crate::runtime::scheduler::WAIT_TIMEOUT;
use crate::tests_support::LoadedTestEngine;

/// Collects the `kernel32.dll` hook definitions currently backed by Rust code.
#[derive(Debug, Default, Clone, Copy)]
pub struct Kernel32HookLibrary;

impl HookLibrary for Kernel32HookLibrary {
    fn collect(&self) -> Vec<HookDefinition> {
        vec![
            definition("CancelIo", 1),
            definition("CloseHandle", 1),
            definition("ApplicationRecoveryFinished", 1),
            definition("ApplicationRecoveryInProgress", 1),
            definition("AreFileApisANSI", 0),
            definition("CreateActCtxW", 1),
            definition("CreateEventA", 4),
            definition("CreateEventW", 4),
            definition("CreateFileA", 7),
            definition("CreateFileW", 7),
            definition("CreateFileMappingA", 6),
            definition("CreateFileMappingW", 6),
            definition("CreateDirectoryA", 2),
            definition("CreateDirectoryW", 2),
            definition("CreateMutexA", 3),
            definition("CreateMutexW", 3),
            definition("CreatePipe", 4),
            definition("CreateProcessA", 10),
            definition("CreateProcessW", 10),
            definition("CreateRemoteThread", 7),
            definition("CreateRemoteThreadEx", 8),
            definition("CreateSemaphoreW", 4),
            definition("CreateThread", 6),
            definition("CreateWaitableTimerW", 3),
            definition("CreateToolhelp32Snapshot", 2),
            definition("CopyFileW", 3),
            definition("DeleteCriticalSection", 1),
            definition("DeleteFileA", 1),
            definition("DeleteFileW", 1),
            definition("DeactivateActCtx", 2),
            definition("DecodePointer", 1),
            definition("DebugBreak", 0),
            definition("DeviceIoControl", 8),
            definition("DuplicateHandle", 7),
            definition("EncodePointer", 1),
            definition("EnterCriticalSection", 1),
            definition("EnumSystemFirmwareTables", 3),
            definition("EnumSystemLocalesA", 2),
            definition("ExitThread", 1),
            definition("ExpandEnvironmentStringsA", 3),
            definition("ExpandEnvironmentStringsW", 3),
            definition("ExitProcess", 1),
            definition("FindClose", 1),
            definition("FindFirstFileA", 2),
            definition("FindFirstFileW", 2),
            definition("FindFirstFileExA", 6),
            definition("FindFirstFileExW", 6),
            definition("FindFirstVolumeW", 2),
            definition("FindNextFileA", 2),
            definition("FindNextFileW", 2),
            definition("FindNextVolumeW", 3),
            definition("FindActCtxSectionStringW", 5),
            definition("FindVolumeClose", 1),
            definition("FindResourceA", 3),
            definition("FindResourceExW", 4),
            definition("FindResourceW", 3),
            definition("FreeConsole", 0),
            definition("FreeEnvironmentStringsA", 1),
            definition("FreeEnvironmentStringsW", 1),
            definition("FreeLibrary", 1),
            definition("FreeLibraryAndExitThread", 2),
            definition("FlsAlloc", 1),
            definition("FlsFree", 1),
            definition("FlsGetValue", 1),
            definition("FlsSetValue", 2),
            definition("FlushFileBuffers", 1),
            definition("FlushViewOfFile", 2),
            definition("GetCommandLineA", 0),
            definition("GetCommandLineW", 0),
            definition("GetACP", 0),
            definition("GetCPInfo", 2),
            definition("GetConsoleCP", 0),
            definition("GetConsoleMode", 2),
            definition("GetConsoleOutputCP", 0),
            definition("GetComputerNameA", 2),
            definition("GetComputerNameW", 2),
            definition("GetCurrentProcess", 0),
            definition("GetCurrentProcessId", 0),
            definition("GetProcessId", 1),
            definition("GetCurrentThread", 0),
            definition("GetCurrentThreadId", 0),
            definition("GetEnvironmentStringsA", 0),
            definition("GetEnvironmentStringsW", 0),
            definition("GetEnvironmentVariableA", 3),
            definition("GetEnvironmentVariableW", 3),
            definition("GetExitCodeProcess", 2),
            definition("GetExitCodeThread", 2),
            definition("FileTimeToLocalFileTime", 2),
            definition("FileTimeToSystemTime", 2),
            definition("GetDiskFreeSpaceExW", 4),
            definition("GetDriveTypeA", 1),
            definition("GetDriveTypeW", 1),
            definition("GetFileAttributesA", 1),
            definition("GetFileAttributesW", 1),
            definition("GetFileAttributesExW", 3),
            definition("GetFileInformationByHandle", 2),
            definition("GetFileInformationByHandleEx", 4),
            definition("GetFileTime", 4),
            definition("GetFileSize", 2),
            definition("GetFileSizeEx", 2),
            definition("GetFileType", 1),
            definition("GetLastError", 0),
            definition("GetLogicalDriveStringsW", 2),
            definition("GetLocalTime", 1),
            definition("GetLocaleInfoA", 4),
            definition("GetLocaleInfoEx", 4),
            definition("GetLocaleInfoW", 4),
            definition("GetModuleFileNameA", 3),
            definition("GetModuleFileNameW", 3),
            definition("GetModuleHandleA", 1),
            definition("GetModuleHandleExW", 3),
            definition("GetModuleHandleW", 1),
            definition("QueryDosDeviceA", 3),
            definition("QueryDosDeviceW", 3),
            definition("GetOEMCP", 0),
            definition("GetFullPathNameA", 4),
            definition("GetFullPathNameW", 4),
            definition("GetProfileIntW", 3),
            definition("GetProcAddress", 2),
            definition("GetPriorityClass", 1),
            definition("GetProcessHeap", 0),
            definition("GetProcessTimes", 5),
            definition("GetProcessWorkingSetSize", 3),
            definition("GetSystemInfo", 1),
            definition("GetSystemDirectoryA", 2),
            definition("GetSystemDirectoryW", 2),
            definition("GetSystemFirmwareTable", 4),
            definition("GetSystemDefaultUILanguage", 0),
            definition("GetSystemWindowsDirectoryA", 2),
            definition("GetSystemWindowsDirectoryW", 2),
            definition("GetThreadPreferredUILanguages", 4),
            definition("GetStringTypeA", 5),
            definition("GetStringTypeW", 4),
            definition("GetStartupInfoA", 1),
            definition("GetStartupInfoW", 1),
            definition("GetStdHandle", 1),
            definition("GetSystemTimeAsFileTime", 1),
            definition("GetTempFileNameW", 4),
            definition("GetTempPathW", 2),
            definition("GetThreadContext", 2),
            definition("GetThreadLocale", 0),
            definition("GetTickCount", 0),
            definition("GetTimeZoneInformation", 1),
            definition("GetUserDefaultLCID", 0),
            definition("GetUserDefaultUILanguage", 0),
            definition("GetVersion", 0),
            definition("GetVersionExA", 1),
            definition("GetVersionExW", 1),
            definition("GetVolumeInformationA", 8),
            definition("GetVolumeInformationW", 8),
            definition("GetCurrentDirectoryW", 2),
            definition("GetWindowsDirectoryA", 2),
            definition("GetWindowsDirectoryW", 2),
            definition("GlobalAddAtomW", 1),
            definition("GlobalAlloc", 2),
            definition("GlobalDeleteAtom", 1),
            definition("GlobalFindAtomW", 1),
            definition("GlobalFlags", 1),
            definition("GlobalFree", 1),
            definition("GlobalGetAtomNameW", 3),
            definition("GlobalHandle", 1),
            definition("GlobalLock", 1),
            definition("GlobalReAlloc", 3),
            definition("GlobalSize", 1),
            definition("GlobalUnlock", 1),
            definition("HeapAlloc", 3),
            definition("HeapCreate", 3),
            definition("HeapDestroy", 1),
            definition("HeapFree", 3),
            definition("HeapLock", 1),
            definition("HeapQueryInformation", 5),
            definition("HeapReAlloc", 4),
            definition("HeapSetInformation", 4),
            definition("HeapSize", 3),
            definition("HeapUnlock", 1),
            definition("HeapWalk", 2),
            definition("InitializeConditionVariable", 1),
            definition("InitializeCriticalSection", 1),
            definition("InitializeCriticalSectionEx", 3),
            definition("InitializeCriticalSectionAndSpinCount", 2),
            definition("InitializeSListHead", 1),
            definition("InitializeSRWLock", 1),
            definition("InterlockedFlushSList", 1),
            definition("InterlockedCompareExchange", 3),
            definition("InterlockedDecrement", 1),
            definition("InterlockedExchange", 2),
            definition("InterlockedExchangeAdd", 2),
            definition("InterlockedIncrement", 1),
            definition("IsBadReadPtr", 2),
            definition("IsDebuggerPresent", 0),
            definition("IsWow64Process", 2),
            definition("IsValidCodePage", 1),
            definition("IsValidLocale", 2),
            definition("IsProcessorFeaturePresent", 1),
            definition("LCMapStringA", 6),
            definition("LCMapStringEx", 9),
            definition("LCMapStringW", 6),
            definition("LeaveCriticalSection", 1),
            definition("LocalAlloc", 2),
            definition("LocalFree", 1),
            definition("LocalFileTimeToFileTime", 2),
            definition("LocalReAlloc", 3),
            definition("LoadLibraryA", 1),
            definition("LoadLibraryExA", 3),
            definition("LoadLibraryExW", 3),
            definition("LoadLibraryW", 1),
            definition("LoadResource", 2),
            definition("LockFile", 5),
            definition("LockResource", 1),
            definition("lstrcmpA", 2),
            // Hash-only shellcode alias used by e862...; keep it explicit so后续可以继续替换成真实 API。
            definition("CxIZKa", 5),
            definition("lstrcatA", 2),
            definition("lstrcmpW", 2),
            definition("lstrcatW", 2),
            definition("lstrcmpiW", 2),
            definition("lstrcpyA", 2),
            definition("lstrcpyW", 2),
            definition("lstrlenA", 1),
            definition("lstrlenW", 1),
            definition("MoveFileExW", 3),
            definition("MoveFileA", 2),
            definition("MoveFileW", 2),
            definition("MapViewOfFile", 5),
            definition("MultiByteToWideChar", 6),
            definition("OpenEventW", 3),
            definition("OpenFileMappingA", 3),
            definition("OpenFileMappingW", 3),
            definition("OpenMutexW", 3),
            definition("OpenProcess", 3),
            definition("OpenThread", 3),
            definition("OpenSemaphoreW", 3),
            definition("OutputDebugStringA", 1),
            definition("OutputDebugStringW", 1),
            definition("PeekNamedPipe", 6),
            definition("Process32First", 2),
            definition("Process32FirstA", 2),
            definition("Process32FirstW", 2),
            definition("Process32Next", 2),
            definition("Process32NextA", 2),
            definition("Process32NextW", 2),
            definition("RegisterApplicationRecoveryCallback", 4),
            definition("RegisterApplicationRestart", 2),
            definition("QueryFullProcessImageNameA", 4),
            definition("QueryFullProcessImageNameW", 4),
            definition("QueryActCtxW", 7),
            definition("QueryPerformanceCounter", 1),
            definition("QueryPerformanceFrequency", 1),
            definition("QueueUserAPC", 3),
            definition("RaiseException", 4),
            definition("ReadFile", 5),
            definition("ReadConsoleW", 5),
            definition("ReleaseMutex", 1),
            definition("ReleaseSemaphore", 3),
            definition("RemoveDirectoryW", 1),
            definition("ResetEvent", 1),
            definition("ReplaceFileW", 6),
            definition("ResumeThread", 1),
            definition("RtlCaptureContext", 1),
            definition("RtlLookupFunctionEntry", 3),
            definition("RtlPcToFileHeader", 2),
            definition("RtlRestoreContext", 2),
            definition("RtlUnwind", 4),
            definition("RtlUnwindEx", 6),
            definition("RtlVirtualUnwind", 8),
            definition("SearchPathW", 6),
            definition("SetCurrentDirectoryW", 1),
            definition("SetErrorMode", 1),
            definition("SetEndOfFile", 1),
            definition("SetEvent", 1),
            definition("SetEnvironmentVariableA", 2),
            definition("SetEnvironmentVariableW", 2),
            definition("SetFileAttributesW", 2),
            definition("SetFileTime", 4),
            definition("SetFilePointer", 4),
            definition("SetFilePointerEx", 5),
            definition("SetHandleCount", 1),
            definition("SetLastError", 1),
            definition("SetProcessWorkingSetSize", 3),
            definition("SetPriorityClass", 2),
            definition("SetThreadPriority", 2),
            definition("SetWaitableTimer", 6),
            definition("SetThreadContext", 2),
            definition("SetStdHandle", 2),
            definition("SetUnhandledExceptionFilter", 1),
            definition("SignalObjectAndWait", 4),
            definition("Sleep", 1),
            definition("SleepEx", 2),
            definition("SwitchToThread", 0),
            definition("SuspendThread", 1),
            definition("SleepConditionVariableCS", 3),
            definition("SleepConditionVariableSRW", 4),
            definition("SizeofResource", 2),
            definition("SystemTimeToFileTime", 2),
            definition("SystemTimeToTzSpecificLocalTime", 3),
            definition("ActivateActCtx", 2),
            definition("TerminateProcess", 2),
            definition("TlsAlloc", 0),
            definition("TlsFree", 1),
            definition("TlsGetValue", 1),
            definition("TlsSetValue", 2),
            definition("UnmapViewOfFile", 1),
            definition("UnhandledExceptionFilter", 1),
            definition("UnregisterApplicationRecoveryCallback", 0),
            definition("UnregisterApplicationRestart", 0),
            definition("UnlockFile", 5),
            definition("WaitForMultipleObjectsEx", 5),
            definition("WaitForMultipleObjects", 4),
            definition("WaitForSingleObject", 2),
            definition("WaitForSingleObjectEx", 3),
            definition("WaitOnAddress", 4),
            definition("WakeAllConditionVariable", 1),
            definition("WakeConditionVariable", 1),
            definition("WakeByAddressAll", 1),
            definition("WakeByAddressSingle", 1),
            definition("WritePrivateProfileStringW", 4),
            definition("GetPrivateProfileStringW", 6),
            definition("GetPrivateProfileIntW", 4),
            definition("WideCharToMultiByte", 8),
            definition("WaitForDebugEvent", 2),
            definition("VirtualAlloc", 4),
            definition("VirtualAllocEx", 5),
            definition("VirtualFree", 3),
            definition("VirtualFreeEx", 4),
            definition("VirtualProtect", 4),
            definition("VirtualProtectEx", 5),
            definition("VirtualQuery", 3),
            definition("VirtualQueryEx", 4),
            definition("ReadProcessMemory", 5),
            definition("WriteProcessMemory", 5),
            definition("WriteConsoleA", 5),
            definition("WriteConsoleW", 5),
            definition("WriteFile", 5),
            definition("ContinueDebugEvent", 3),
            definition("InitializeProcThreadAttributeList", 4),
            definition("UpdateProcThreadAttribute", 7),
            definition("DeleteProcThreadAttributeList", 1),
            definition("CompareStringW", 6),
            definition("EnumSystemLocalesW", 2),
            definition("FormatMessageA", 7),
            definition("FormatMessageW", 7),
            definition("MulDiv", 3),
            definition("TryEnterCriticalSection", 1),
            definition("VerLanguageNameW", 3),
            definition("VerSetConditionMask", 4),
            definition("VerifyVersionInfoW", 4),
            definition("AddVectoredExceptionHandler", 2),
            definition("RemoveVectoredExceptionHandler", 1),
        ]
    }
}

/// Registers the currently supported `kernel32.dll` hook definitions.
pub fn register_kernel32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Kernel32HookLibrary);
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

fn definition(function: &'static str, argc: usize) -> HookDefinition {
    HookDefinition {
        module: "kernel32.dll",
        function,
        argc,
        call_conv: CallConv::Stdcall,
    }
}
