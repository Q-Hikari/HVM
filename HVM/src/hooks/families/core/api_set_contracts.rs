use crate::hooks::families::com::ole32_signatures::OLE32_SIGNATURES;
use crate::hooks::families::security::advapi32_signatures;
use crate::hooks::families::shell_services::shlwapi_signatures::SHLWAPI_SIGNATURES;
use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;
use crate::hooks::types::LogicalAbi;

use super::kernel32_signatures;
use super::ntdll_signatures;
use super::psapi_signatures::PSAPI_SIGNATURES;
use super::version_signatures::VERSION_SIGNATURES;

const LIBRARYLOADER_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("DisableThreadLibraryCalls", LogicalAbi::WinApi),
    ("FindResourceA", LogicalAbi::WinApi),
    ("FindResourceExW", LogicalAbi::WinApi),
    ("FindResourceW", LogicalAbi::WinApi),
    ("FreeLibrary", LogicalAbi::WinApi),
    ("FreeLibraryAndExitThread", LogicalAbi::WinApi),
    ("GetModuleFileNameA", LogicalAbi::WinApi),
    ("GetModuleFileNameW", LogicalAbi::WinApi),
    ("GetModuleHandleA", LogicalAbi::WinApi),
    ("GetModuleHandleExA", LogicalAbi::WinApi),
    ("GetModuleHandleExW", LogicalAbi::WinApi),
    ("GetModuleHandleW", LogicalAbi::WinApi),
    ("GetProcAddress", LogicalAbi::WinApi),
    ("LoadLibraryA", LogicalAbi::WinApi),
    ("LoadLibraryExA", LogicalAbi::WinApi),
    ("LoadLibraryExW", LogicalAbi::WinApi),
    ("LoadLibraryW", LogicalAbi::WinApi),
    ("LoadResource", LogicalAbi::WinApi),
    ("LoadStringA", LogicalAbi::WinApi),
    ("LoadStringW", LogicalAbi::WinApi),
    ("LockResource", LogicalAbi::WinApi),
    ("SizeofResource", LogicalAbi::WinApi),
];

const HEAP_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("GlobalAlloc", LogicalAbi::WinApi),
    ("GlobalFlags", LogicalAbi::WinApi),
    ("GlobalFree", LogicalAbi::WinApi),
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
    ("LocalAlloc", LogicalAbi::WinApi),
    ("LocalFree", LogicalAbi::WinApi),
    ("LocalReAlloc", LogicalAbi::WinApi),
];

const PROCESSTHREADS_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("GetProcessInformation", LogicalAbi::WinApi),
    ("GetProcessShutdownParameters", LogicalAbi::WinApi),
    ("OpenProcessToken", LogicalAbi::WinApi),
    ("OpenThreadToken", LogicalAbi::WinApi),
    ("SetProcessInformation", LogicalAbi::WinApi),
    ("SetThreadIdealProcessor", LogicalAbi::WinApi),
    ("SetThreadToken", LogicalAbi::WinApi),
];

const PSAPI_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("K32EmptyWorkingSet", LogicalAbi::WinApi),
    ("K32EnumDeviceDrivers", LogicalAbi::WinApi),
    ("K32EnumPageFilesA", LogicalAbi::WinApi),
    ("K32EnumPageFilesW", LogicalAbi::WinApi),
    ("K32EnumProcesses", LogicalAbi::WinApi),
    ("K32EnumProcessModules", LogicalAbi::WinApi),
    ("K32EnumProcessModulesEx", LogicalAbi::WinApi),
    ("K32GetDeviceDriverBaseNameA", LogicalAbi::WinApi),
    ("K32GetDeviceDriverBaseNameW", LogicalAbi::WinApi),
    ("K32GetDeviceDriverFileNameA", LogicalAbi::WinApi),
    ("K32GetDeviceDriverFileNameW", LogicalAbi::WinApi),
    ("K32GetMappedFileNameA", LogicalAbi::WinApi),
    ("K32GetMappedFileNameW", LogicalAbi::WinApi),
    ("K32GetModuleBaseNameA", LogicalAbi::WinApi),
    ("K32GetModuleBaseNameW", LogicalAbi::WinApi),
    ("K32GetModuleFileNameExA", LogicalAbi::WinApi),
    ("K32GetModuleFileNameExW", LogicalAbi::WinApi),
    ("K32GetModuleInformation", LogicalAbi::WinApi),
    ("K32GetPerformanceInfo", LogicalAbi::WinApi),
    ("K32GetProcessImageFileNameA", LogicalAbi::WinApi),
    ("K32GetProcessImageFileNameW", LogicalAbi::WinApi),
    ("K32GetProcessMemoryInfo", LogicalAbi::WinApi),
    ("K32GetWsChanges", LogicalAbi::WinApi),
    ("K32GetWsChangesEx", LogicalAbi::WinApi),
    ("K32InitializeProcessForWsWatch", LogicalAbi::WinApi),
    ("K32QueryWorkingSet", LogicalAbi::WinApi),
    ("K32QueryWorkingSetEx", LogicalAbi::WinApi),
    ("QueryFullProcessImageNameA", LogicalAbi::WinApi),
    ("QueryFullProcessImageNameW", LogicalAbi::WinApi),
];

const APIQUERY_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("ApiSetQueryApiSetPresence", LogicalAbi::WinApi),
    ("ApiSetQueryApiSetPresenceEx", LogicalAbi::WinApi),
];

const COM_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("CLSIDFromProgID", LogicalAbi::WinApi),
    ("CoCreateGuid", LogicalAbi::WinApi),
    ("CoCreateInstance", LogicalAbi::WinApi),
    ("CoGetClassObject", LogicalAbi::WinApi),
    ("CoInitialize", LogicalAbi::WinApi),
    ("CoInitializeEx", LogicalAbi::WinApi),
    ("CoTaskMemRealloc", LogicalAbi::WinApi),
    ("CoUninitialize", LogicalAbi::WinApi),
    ("IIDFromString", LogicalAbi::WinApi),
];

const SIDEBYSIDE_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("ActivateActCtx", LogicalAbi::WinApi),
    ("AddRefActCtx", LogicalAbi::WinApi),
    ("CreateActCtxW", LogicalAbi::WinApi),
    ("DeactivateActCtx", LogicalAbi::WinApi),
    ("FindActCtxSectionGuid", LogicalAbi::WinApi),
    ("FindActCtxSectionStringW", LogicalAbi::WinApi),
    ("GetCurrentActCtx", LogicalAbi::WinApi),
    ("QueryActCtxSettingsW", LogicalAbi::WinApi),
    ("QueryActCtxW", LogicalAbi::WinApi),
    ("ReleaseActCtx", LogicalAbi::WinApi),
    ("ZombifyActCtx", LogicalAbi::WinApi),
];

const MEMORY_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("CreateFileMappingNumaW", LogicalAbi::WinApi),
    ("CreateFileMappingW", LogicalAbi::WinApi),
    ("CreateMemoryResourceNotification", LogicalAbi::WinApi),
    ("FlushViewOfFile", LogicalAbi::WinApi),
    ("GetLargePageMinimum", LogicalAbi::WinApi),
    ("GetProcessWorkingSetSizeEx", LogicalAbi::WinApi),
    ("GetSystemFileCacheSize", LogicalAbi::WinApi),
    ("GetWriteWatch", LogicalAbi::WinApi),
    ("MapViewOfFile", LogicalAbi::WinApi),
    ("MapViewOfFileEx", LogicalAbi::WinApi),
    ("OpenFileMappingW", LogicalAbi::WinApi),
    ("PrefetchVirtualMemory", LogicalAbi::WinApi),
    ("QueryMemoryResourceNotification", LogicalAbi::WinApi),
    ("ReadProcessMemory", LogicalAbi::WinApi),
    ("ResetWriteWatch", LogicalAbi::WinApi),
    ("SetProcessWorkingSetSizeEx", LogicalAbi::WinApi),
    ("SetSystemFileCacheSize", LogicalAbi::WinApi),
    ("UnmapViewOfFile", LogicalAbi::WinApi),
    ("VirtualAlloc", LogicalAbi::WinApi),
    ("VirtualAllocEx", LogicalAbi::WinApi),
    ("VirtualFree", LogicalAbi::WinApi),
    ("VirtualFreeEx", LogicalAbi::WinApi),
    ("VirtualLock", LogicalAbi::WinApi),
    ("VirtualProtect", LogicalAbi::WinApi),
    ("VirtualProtectEx", LogicalAbi::WinApi),
    ("VirtualQuery", LogicalAbi::WinApi),
    ("VirtualQueryEx", LogicalAbi::WinApi),
    ("VirtualUnlock", LogicalAbi::WinApi),
    ("WriteProcessMemory", LogicalAbi::WinApi),
];

const CONSOLE_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("AttachConsole", LogicalAbi::WinApi),
    ("AddConsoleAliasA", LogicalAbi::WinApi),
    ("AddConsoleAliasW", LogicalAbi::WinApi),
    ("ClosePseudoConsole", LogicalAbi::WinApi),
    ("CreatePseudoConsole", LogicalAbi::WinApi),
    ("CreateConsoleScreenBuffer", LogicalAbi::WinApi),
    ("ExpungeConsoleCommandHistoryA", LogicalAbi::WinApi),
    ("ExpungeConsoleCommandHistoryW", LogicalAbi::WinApi),
    ("FillConsoleOutputAttribute", LogicalAbi::WinApi),
    ("FillConsoleOutputCharacterA", LogicalAbi::WinApi),
    ("FillConsoleOutputCharacterW", LogicalAbi::WinApi),
    ("FlushConsoleInputBuffer", LogicalAbi::WinApi),
    ("FreeConsole", LogicalAbi::WinApi),
    ("GenerateConsoleCtrlEvent", LogicalAbi::WinApi),
    ("GetConsoleAliasA", LogicalAbi::WinApi),
    ("GetConsoleAliasExesA", LogicalAbi::WinApi),
    ("GetConsoleAliasExesLengthA", LogicalAbi::WinApi),
    ("GetConsoleAliasExesLengthW", LogicalAbi::WinApi),
    ("GetConsoleAliasExesW", LogicalAbi::WinApi),
    ("GetConsoleAliasesA", LogicalAbi::WinApi),
    ("GetConsoleAliasesLengthA", LogicalAbi::WinApi),
    ("GetConsoleAliasesLengthW", LogicalAbi::WinApi),
    ("GetConsoleAliasesW", LogicalAbi::WinApi),
    ("GetConsoleAliasW", LogicalAbi::WinApi),
    ("GetConsoleCommandHistoryA", LogicalAbi::WinApi),
    ("GetConsoleCommandHistoryLengthA", LogicalAbi::WinApi),
    ("GetConsoleCommandHistoryLengthW", LogicalAbi::WinApi),
    ("GetConsoleCommandHistoryW", LogicalAbi::WinApi),
    ("GetConsoleCP", LogicalAbi::WinApi),
    ("GetConsoleCursorInfo", LogicalAbi::WinApi),
    ("GetConsoleDisplayMode", LogicalAbi::WinApi),
    ("GetConsoleFontSize", LogicalAbi::WinApi),
    ("GetConsoleHistoryInfo", LogicalAbi::WinApi),
    ("GetConsoleMode", LogicalAbi::WinApi),
    ("GetConsoleOriginalTitleA", LogicalAbi::WinApi),
    ("GetConsoleOriginalTitleW", LogicalAbi::WinApi),
    ("GetConsoleOutputCP", LogicalAbi::WinApi),
    ("GetConsoleProcessList", LogicalAbi::WinApi),
    ("GetConsoleScreenBufferInfo", LogicalAbi::WinApi),
    ("GetConsoleScreenBufferInfoEx", LogicalAbi::WinApi),
    ("GetConsoleSelectionInfo", LogicalAbi::WinApi),
    ("GetConsoleTitleA", LogicalAbi::WinApi),
    ("GetConsoleTitleW", LogicalAbi::WinApi),
    ("GetConsoleWindow", LogicalAbi::WinApi),
    ("GetCurrentConsoleFont", LogicalAbi::WinApi),
    ("GetCurrentConsoleFontEx", LogicalAbi::WinApi),
    ("GetLargestConsoleWindowSize", LogicalAbi::WinApi),
    ("GetNumberOfConsoleMouseButtons", LogicalAbi::WinApi),
    ("PeekConsoleInputA", LogicalAbi::WinApi),
    ("PeekConsoleInputW", LogicalAbi::WinApi),
    ("ReadConsoleOutputA", LogicalAbi::WinApi),
    ("ReadConsoleOutputAttribute", LogicalAbi::WinApi),
    ("ReadConsoleOutputCharacterA", LogicalAbi::WinApi),
    ("ReadConsoleOutputCharacterW", LogicalAbi::WinApi),
    ("ReadConsoleOutputW", LogicalAbi::WinApi),
    ("ReadConsoleW", LogicalAbi::WinApi),
    ("ResizePseudoConsole", LogicalAbi::WinApi),
    ("ScrollConsoleScreenBufferA", LogicalAbi::WinApi),
    ("ScrollConsoleScreenBufferW", LogicalAbi::WinApi),
    ("SetConsoleActiveScreenBuffer", LogicalAbi::WinApi),
    ("SetConsoleCP", LogicalAbi::WinApi),
    ("SetConsoleCtrlHandler", LogicalAbi::WinApi),
    ("SetConsoleCursorInfo", LogicalAbi::WinApi),
    ("SetConsoleCursorPosition", LogicalAbi::WinApi),
    ("SetConsoleDisplayMode", LogicalAbi::WinApi),
    ("SetConsoleHistoryInfo", LogicalAbi::WinApi),
    ("SetConsoleNumberOfCommandsA", LogicalAbi::WinApi),
    ("SetConsoleNumberOfCommandsW", LogicalAbi::WinApi),
    ("SetConsoleOutputCP", LogicalAbi::WinApi),
    ("SetConsoleScreenBufferSize", LogicalAbi::WinApi),
    ("SetConsoleScreenBufferInfoEx", LogicalAbi::WinApi),
    ("SetConsoleTextAttribute", LogicalAbi::WinApi),
    ("SetConsoleTitleA", LogicalAbi::WinApi),
    ("SetConsoleTitleW", LogicalAbi::WinApi),
    ("SetConsoleWindowInfo", LogicalAbi::WinApi),
    ("SetCurrentConsoleFontEx", LogicalAbi::WinApi),
    ("WriteConsoleA", LogicalAbi::WinApi),
    ("WriteConsoleInputA", LogicalAbi::WinApi),
    ("WriteConsoleInputW", LogicalAbi::WinApi),
    ("WriteConsoleOutputA", LogicalAbi::WinApi),
    ("WriteConsoleOutputAttribute", LogicalAbi::WinApi),
    ("WriteConsoleOutputCharacterA", LogicalAbi::WinApi),
    ("WriteConsoleOutputCharacterW", LogicalAbi::WinApi),
    ("WriteConsoleOutputW", LogicalAbi::WinApi),
    ("WriteConsoleW", LogicalAbi::WinApi),
];

const REGISTRY_USERSPECIFIC_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("SHRegCloseUSKey", LogicalAbi::WinApi),
    ("SHRegCreateUSKeyA", LogicalAbi::WinApi),
    ("SHRegCreateUSKeyW", LogicalAbi::WinApi),
    ("SHRegDeleteEmptyUSKeyA", LogicalAbi::WinApi),
    ("SHRegDeleteEmptyUSKeyW", LogicalAbi::WinApi),
    ("SHRegDeleteUSValueA", LogicalAbi::WinApi),
    ("SHRegDeleteUSValueW", LogicalAbi::WinApi),
    ("SHRegEnumUSKeyA", LogicalAbi::WinApi),
    ("SHRegEnumUSKeyW", LogicalAbi::WinApi),
    ("SHRegEnumUSValueA", LogicalAbi::WinApi),
    ("SHRegEnumUSValueW", LogicalAbi::WinApi),
    ("SHRegGetBoolUSValueA", LogicalAbi::WinApi),
    ("SHRegGetBoolUSValueW", LogicalAbi::WinApi),
    ("SHRegGetUSValueA", LogicalAbi::WinApi),
    ("SHRegGetUSValueW", LogicalAbi::WinApi),
    ("SHRegOpenUSKeyA", LogicalAbi::WinApi),
    ("SHRegOpenUSKeyW", LogicalAbi::WinApi),
    ("SHRegQueryInfoUSKeyA", LogicalAbi::WinApi),
    ("SHRegQueryInfoUSKeyW", LogicalAbi::WinApi),
    ("SHRegQueryUSValueA", LogicalAbi::WinApi),
    ("SHRegQueryUSValueW", LogicalAbi::WinApi),
    ("SHRegSetUSValueA", LogicalAbi::WinApi),
    ("SHRegSetUSValueW", LogicalAbi::WinApi),
    ("SHRegWriteUSValueA", LogicalAbi::WinApi),
    ("SHRegWriteUSValueW", LogicalAbi::WinApi),
];

const ATOMS_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("AddAtomA", LogicalAbi::WinApi),
    ("AddAtomW", LogicalAbi::WinApi),
    ("DeleteAtom", LogicalAbi::WinApi),
    ("FindAtomA", LogicalAbi::WinApi),
    ("FindAtomW", LogicalAbi::WinApi),
    ("GetAtomNameA", LogicalAbi::WinApi),
    ("GetAtomNameW", LogicalAbi::WinApi),
    ("GlobalAddAtomA", LogicalAbi::WinApi),
    ("GlobalAddAtomW", LogicalAbi::WinApi),
    ("GlobalDeleteAtom", LogicalAbi::WinApi),
    ("GlobalFindAtomA", LogicalAbi::WinApi),
    ("GlobalFindAtomW", LogicalAbi::WinApi),
    ("GlobalGetAtomNameA", LogicalAbi::WinApi),
    ("GlobalGetAtomNameW", LogicalAbi::WinApi),
];

const PATH_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("PathAllocCanonicalize", LogicalAbi::WinApi),
    ("PathAllocCombine", LogicalAbi::WinApi),
    ("PathCchAddBackslash", LogicalAbi::WinApi),
    ("PathCchAddBackslashEx", LogicalAbi::WinApi),
    ("PathCchAddExtension", LogicalAbi::WinApi),
    ("PathCchAppend", LogicalAbi::WinApi),
    ("PathCchAppendEx", LogicalAbi::WinApi),
    ("PathCchCanonicalize", LogicalAbi::WinApi),
    ("PathCchCombine", LogicalAbi::WinApi),
    ("PathCchCombineEx", LogicalAbi::WinApi),
    ("PathCchRemoveBackslash", LogicalAbi::WinApi),
    ("PathCchRemoveExtension", LogicalAbi::WinApi),
    ("PathCchRemoveFileSpec", LogicalAbi::WinApi),
    ("PathCchRenameExtension", LogicalAbi::WinApi),
    ("PathCchSkipRoot", LogicalAbi::WinApi),
    ("PathCchStripPrefix", LogicalAbi::WinApi),
    ("PathCchStripToRoot", LogicalAbi::WinApi),
    ("PathIsUNCEx", LogicalAbi::WinApi),
];

const WOW64_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("GetSystemWow64DirectoryA", LogicalAbi::WinApi),
    ("GetSystemWow64Directory2W", LogicalAbi::WinApi),
    ("GetSystemWow64DirectoryW", LogicalAbi::WinApi),
    ("IsWow64Process2", LogicalAbi::WinApi),
    ("Wow64GetThreadContext", LogicalAbi::WinApi),
    ("Wow64SetThreadContext", LogicalAbi::WinApi),
    ("Wow64SuspendThread", LogicalAbi::WinApi),
    ("Wow64SetThreadDefaultGuestMachine", LogicalAbi::WinApi),
];

const DELAYLOAD_EXPORTS: &[(&str, LogicalAbi)] = &[("ResolveDelayLoadedAPI", LogicalAbi::WinApi)];

const FIBERS_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("FlsAlloc", LogicalAbi::WinApi),
    ("FlsFree", LogicalAbi::WinApi),
    ("FlsGetValue", LogicalAbi::WinApi),
    ("FlsGetValue2", LogicalAbi::WinApi),
    ("FlsSetValue", LogicalAbi::WinApi),
];

const SYNCH_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("CreateSemaphoreW", LogicalAbi::WinApi),
    ("InitOnceBeginInitialize", LogicalAbi::WinApi),
    ("InitOnceComplete", LogicalAbi::WinApi),
    ("InitOnceExecuteOnce", LogicalAbi::WinApi),
    ("InitializeConditionVariable", LogicalAbi::WinApi),
    ("InitializeCriticalSectionEx", LogicalAbi::WinApi),
    ("SetWaitableTimerEx", LogicalAbi::WinApi),
    ("SleepConditionVariableCS", LogicalAbi::WinApi),
    ("SleepConditionVariableSRW", LogicalAbi::WinApi),
    ("WaitForMultipleObjects", LogicalAbi::WinApi),
];

const FILE_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("CopyFileW", LogicalAbi::WinApi),
    ("FindFirstFileNameW", LogicalAbi::WinApi),
    ("FindFirstStreamW", LogicalAbi::WinApi),
    ("FindNextFileNameW", LogicalAbi::WinApi),
    ("GetTempFileNameA", LogicalAbi::WinApi),
    ("GetTempPathA", LogicalAbi::WinApi),
    ("GetVolumeInformationA", LogicalAbi::WinApi),
];

const LARGEINTEGER_EXPORTS: &[(&str, LogicalAbi)] = &[("MulDiv", LogicalAbi::WinApi)];

const LOCALIZATION_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("GetNumberFormatEx", LogicalAbi::WinApi),
    ("LCIDToLocaleName", LogicalAbi::WinApi),
    ("LCMapStringEx", LogicalAbi::WinApi),
];

const REGISTRY_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("RegDeleteKeyValueA", LogicalAbi::WinApi),
    ("RegDeleteKeyValueW", LogicalAbi::WinApi),
    ("RegSetKeyValueA", LogicalAbi::WinApi),
    ("RegSetKeyValueW", LogicalAbi::WinApi),
];

const SHLWAPI_LEGACY_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("IsCharBlankW", LogicalAbi::WinApi),
    ("IsCharCntrlW", LogicalAbi::WinApi),
    ("IsCharDigitW", LogicalAbi::WinApi),
    ("IsCharPunctW", LogicalAbi::WinApi),
    ("IsCharXDigitW", LogicalAbi::WinApi),
    ("PathIsValidCharW", LogicalAbi::WinApi),
    ("SHExpandEnvironmentStringsA", LogicalAbi::WinApi),
    ("SHExpandEnvironmentStringsW", LogicalAbi::WinApi),
    ("SHTruncateString", LogicalAbi::WinApi),
];

const SHLWAPI_OBSOLETE_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("StrCpyNXA", LogicalAbi::WinApi),
    ("StrCpyNXW", LogicalAbi::WinApi),
];

const STRING_EXPORTS: &[(&str, LogicalAbi)] = &[("SHLoadIndirectString", LogicalAbi::WinApi)];

const SYSINFO_EXPORTS: &[(&str, LogicalAbi)] =
    &[("GetLogicalProcessorInformationEx", LogicalAbi::WinApi)];

const VERSIONANSI_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("GetFileVersionInfoA", LogicalAbi::WinApi),
    ("GetFileVersionInfoExA", LogicalAbi::WinApi),
    ("GetFileVersionInfoSizeA", LogicalAbi::WinApi),
    ("GetFileVersionInfoSizeExA", LogicalAbi::WinApi),
    ("VerFindFileA", LogicalAbi::WinApi),
    ("VerQueryValueA", LogicalAbi::WinApi),
];

const LIBRARYLOADER_EXT_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("EnumResourceLanguagesExA", LogicalAbi::WinApi),
    ("EnumResourceLanguagesExW", LogicalAbi::WinApi),
    ("EnumResourceNamesExA", LogicalAbi::WinApi),
    ("EnumResourceNamesExW", LogicalAbi::WinApi),
    ("EnumResourceNamesW", LogicalAbi::WinApi),
    ("EnumResourceTypesExA", LogicalAbi::WinApi),
    ("EnumResourceTypesExW", LogicalAbi::WinApi),
    ("FindStringOrdinal", LogicalAbi::WinApi),
    ("FreeResource", LogicalAbi::WinApi),
];

fn aliased_signature(
    alias_module: &'static str,
    function: &'static str,
    sources: &[&[HookSignature]],
) -> Option<HookSignature> {
    sources
        .iter()
        .flat_map(|signatures| signatures.iter())
        .find(|sig| sig.function.eq_ignore_ascii_case(function))
        .map(|sig| HookSignature {
            module: alias_module,
            function: sig.function,
            abi: sig.abi,
            params: sig.params,
            ret: sig.ret,
            flags: sig.flags,
        })
}

fn register_aliased_signatures(
    registry: &mut HookRegistry,
    alias_module: &'static str,
    exports: &[(&'static str, LogicalAbi)],
    sources: &[&[HookSignature]],
) {
    let aliases = exports
        .iter()
        .filter_map(|(function, _)| aliased_signature(alias_module, function, sources))
        .collect::<Vec<_>>();
    registry.register_signatures(&aliases);
}

pub fn register_api_set_contract_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("api-ms-win-core-libraryloader", &LIBRARYLOADER_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-heap", &HEAP_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-processthreads", &PROCESSTHREADS_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-psapi", &PSAPI_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-fibers", &FIBERS_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-synch", &SYNCH_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-file", &FILE_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-apiquery", &APIQUERY_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-com", &COM_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-sidebyside", &SIDEBYSIDE_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-libraryloader", &LIBRARYLOADER_EXT_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-memory", &MEMORY_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-console", &CONSOLE_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-localization", &LOCALIZATION_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-registry", &REGISTRY_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-shlwapi-legacy", &SHLWAPI_LEGACY_EXPORTS);
    registry.register_function_stubs(
        "api-ms-win-core-shlwapi-obsolete",
        &SHLWAPI_OBSOLETE_EXPORTS,
    );
    registry.register_function_stubs("api-ms-win-core-string", &STRING_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-versionansi", &VERSIONANSI_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-sysinfo", &SYSINFO_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-largeinteger", &LARGEINTEGER_EXPORTS);
    registry.register_function_stubs(
        "api-ms-win-core-registryuserspecific",
        &REGISTRY_USERSPECIFIC_EXPORTS,
    );
    registry.register_function_stubs("api-ms-win-core-atoms", &ATOMS_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-path", &PATH_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-wow64", &WOW64_EXPORTS);
    registry.register_function_stubs("api-ms-win-core-delayload", &DELAYLOAD_EXPORTS);

    let kernel32_sources = kernel32_signatures::ALL_SLICES;
    register_aliased_signatures(
        registry,
        "api-ms-win-core-libraryloader",
        LIBRARYLOADER_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-libraryloader",
        LIBRARYLOADER_EXT_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-heap",
        HEAP_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-fibers",
        FIBERS_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-synch",
        SYNCH_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-file",
        FILE_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-memory",
        MEMORY_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-console",
        CONSOLE_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-localization",
        LOCALIZATION_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-largeinteger",
        LARGEINTEGER_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-atoms",
        ATOMS_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-wow64",
        WOW64_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-sysinfo",
        SYSINFO_EXPORTS,
        kernel32_sources,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-delayload",
        DELAYLOAD_EXPORTS,
        kernel32_sources,
    );

    register_aliased_signatures(
        registry,
        "api-ms-win-core-processthreads",
        PROCESSTHREADS_EXPORTS,
        advapi32_signatures::ALL_SLICES,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-registry",
        REGISTRY_EXPORTS,
        advapi32_signatures::ALL_SLICES,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-registryuserspecific",
        REGISTRY_USERSPECIFIC_EXPORTS,
        advapi32_signatures::ALL_SLICES,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-apiquery",
        APIQUERY_EXPORTS,
        ntdll_signatures::ALL_SLICES,
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-com",
        COM_EXPORTS,
        &[OLE32_SIGNATURES],
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-psapi",
        PSAPI_EXPORTS,
        {
            let mut v: Vec<&[HookSignature]> = vec![PSAPI_SIGNATURES];
            v.extend_from_slice(kernel32_signatures::ALL_SLICES);
            v
        }
        .as_slice(),
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-shlwapi-legacy",
        SHLWAPI_LEGACY_EXPORTS,
        &[SHLWAPI_SIGNATURES],
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-shlwapi-obsolete",
        SHLWAPI_OBSOLETE_EXPORTS,
        &[SHLWAPI_SIGNATURES],
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-string",
        STRING_EXPORTS,
        &[SHLWAPI_SIGNATURES],
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-path",
        PATH_EXPORTS,
        &[SHLWAPI_SIGNATURES],
    );
    register_aliased_signatures(
        registry,
        "api-ms-win-core-versionansi",
        VERSIONANSI_EXPORTS,
        &[VERSION_SIGNATURES],
    );
}
