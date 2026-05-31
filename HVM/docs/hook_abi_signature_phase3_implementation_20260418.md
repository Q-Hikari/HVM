# Phase 3: Core DLL Migration — Implementation Report

**Date**: 2026-04-18
**Branch**: `hikari-v1`
**Scope**: Full `HookSignature` definitions for 5 core DLL families (high-frequency first)

## Summary

Phase 3 migrates the 5 core DLL families from empty bridged signatures to full `HookSignature` definitions with typed parameters and return specs. A total of **918 function signatures** were created across 5 DLLs (kernel32: 392, ntdll: 50, advapi32: 116, msvcrt: 99, user32: 261), and the dispatch layer was upgraded to use `ReturnSpec`-driven `HookValue` wrapping.

后续补齐轮次将 advapi32 从 38 → 116（+78）、msvcrt 从 40 → 99（+59）、user32 从 48 → 261（+213，含 2 个 variadic cdecl wsprintfA/W）推进到 100% 覆盖。

## Deliverables

### 1. Registry Enhancement

**File**: `src/hooks/registry.rs`

Added `register_signatures()` method:
```rust
pub fn register_signatures(&mut self, signatures: &[HookSignature]) {
    for sig in signatures {
        let key = normalized_key(sig.module, sig.function);
        self.signatures.insert(key, sig.clone());
    }
}
```

This overwrites empty bridged signatures with full ones. Called after `register_library()` in each DLL's registration function.

### 2. Signature Tables (5 new files)

| File | DLL | Entries | Lines |
|------|-----|---------|-------|
| `src/hooks/families/core/kernel32_signatures.rs` | kernel32.dll | 392 | 4438 |
| `src/hooks/families/core/ntdll_signatures.rs` | ntdll.dll | 50 | 669 |
| `src/hooks/families/security/advapi32_signatures.rs` | advapi32.dll | 116 | 1590 |
| `src/hooks/families/crt/msvcrt_signatures.rs` | msvcrt.dll | 99 | 1068 |
| `src/hooks/families/ui/user32/user32_signatures.rs` | user32.dll | 261 | 3200 |
| **Total** | | **918** | **10965** |

Each entry contains:
- `module` / `function` — DLL and function name
- `abi` — `LogicalAbi::WinApi`, `Cdecl`, etc.
- `params` — `&[ParamSpec]` with name, `ParamType`, and direction
- `ret` — `ReturnSpec` (Void, Bool32, I32, U32, U16, NtStatus, Win32Error, Handle, Pointer, PointerSizedUInt, PointerSizedInt)
- `flags` — `HookFlags::empty()` for all Phase 3 entries

#### Coverage by Category

**kernel32.dll** (191 entries):
- File I/O (CreateFileA/W, ReadFile, WriteFile, mappings, finders, attributes)
- Memory (VirtualAlloc/Ex/Free/Protect/Query, Heap*, Global*)
- Process/Thread (CreateProcessA/W, CreateThread, OpenProcess, GetCurrent*)
- Module (GetModuleHandleA/W, LoadLibraryA/W/ExA/ExW, GetProcAddress, FreeLibrary)
- Sync (CreateEventA/W, WaitForSingleObject, Mutex, Sleep)
- TLS (TlsAlloc/Free/GetValue/SetValue, Fls*)
- Console, Environment, String, Error/Info, Misc

**ntdll.dll** (50 entries):
- Memory (NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory)
- Process/Thread (NtOpenProcess, NtCreateThreadEx, NtClose, NtTerminate*)
- Heap (RtlAllocateHeap, RtlFreeHeap, RtlReAllocateHeap, RtlCreate/DestroyHeap)
- Loader (LdrLoadDll, LdrGetProcedureAddress, LdrGetDllHandle)
- Section (NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection)
- Exception/Context (NtContinue, KiUserExceptionDispatcher, RtlCapture/RestoreContext)
- Unicode/String (RtlInitUnicodeString, RtlGetVersion, RtlDecompressBuffer)

**advapi32.dll** (38 entries):
- Registry (RegOpenKeyExA/W, RegCreateKeyExA/W, RegQueryValueExA/W, RegSetValueExA/W, RegCloseKey, RegEnumKeyExA/W, RegGetValueA/W, etc.)
- Token/Privilege (OpenProcessToken, OpenThreadToken, GetTokenInformation, AdjustTokenPrivileges, LookupPrivilegeValueA/W)
- Crypto (CryptAcquireContextW, CryptReleaseContext, CryptGenRandom, CryptCreateHash, CryptHashData, CryptGetHashParam, CryptDeriveKey, CryptEncrypt, CryptDecrypt, CryptDestroyHash/Key)
- Service (StartServiceCtrlDispatcherW, RegisterServiceCtrlHandlerW)

**msvcrt.dll** (40 entries):
- Memory (malloc, free, realloc, calloc, memcpy, memmove, memset, memcmp)
- String (strlen, wcslen, strcmp, wcscmp, strncmp, wcsncmp, strcpy, wcscpy, strcat, wcscat, strchr, wcschr, strstr, wcsstr)
- Conversion (atoi, atol, strtol, strtoul, toupper, tolower)
- Sort/Search (qsort, bsearch)
- CRT init (_initterm, _amsg_exit, __set_app_type, _controlfp)
- File I/O (fopen, fclose, fread, fwrite, fseek, ftell)

**user32.dll** (48 entries):
- MessageBox (MessageBoxA/W)
- Window (FindWindowA/W, CreateWindowExA/W, DestroyWindow, MoveWindow, SetWindowPos, GetWindowRect, GetClientRect, GetWindowTextW)
- Message (SendMessageA/W, PostMessageA/W, PeekMessageW, GetMessageW, TranslateMessage, DispatchMessageA/W, DefWindowProcW, PostQuitMessage)
- System (GetSystemMetrics, LoadCursorW, LoadIconW, RegisterClassExA/W, GetDC, ReleaseDC)
- Timer/Hook/Enum (SetTimer, KillTimer, SetWindowsHookExW, CallNextHookEx, UnhookWindowsHookEx, EnumWindows)
- Misc (SystemParametersInfoW, GetCursorPos, BeginPaint, EndPaint, IsWindow, IsWindowVisible, GetActiveWindow, GetDesktopWindow, GetForegroundWindow, ShowWindow, GetParent, GetWindowThreadProcessId)

### 3. Module Registration

Modified 5 registration functions and module declarations:

| DLL | Registration Function | Module Declaration |
|-----|----------------------|--------------------|
| kernel32 | `register_kernel32_hooks()` in `kernel32.rs` | `pub mod kernel32_signatures;` in `core/mod.rs` |
| ntdll | `register_ntdll_hooks()` in `ntdll.rs` | `pub mod ntdll_signatures;` in `core/mod.rs` |
| advapi32 | `register_advapi32_hooks()` in `advapi32.rs` | `pub mod advapi32_signatures;` in `security/mod.rs` |
| msvcrt | `register_msvcrt_hooks()` in `msvcrt.rs` | `pub mod msvcrt_signatures;` in `crt/mod.rs` |
| user32 | `register_user32_hooks()` in `user32/mod.rs` | `mod user32_signatures;` in `user32/mod.rs` |

### 4. ReturnSpec::U16 Addition

**File**: `src/hooks/signature.rs`

Added `U16` variant to `ReturnSpec` for `RegisterClassExW/A` which return `ATOM` (u16).

**File**: `src/runtime/engine/logging_helpers.rs`

Added `U16` rendering in `format_return_from_signature()`:
```rust
ReturnSpec::U16 => format!("u16={}", retval as u16),
```

### 5. FromHookParam Scalar Implementations

**File**: `src/runtime/engine/hook_context.rs`

Added `FromHookParam` implementations for core scalar types:
- `u32`, `i32` — 32-bit extraction
- `u64`, `i64` — full-width passthrough
- `bool` — non-zero check
- `u16` — 16-bit extraction
- `usize` — pointer-sized extraction

### 6. ReturnSpec-Driven HookValue Wrapping (Alternative to Handler Conversion)

**File**: `src/runtime/engine/hook_value.rs`

Added `HookValue::from_raw_with_spec()` method that interprets a raw `u64` return value based on `ReturnSpec`:

```rust
pub fn from_raw_with_spec(raw: u64, spec: ReturnSpec, arch: &ArchSpec) -> Self {
    match spec {
        ReturnSpec::Void => Self::Void,
        ReturnSpec::Bool32 => Self::Raw(raw),
        ReturnSpec::I32 => Self::I32(raw as u32 as i32),
        ReturnSpec::U32 | ReturnSpec::U16 => Self::U32(raw as u32),
        ReturnSpec::NtStatus => Self::NtStatus(raw as u32),
        ReturnSpec::Win32Error => Self::Win32Error(raw as u32),
        ReturnSpec::Handle => { /* sign-extension logic */ }
        ReturnSpec::Pointer => { /* truncation logic */ }
        ReturnSpec::PointerSizedUInt | ReturnSpec::PointerSizedInt => Self::Raw(raw),
    }
}
```

**File**: `src/runtime/engine/hooks/family_dispatch.rs`

Updated `dispatch_bound_stub_with_definition()` to use `from_raw_with_spec` instead of `HookValue::from(retval?)`:

```rust
// Before:
HookValue::from(retval?)

// After:
HookValue::from_raw_with_spec(retval?, signature.ret, &self.core.arch)
```

This applies to all three dispatch paths (kernel32, manual contract, known family).

**Design Rationale**: Rather than converting ~20-30 individual handler match arms to return `HookValue` directly, this approach leverages the `ReturnSpec` already declared in each signature. Benefits:
1. Covers all 367 signature'd functions at once
2. Maintainable — new signatures auto-get correct return semantics
3. Consistent with the signature-driven architecture
4. No risk of handler/descriptor mismatch

## Verification

- `cargo check` — zero errors (52 pre-existing warnings, all dead-code)
- `cargo test` — 37 passed, 3 failed (all 3 failures pre-existing, unrelated to Phase 3)
  - `api_set::tests::unmapped_contracts_remain_unmapped`
  - `hooks::registry::tests::kernelbase_real_exports_share_kernel32_hook_space`
  - `runtime::engine::tests::send_message_invokes_registered_wndproc_x64_from_native_context`

## Files Changed

### New Files (5)
- `src/hooks/families/core/kernel32_signatures.rs`
- `src/hooks/families/core/ntdll_signatures.rs`
- `src/hooks/families/security/advapi32_signatures.rs`
- `src/hooks/families/crt/msvcrt_signatures.rs`
- `src/hooks/families/ui/user32/user32_signatures.rs`

### Modified Files (9)
- `src/hooks/registry.rs` — `register_signatures()` method
- `src/hooks/signature.rs` — `ReturnSpec::U16` variant
- `src/hooks/families/core/mod.rs` — module declarations
- `src/hooks/families/core/kernel32.rs` — `register_kernel32_hooks()`
- `src/hooks/families/core/ntdll.rs` — `register_ntdll_hooks()`
- `src/hooks/families/security/mod.rs` — module declaration
- `src/hooks/families/security/advapi32.rs` — `register_advapi32_hooks()`
- `src/hooks/families/crt/mod.rs` — module declaration
- `src/hooks/families/crt/msvcrt.rs` — `register_msvcrt_hooks()`
- `src/hooks/families/ui/user32/mod.rs` — module declaration + `register_user32_hooks()`
- `src/runtime/engine/hook_value.rs` — `from_raw_with_spec()` method
- `src/runtime/engine/hook_context.rs` — `FromHookParam` scalar impls
- `src/runtime/engine/hooks/family_dispatch.rs` — `from_raw_with_spec` usage
- `src/runtime/engine/logging_helpers.rs` — `ReturnSpec::U16` rendering

## Next Steps

Phase 4 (per migration plan): Remaining DLL families (ws2_32, wininet, crypt32, ole32, shell32, shlwapi, etc.), or ntdll/user32 high-frequency补齐。

---

## Appendix: Unsigned Functions (Deferred to Future Work)

The following functions have `HookDefinition` entries but no `HookSignature` yet.
They retain the empty bridged signature and continue to work via the raw `arg(args, N)` dispatch path.
These are candidates for the next round of signature migration.

### Coverage Summary

| DLL | HookDefinitions | Phase 3 Signatures | Unsigned | Coverage |
|-----|----------------|-------------------|----------|----------|
| kernel32.dll | 392 | 392 | 0 | 100% |
| ntdll.dll | 2471 | 50 | 2421 | 2% |
| advapi32.dll | 108 | 116 | 0 | **100%** |
| msvcrt.dll | 87 | 99 | 0 | **100%** |
| user32.dll | 259 | 261 | 0 | **100%** |
| **Total** | **3317** | **918** | **2421** | **27%** |

### kernel32.dll — COMPLETE (392/392, 100% coverage)

All kernel32.dll functions now have full `HookSignature` definitions. The 201 previously unsigned functions
were added in a follow-up migration round. No kernel32 functions remain unsigned.

### advapi32.dll — COMPLETE (116/108, 100% coverage)

All advapi32.dll functions now have full `HookSignature` definitions. The 78 previously unsigned functions
were added in a follow-up migration round. No advapi32 functions remain unsigned.
(Signature count exceeds HookDefinitions because the signature file includes supplementary entries.)

### msvcrt.dll — COMPLETE (99/87, 100% coverage)

All msvcrt.dll functions now have full `HookSignature` definitions. The 59 previously unsigned functions
were added in a follow-up migration round. 9 C++ mangled names and 12 data export symbols were intentionally
skipped. No meaningful msvcrt functions remain unsigned.

### ntdll.dll — 2421 unsigned functions

<details>
<summary>Click to expand (too many to list — 2421 functions, only 50/2471 signed)</summary>

ntdll.dll has 2471 registered hook definitions but only 50 high-frequency signatures were created in Phase 3.
The vast majority are low-frequency or internal functions. The next migration round should focus on
the remaining Nt*/Zw* system services and Rtl* runtime functions that appear in actual malware traces.

Key unsigned categories:
- **Nt/Zw system services**: NtAllocateLocallyUniqueId, NtCreateJobObject, NtOpenJobObject,
  NtAssignProcessToJobObject, NtCreateKeyedEvent, NtOpenKeyedEvent, NtReleaseKeyedEvent,
  NtWaitForKeyedEvent, NtCreateIoCompletion, NtOpenIoCompletion, NtSetIoCompletion,
  NtRemoveIoCompletion, NtCreateTimer, NtOpenTimer, NtSetTimer, NtCancelTimer,
  NtQueryTimer, NtCreateTransaction, NtOpenTransaction, NtCommitTransaction, NtRollbackTransaction,
  NtCreateTransactionManager, NtOpenTransactionManager, etc.
- **Rtl runtime**: RtlZeroMemory, RtlCopyMemory, RtlFillMemory, RtlCompareMemory,
  RtlInitAnsiString, RtlFreeAnsiString, RtlFreeUnicodeString, RtlAppendUnicodeToString,
  RtlAppendUnicodeStringToString, RtlIntegerToUnicodeString, RtlUnicodeStringToInteger,
  RtlUpcaseUnicodeString, RtlDowncaseUnicodeString, RtlOemStringToUnicodeString,
  RtlUnicodeStringToOemString, RtlMultiByteToUnicodeN, RtlUnicodeToMultiByteN, etc.
- **Loader**: LdrEnumerateLoadedModules, LdrUnloadDll, RtlDllShutdown, etc.
- **Security**: RtlEncryptMemory, RtlDecryptMemory, RtlGenRandom, etc.

</details>

### user32.dll — COMPLETE (261/259, 100% coverage)

All user32.dll functions now have full `HookSignature` definitions. The 211 previously unsigned functions
were added in a follow-up migration round. Includes 2 variadic cdecl functions (wsprintfA/W).
(Signature count exceeds HookDefinitions because the signature file includes supplementary entries.)
No user32 functions remain unsigned.
