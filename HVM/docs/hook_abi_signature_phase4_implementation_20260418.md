# Phase 4: Callback / Variadic / COM Migration — Implementation Report

**Date**: 2026-04-18
**Branch**: `hikari-v1`
**Scope**: Unified callback ABI, variadic function model, COM DLL signatures

## Summary

Phase 4 implements the fourth stage of the Hook ABI Signature migration plan: callback/virtual/COM support. The work is divided into 6 groups (A through F), each building on the previous.

Core deliverables:
1. **Callback type infrastructure** — `CallbackSignature`, `PreparedCallbackFrame`, `VariadicDecoderKind`, `ParamListKind`
2. **AbiAdapter callback extension** — `prepare_callback_frame()` method for x86 and x64
3. **Callback site migration** — 5 async callback types merged from x86/x64 split into unified functions
4. **Variadic function model** — signature definitions for printf/sprintf/wsprintf family, extended ABI capture
5. **Native bridge consolidation** — frame-building extracted into shared helpers
6. **COM DLL signatures** — 175 HookSignature definitions across 4 COM DLLs

## Deliverables

### Group A: Type Infrastructure

| New Type | File | Description |
|----------|------|-------------|
| `CallbackSignature` | `src/hooks/callback_signature.rs` | Static signature for callback function pointers (`abi`, `params`, `ret`) |
| `ENUM_WINDOWS_CALLBACK` | same | `BOOL CALLBACK EnumWindowsProc(HWND, LPARAM)` — 2 args, Bool32 return |
| `WNDPROC_CALLBACK` | same | `LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM)` — 4 args |
| `TIMERPROC_CALLBACK` | same | `VOID CALLBACK TimerProc(HWND, UINT, UINT_PTR, DWORD)` — 4 args, Void return |
| `INITTERM_CALLBACK` | same | `void _initterm_fn(void)` — 0 args, Void return |
| `LDR_ENUM_CALLBACK` | same | `VOID CALLBACK LdrEnumCallback(PLDR, PVOID, BOOLEAN*)` — 3 args, Void return |
| `PreparedCallbackFrame` | `src/runtime/engine/abi/frame.rs` | Result of `prepare_callback_frame()` — `new_sp`, `new_pc`, `save_callee_saved`, `callee_cleanup_bytes` |
| `VariadicDecoderKind` | `src/hooks/types.rs` | 8 variants: PrintfStyle, WprintfStyle, SprintfStyle, SwprintfStyle, WsprintfAStyle, WsprintfWStyle, FormatMessageStyle, Custom |
| `ParamListKind` | `src/hooks/signature.rs` | `Fixed(&[ParamSpec])` and `Variadic { fixed, decoder }` |

### Group B: AbiAdapter Extension

| Method | x86 Implementation | x64 Implementation |
|--------|--------------------|--------------------|
| `prepare_callback_frame()` | Stack frame: `[ret_addr(4B)] [args(4B each)]`; sets EIP, ESP | Shadow frame: `[ret_addr(8B)] [0x20 shadow] [stack_args(8B each)]`; sets RIP, RSP, RCX, RDX, R8, R9 |
| `write_return_value()` | Writes EAX | Writes RAX |
| `adjust_stack_after_call()` | stdcall: +4+argc*4; cdecl: +4 | +8 |

The `prepare_callback_frame()` uses `dyn FnMut` closures for register/memory access, consistent with the existing trait design.

### Group C: Callback Site Migration

5 async callback types migrated from x86/x64 split functions to unified `prepare_callback_frame()` calls:

| Callback | File | Old Functions (removed) | New Functions |
|----------|------|------------------------|---------------|
| EnumWindows | `hooks/ui/user32/enum_windows.rs` | `schedule_active_x64_user32_enumwindows_callback` + `schedule_active_x86_user32_enumwindows_callback` | `schedule_active_user32_enumwindows_callback` |
| SendMessage/WndProc | `hooks/ui/user32/messages.rs` | `schedule_active_x64_user32_sendmessage_callback` + `schedule_active_x86_user32_sendmessage_callback` | `schedule_active_user32_sendmessage_callback` |
| TimerProc | `hooks/ui/user32/timers.rs` | x64 + x86 schedule/complete | unified schedule/complete |
| _initterm | `hooks/crt/initterm.rs` | x64 + x86 schedule/complete | unified schedule/complete |
| LdrEnum | `hooks/core/ldr_enum.rs` | x64 + x86 schedule/complete | unified schedule/complete + `save_callee_saved_registers()` / `restore_callee_saved_registers()` helpers |

**Skipped (Group E scope)**: Windows Hooks, TLS callbacks, _onexit — these use synchronous `call_native_with_entry_frame()` and don't have inline frame preparation.

### Group D: Variadic Function Model

| Item | File | Description |
|------|------|-------------|
| `VariadicArgReader` | `src/runtime/engine/hook_context.rs` | Sequential reader for variadic args beyond fixed prefix. Methods: `next()`, `next_ptr()`, `read_count()`, `reset()`, `available()` |
| 11 variadic signatures | `src/hooks/families/crt/variadic_signatures.rs` | wsprintfA/W, printf, wprintf, sprintf, swprintf_s, sscanf, _vsnwprintf, vsprintf, _vsnprintf, FormatMessageW |
| Extended ABI capture | `src/runtime/engine/abi/x86.rs`, `x64.rs` | When `HookFlags::VARIADIC` is set, reads `argc + 16` args instead of just `argc` |

### Group E: Native Bridge Consolidation

| Helper | File | Description |
|--------|------|-------------|
| `build_x86_native_frame()` | `src/runtime/engine/native_call_helpers.rs` | Builds x86 frame bytes `[ret_addr(4B)] [args(4B each)]` + computes new_esp |
| `build_x64_native_frame()` | same | Builds x64 frame bytes `[ret_addr(8B)] [0x20 shadow] [stack_args(8B each)]` + computes new_rsp |

Used by:
- `call_x86_native_with_unicorn_context()` — replaced inline frame building
- `call_x64_native_with_unicorn_context()` — replaced inline frame building
- `call_x86_native_interpreter_context()` — replaced inline frame building

### Group F: COM DLL Signatures

| DLL | Signatures | File |
|-----|-----------|------|
| combase.dll | 26 | `src/hooks/families/com/combase_signatures.rs` |
| ole32.dll | 52 | `src/hooks/families/com/ole32_signatures.rs` |
| oleaut32.dll | 65 | `src/hooks/families/com/oleaut32_signatures.rs` |
| rpcrt4.dll | 32 | `src/hooks/families/com/rpcrt4_signatures.rs` |
| **Total** | **175** | |

## Coverage Summary (After Phase 4)

| DLL | Phase 3 Signatures | Phase 4 Signatures | Total | HookDefinitions | Coverage |
|-----|-------------------|-------------------|-------|----------------|----------|
| kernel32.dll | 392 | +1 (FormatMessageW) | 393 | 392 | 100% |
| ntdll.dll | 671 | — | 671 | 2471 | 27% |
| advapi32.dll | 116 | — | 116 | 108 | 100% |
| msvcrt.dll | 99 | +10 (variadic) | 109 | 87 | 100% |
| user32.dll | 261 | +2 (wsprintfA/W) | 263 | 259 | 100% |
| combase.dll | — | +26 | 26 | 26 | 100% |
| ole32.dll | — | +52 | 52 | 52 | 100% |
| oleaut32.dll | — | +65 | 65 | 65 | 100% |
| rpcrt4.dll | — | +32 | 32 | 32 | 100% |
| **Total** | **1539** | **+188** | **1727** | **3494** | **49%** |

## New Files

1. `src/hooks/callback_signature.rs` — CallbackSignature struct + 5 static instances
2. `src/hooks/families/crt/variadic_signatures.rs` — 11 variadic function signatures
3. `src/hooks/families/com/combase_signatures.rs` — 26 combase.dll signatures
4. `src/hooks/families/com/ole32_signatures.rs` — 52 ole32.dll signatures
5. `src/hooks/families/com/oleaut32_signatures.rs` — 65 oleaut32.dll signatures
6. `src/hooks/families/com/rpcrt4_signatures.rs` — 32 rpcrt4.dll signatures

## Modified Files

| File | Changes |
|------|---------|
| `src/hooks/types.rs` | Added `VariadicDecoderKind` enum |
| `src/hooks/signature.rs` | Added `ParamListKind` enum |
| `src/hooks/mod.rs` | Added `pub mod callback_signature;` |
| `src/runtime/engine/abi/frame.rs` | Added `PreparedCallbackFrame` struct |
| `src/runtime/engine/abi/adapter.rs` | Added `prepare_callback_frame()` to `AbiAdapter` trait |
| `src/runtime/engine/abi/x86.rs` | Implemented `prepare_callback_frame()` + variadic capture extension |
| `src/runtime/engine/abi/x64.rs` | Implemented `prepare_callback_frame()` + variadic capture extension |
| `src/runtime/engine/abi/mod.rs` | Updated re-exports |
| `src/runtime/engine/hook_context.rs` | Added `VariadicArgReader` |
| `src/runtime/engine/hooks/ui/user32/enum_windows.rs` | Merged x86/x64 callback functions |
| `src/runtime/engine/hooks/ui/user32/messages.rs` | Merged x86/x64 callback functions |
| `src/runtime/engine/hooks/ui/user32/timers.rs` | Merged x86/x64 callback functions |
| `src/runtime/engine/hooks/crt/initterm.rs` | Merged x86/x64 callback functions |
| `src/runtime/engine/hooks/core/ldr_enum.rs` | Merged x86/x64 callback functions + callee-saved helpers |
| `src/runtime/engine/native_call_helpers.rs` | Added `build_x86_native_frame()`, `build_x64_native_frame()` |
| `src/runtime/engine/native_unicorn_call_helpers.rs` | Used shared frame builders |
| `src/hooks/families/crt/mod.rs` | Added `pub mod variadic_signatures;` |
| `src/hooks/families/crt/msvcrt.rs` | Registered variadic signatures |
| `src/hooks/families/core/kernel32.rs` | Registered FormatMessageW signature |
| `src/hooks/families/ui/user32/mod.rs` | Registered wsprintfA/W signatures |
| `src/hooks/families/com/mod.rs` | Added 4 signature module declarations |
| `src/hooks/families/com/combase.rs` | Registered signatures |
| `src/hooks/families/com/ole32.rs` | Registered signatures |
| `src/hooks/families/com/oleaut32.rs` | Registered signatures |
| `src/hooks/families/com/rpcrt4.rs` | Registered signatures |

## Verification

- `cargo check` — zero errors (60 pre-existing warnings)
- `cargo test --lib` — 37 passed, 3 failed (all 3 failures pre-existing, unrelated to Phase 4)

## Next Steps

Per the migration plan, the next phases are:

- **Phase 5**: Full family migration (network, shell_services, device, security remaining, graphics, diagnostics, installer, print)
- **Phase 6**: Cleanup — remove `HookDefinition`, `api_parameter_specs()`, `arg(args, i)` helper, redundant `arch_ptr`/`arch_i32` direct usage
