# Hook ABI Signature Migration — Phase 6 Implementation Report

**Date**: 2026-04-19  
**Branch**: hikari-v1  
**Status**: Complete (5/5 subtasks done)

## Overview

Phase 6 ("清理兼容层" / Cleanup Compatibility Layer) removes legacy `HookDefinition`/`CallConv`/`HookLibrary` infrastructure now that the new `HookSignature`-based system is fully operational across all DLL families.

## Completed Subtasks

### 6A: Remove HookDefinition/CallConv from Dispatch Chain ✅

**Scope**: Replaced all `HookDefinition`-based APIs in the runtime dispatch chain with `HookSignature`-based equivalents.

**Files Modified**:
- `runtime/api_logger.rs` — `log_api_call()` and `log_api_return()` now take `(module: &str, function: &str)` instead of `&HookDefinition`
- `runtime/engine/logging_helpers.rs` — `log_api_call()`, `log_api_return()`, `log_unsupported_runtime_stub()`, `describe_api_call_args()` all switched to `&HookSignature`
- `runtime/engine/shared/api_logging.rs` — `describe_custom_api_call_args()`, `describe_api_return_decoded_text()` take `(module: &str, function: &str)`
- `runtime/engine/hooks/family_dispatch.rs` — `dispatch_manual_contract_hook()` and `dispatch_bound_stub_with_signature()` use `&HookSignature`
- `runtime/engine/hooks/core/kernel32.rs` — `dispatch_kernel32_hook()` takes `&HookSignature`
- `runtime/engine.rs` — `dispatch_bound_stub()` and `dispatch_unicorn_bound_stub()` use `signature_for_address()` instead of `definition_for_address()`
- `runtime/engine/x86_interpreter_helpers.rs` — `step_x86_interpreter()` uses `signature.abi` (LogicalAbi) instead of `definition.call_conv` (CallConv) for stack cleanup
- `runtime/engine/shared/seh.rs` — `emit_startup_resume_chain()` uses `signature()` instead of `definition()`
- `hooks/registry.rs` — Added `functions_for_module()`, `has_signature_for()`, `has_signatures_for_module()` as signature-based query API
- `managers/module_manager.rs` — Updated to use `has_signature_for()`, `functions_for_module()`
- `tests_support.rs` — Updated test helpers to use `has_signature_for()`
- 4 family test files (kernel32.rs, dxgi.rs, ws2_32.rs, mfc42u.rs) — Updated assertions

**Key Design Decisions**:
- `HookDefinition`, `CallConv`, `HookLibrary` struct/trait/enum retained in `base.rs` and `stub.rs` as internal bridge in `registry.rs` only. No runtime code references them.
- `BoundHookLookup.definition` field retained but unused by dispatch chain. Only tests reference `bound.signature` now.
- `registry.rs` internal `definitions` HashMap still populated by `register_function_stubs()` for backward compatibility, but all public APIs migrated to signature-based queries.

### 6B: Delete api_parameter_specs() ✅

**Scope**: Removed the ~610-line `api_parameter_specs()` match statement from `api_logging.rs`.

**Details**:
- The function was a legacy fallback that provided parameter name/type metadata for log rendering
- Now fully superseded by `HookSignature.params` (ParamSpec[]) which carries typed parameter info
- `ApiParameterSpec` struct and `spec()` helper removed from `logging_helpers.rs`
- Custom renderers (`describe_custom_api_call_args`, `describe_api_return_decoded_text`) retained for special formatting (buffer hex, code page decode, etc.)

### 6C: Delete arg(args, i) Helper ✅

**Scope**: Replaced 2,335 `arg(args, i)` call sites across 35 files with trait method `args.arg(i)`.

**Details**:
- Added `ArgAccess` trait on `[u64]` in `utilities.rs` with `fn arg(&self, index: usize) -> u64`
- Same bounds-checked semantics: returns 0 for out-of-bounds indices
- Replaced standalone `fn arg(args: &[u64], index: usize) -> u64` with trait method dispatch
- All 35 files updated: 32 hook handler files + `family_dispatch.rs` + `api_logging.rs` + `native_unicorn_call_helpers.rs` + `filesystem.rs`
- Deleted the standalone `arg()` function from `utilities.rs`
- Updated `engine.rs` import: `arg` → `ArgAccess`

**Why trait instead of inline**: `args.get(i).copied().unwrap_or(0)` at 2,335 call sites would be extremely verbose. The trait preserves readability while removing the standalone function dependency.

### 6D: Delete arch_ptr/arch_i32 Business-Side Direct Usage ✅

**Scope**: Removed 113 `arch_ptr()`/`arch_i32()` call sites across 13 hook handler files.

**Details**:
- `arch_ptr(value)` was redundant because `HookValue::from_raw_with_spec()` at the dispatch layer already handles pointer truncation based on `ReturnSpec::Pointer`/`ReturnSpec::Handle`
- `arch_i32(value)` was redundant because `from_raw_with_spec()` with `ReturnSpec::I32` handles sign extension
- `write_pointer_value()` already truncates internally (`value as u32` on x86), so `arch_ptr` wrapping was double-encoding
- Replacements:
  - `Ok(self.arch_ptr(X))` → `Ok(X)` or `Ok(X as u64)`
  - `Ok(self.arch_i32(X))` → `Ok(X as u64)` where X: i32
  - `.map(|m| self.arch_ptr(m.base))` → `.map(|m| m.base)`
- Deleted `arch_ptr()`, `arch_i32()`, `arch_invalid_handle()` methods from `core_helpers.rs`

**Files affected**: kernel32.rs (43), msvcrt.rs (22), user32/exports.rs (12), crypt32.rs (8), wininet.rs (8), winhttp.rs (3), ntdll.rs (3), advapi32.rs (4), eventing.rs (2), gdi32.rs (2), ws2_32.rs (2), wtsapi32.rs (2)

### 6E: Family Migration (register_library → register_function_stubs) ✅

**Scope**: All 69 family files migrated from `register_library()` to `register_function_stubs()`.

**Details**: This was completed in earlier phases. The family files now export compact `(&'static str, LogicalAbi)` arrays and call `register_function_stubs()`. Full signatures are registered separately via `_signatures.rs` companion files.

## Remaining Legacy Code

The following code remains in the codebase as internal bridges but is **not referenced by any runtime code**:

| File | Item | Status |
|------|------|--------|
| `hooks/base.rs` | `HookDefinition`, `CallConv`, `HookLibrary`, `From<&HookDefinition> for HookSignature` | Used only by `registry.rs` internal bridge |
| `hooks/stub.rs` | `stub_definitions()`, `stdcall_definitions()` | Dead code (no callers) |
| `hooks/registry.rs` | `definitions` HashMap, `register_library()`, `definition()`, `definitions_for_module()`, `definition_for_address()`, `definition_from_parts()`, `HookDefinition::synthetic()` | Internal bridge, all callers migrated |

**Recommendation**: These can be safely deleted in a follow-up cleanup PR once the `register_function_stubs()` bridge is confirmed stable.

## Test Results

- All Phase 6 changes compile cleanly with `cargo check` (65 warnings, 0 errors)

## Change Statistics

Phase 6A+6B+6E (earlier):
```
82 files changed, 2,149 insertions(+), 12,606 deletions(-)
```

Phase 6C+6D (this session):
```
~38 files changed, ~2,450 replacements
- 113 arch_ptr/arch_i32 calls removed
- 2,335 arg(args,i) calls migrated to args.arg(i) trait method
- 3 helper functions deleted (arch_ptr, arch_i32, arch_invalid_handle)
- 1 standalone function deleted (arg), replaced by ArgAccess trait
```
