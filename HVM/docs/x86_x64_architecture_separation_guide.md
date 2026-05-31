# x86/x64 Architecture Separation — Development Guide

## 1. Background

HVM emulates both x86 (32-bit) and x64 (64-bit) PE samples. The two architectures differ in:

| Dimension | x86 | x64 |
|-----------|-----|-----|
| Pointer size | 4 bytes | 8 bytes |
| Return register | EAX | RAX |
| Stack pointer | ESP | RSP |
| Instruction pointer | EIP | RIP |
| Calling convention | cdecl/stdcall (stack args) | Win64 (RCX/RDX/R8/R9 + stack) |
| PEB field offsets | compact (small pointers) | spread (8-byte pointers) |
| INVALID_HANDLE_VALUE | `0xFFFFFFFF` | `0xFFFFFFFFFFFFFFFF` |

When these differences are not handled correctly, x86 samples silently break:
- Structure field reads return wrong values.
- Function returns are truncated or sign-extended incorrectly.
- Callback parameters land in the wrong registers/stack slots.

## 2. Already Correctly Separated Areas

The following areas use the `_for_arch()` / `is_x86()` / `pointer_size()` pattern
and **require no changes**:

| Area | File | Mechanism |
|------|------|-----------|
| TEB offsets | `runtime/windows_env/thread/layout.rs` | `teb_offsets_for_arch()` |
| PEB offsets | `runtime/windows_env/process/peb.rs` | `peb_offsets_for_arch()` |
| ProcessParameters offsets | `runtime/windows_env/process/parameters/layout.rs` | `process_parameters_offsets_for_arch()` |
| LDR entry/header offsets | `runtime/windows_env/process/loader/layout/schema.rs` | Cached in `ProcessEnvironmentOffsets` |
| Pointer read/write | `runtime/windows_env/memory/io/reads.rs` + `writes.rs` | `pointer_size()` branch |
| Hook dispatch args | `runtime/engine.rs:1810-1893` | x86 reads stack, x64 reads registers |
| Hook dispatch return | `runtime/engine.rs:1909-2006` | x86 writes EAX, x64 writes RAX |
| SEH constants | `runtime/engine/shared/seh.rs` | Separate X86_*/X64_* constants |
| GDT / segment regs | `runtime/engine/unicorn_helpers.rs:124-133` | x86: GDT+FS, x64: GS_BASE |
| NtQueryInformationProcess | `runtime/engine/shared/system/processes.rs` | arch-specific struct sizes |
| PE header synthesis | `hooks/registry.rs` | `is_x64` branch |
| UNICODE_STRING descriptor | `runtime/windows_env/process/parameters/strings.rs:26` | `pointer_size()` for buffer offset |
| Heap anti-debug flags | `managers/heap_manager.rs:71-79` | Writes both x86 and x64 offsets |
| mfc42u register access | `runtime/engine/hooks/ui/mfc42u.rs` | All behind `is_x64()` guards |

## 3. Changes Made in This Batch

### 3.1 PEB Anti-Debug Fields

**File**: `runtime/windows_env/process/peb.rs`, `core/layout.rs`, `core/offsets.rs`

Added to `PebOffsetGroup` / `ProcessEnvironmentOffsets`:

| Field | x86 offset | x64 offset |
|-------|-----------|-----------|
| `being_debugged` | 0x02 | 0x02 |
| `nt_global_flag` | 0x68 | 0xBC |
| `number_of_heaps` | 0x1C | 0x38 |
| `process_heaps` | 0x20 | 0x40 |

Usage: `self.offsets().peb_being_debugged`, `self.offsets().peb_nt_global_flag`, etc.

### 3.2 Return Value Abstraction Layer

**File**: `runtime/engine/hook_value.rs` (new), `runtime/engine/core_helpers.rs`

Added `HookValue` type with architecture-aware constructors:

```
HookValue::ptr(addr, arch)         → auto-truncate for x86
HookValue::handle(val, arch)       → auto sign-extend for x64
HookValue::invalid_handle(arch)    → 0xFFFFFFFF or 0xFFFFFFFFFFFFFFFF
HookValue::i32(val, arch)          → sign-extend for x64
HookValue::win32_error(code)       → no conversion needed
HookValue::ntstatus(status)        → no conversion needed
HookValue::raw(val)                → pass-through (backward compat)
```

Engine helper methods on `VirtualExecutionEngine`:

```
self.arch_ptr(value)               → truncate to pointer width
self.arch_invalid_handle()         → architecture-correct INVALID_HANDLE_VALUE
self.arch_i32(value)               → sign-extend i32 to u64
```

### 3.3 Callback Invocation x86 Support

**Files**: `runtime/engine/hooks/ui/user32/timers.rs`, `messages.rs`, `runtime/engine/hooks/crt/initterm.rs`

Added x86 calling convention paths alongside existing x64:

- **x86**: Push args onto stack → set EIP/ESP → on return restore EAX/ESP/EIP
- **x64**: Keep existing RCX/RDX/R8/R9 register setup

Functions added per file:

| File | x86 schedule function | x86 complete function |
|------|----------------------|-----------------------|
| `timers.rs` | `schedule_active_x86_user32_timer_callback` | `complete_active_x86_user32_timer_callback` |
| `messages.rs` | `schedule_active_x86_user32_sendmessage_callback` | `complete_active_x86_user32_sendmessage_callback` |
| `initterm.rs` | `schedule_active_x86_msvcrt_initterm_callback` | `complete_active_x86_msvcrt_initterm_callback` |

### 3.4 LDR Offsets Cached

**Files**: `runtime/windows_env/core/layout.rs`, `core/offsets.rs`, `process/loader/layout/schema.rs`

Moved LDR offset computation from per-call `is_x86()` branches into
`ProcessEnvironmentOffsets` at initialization time. The existing methods
`loader_entry_offsets()`, `loader_header_layout()`, `loader_entry_size()`
now delegate to cached values — all callers unchanged.

---

## 4. Hook Return Value Migration Guide

### 4.1 The Problem

All hook handlers currently return `Result<u64, VmError>`. The dispatch layer
writes this `u64` to EAX (x86) or RAX (x64). This works for simple cases
but breaks for values whose semantics differ by architecture:

| Scenario | Current code | Problem on x86 | Problem on x64 |
|----------|-------------|----------------|----------------|
| Return a handle | `Ok(handle as u64)` | May have high bits set | Needs sign-extension |
| Return INVALID_HANDLE_VALUE | `Ok(0xFFFFFFFF)` | OK | Wrong — should be `0xFFFFFFFFFFFFFFFF` |
| Return -1 (signed) | `Ok(-1i32 as u64)` → `0xFFFFFFFF` | OK | Missing sign extension → `0x00000000FFFFFFFF` |
| Return a pointer | `Ok(ptr as u64)` | Usually OK | OK |
| Return an error code | `Ok(error_code as u64)` | OK (fits u32) | OK (fits u32) |

### 4.2 HookValue Type

The `HookValue` type (in `runtime/engine/hook_value.rs`) solves this.
Each constructor takes `&ArchSpec` and produces the correct `u64` for the
guest architecture.

**Phase 1** (current): `HookValue` is defined but not yet integrated into the
dispatch return path. Hook authors use `self.arch_*()` helpers.

**Phase 2** (future): Change dispatch signature to accept `Result<HookValue, VmError>`.
The dispatch calls `.into_raw()` internally. Old hooks continue working via `From<u64>`.

### 4.3 Migration Patterns

For each hook handler, identify what kind of value it returns and apply
the corresponding pattern:

#### Pattern A: Boolean / Success/Failure (no change needed)

```rust
// BEFORE (correct for both archs):
("kernel32.dll", "CloseHandle") => Ok(1),
("kernel32.dll", "DeleteFileW") => Ok(0),

// AFTER (optional, more explicit):
("kernel32.dll", "CloseHandle") => Ok(HookValue::from_bool(true).into_raw()),
```

**Priority**: Low. No correctness issue.

#### Pattern B: Win32 Error Code / NTSTATUS (no change needed)

```rust
// BEFORE (correct for both archs — fits in u32):
Ok(STATUS_SUCCESS as u64)
Ok(ERROR_ACCESS_DENIED as u64)

// AFTER (optional):
Ok(HookValue::ntstatus(STATUS_SUCCESS).into_raw())
```

**Priority**: Low. No correctness issue.

#### Pattern C: Pointer Return (MUST migrate)

```rust
// BEFORE (may overflow for x86 if high bits set):
("kernel32.dll", "GetProcessHeap") => Ok(self.process_memory.heaps.process_heap() as u64),

// AFTER:
("kernel32.dll", "GetProcessHeap") => Ok(self.arch_ptr(self.process_memory.heaps.process_heap())),
```

**Priority**: Medium. Breaks if heap base exceeds 4GB (unlikely but possible).

#### Pattern D: Handle with Sign-Extension (MUST migrate)

```rust
// BEFORE (no sign extension):
("kernel32.dll", "GetCurrentProcess") => Ok(self.current_process_pseudo_handle()),
// This already uses sign_extend_win32_handle_for_arch internally — correct.

// AFTER (using HookValue directly):
("kernel32.dll", "GetCurrentProcess") => {
    let handle = HookValue::handle(PROCESS_HANDLE_PSEUDO, self.core.arch);
    Ok(handle.into_raw())
}
```

**Priority**: Medium. Already handled for pseudo-handles, but other handle returns
may not be.

#### Pattern E: INVALID_HANDLE_VALUE / -1 (MUST migrate)

```rust
// BEFORE (hardcoded — wrong on one arch):
Ok(0xFFFFFFFF)  // Correct for x86, wrong for x64

// AFTER:
Ok(self.arch_invalid_handle())

// or with HookValue:
Ok(HookValue::invalid_handle(self.core.arch).into_raw())
```

**Priority**: High. Currently incorrect for x64.

#### Pattern F: Signed i32 Return (MUST migrate)

```rust
// BEFORE (loses sign extension on x64):
Ok(-1i32 as u64)  // = 0x00000000FFFFFFFF — wrong on x64!

// AFTER:
Ok(self.arch_i32(-1))
```

**Priority**: High. Wrong on x64.

#### Pattern G: Pointer-Sized Value Read From Memory

When a hook reads a pointer-sized argument and later returns it:

```rust
// BEFORE:
Ok(arg(args, 0))  // arg() already zero-extends for x86

// AFTER (no change needed — dispatch truncates for x86):
Ok(arg(args, 0))
```

**Priority**: Low. Dispatch handles truncation.

### 4.4 Migration Priority by Hook File

| File | Returns | High-Priority Patterns | Count |
|------|---------|----------------------|-------|
| `hooks/core/kernel32.rs` | 62 | Handles (D), ptrs (C), -1 (E) | ~15 |
| `hooks/ui/user32/exports.rs` | 20 | Handles (D), ptrs (C) | ~8 |
| `hooks/core/ntdll.rs` | 7 | Handles (D), ptrs (C) | ~4 |
| `hooks/crt/msvcrt.rs` | 8 | ptrs (C) | ~4 |
| `hooks/shell_services/shell32.rs` | 5 | ptrs (C) | ~2 |
| `hooks/security/crypt32.rs` | 5 | Handles (C/D) | ~3 |
| `hooks/graphics/gdi32.rs` | 5 | Handles (D) | ~2 |
| Others (13 files) | 1-4 each | Mostly bools/ints | Low |

**Recommended migration order**:
1. `kernel32.rs` — highest impact, most return patterns
2. `ntdll.rs` — handles and pointers from NT API
3. `user32/exports.rs` — window/message handles
4. `msvcrt.rs` — memory allocation pointers
5. Remaining files — mostly low-priority bool/error returns

### 4.5 How to Migrate a Hook File

For each `=> Ok(...)` return in the hook dispatch:

1. **Classify** the return value type: bool / error code / pointer / handle / signed int
2. **Check** if it uses `as u64` on a value that could differ by architecture
3. **Replace** with the appropriate `self.arch_*()` call or `HookValue` constructor
4. **Verify** with `cargo test` after each file

Example migration of a kernel32 hook:

```rust
// BEFORE:
("kernel32.dll", "GetModuleHandleW") => {
    let module_base = self.resolve_module_base(arg(args, 0));
    Ok(module_base.unwrap_or(0))
}

// AFTER:
("kernel32.dll", "GetModuleHandleW") => {
    let module_base = self.resolve_module_base(arg(args, 0));
    Ok(module_base.map(|b| self.arch_ptr(b)).unwrap_or(0))
}
```

---

## 5. Architecture-Aware Offset Usage

### 5.1 Accessing Offsets

All architecture-dependent structure offsets are centralized in
`ProcessEnvironmentOffsets` (at `runtime/windows_env/core/layout.rs`).

From any code that has access to `WindowsProcessEnvironment`:

```rust
let offsets = self.process_env().offsets();
let peb_ldr_offset = offsets.peb_ldr;          // usize
let teb_peb_offset = offsets.teb_peb;          // usize
let ldr_entry_dll_base = offsets.ldr_entry_dll_base;  // u64
```

### 5.2 Adding a New Structure Offset

When you need to mirror a new Windows structure field:

1. Add the field to the appropriate `*OffsetGroup` struct:
   - TEB fields → `runtime/windows_env/thread/layout.rs` (`TebOffsetGroup`)
   - PEB fields → `runtime/windows_env/process/peb.rs` (`PebOffsetGroup`)
   - ProcessParameters → `runtime/windows_env/process/parameters/layout.rs`
   - LDR fields → `runtime/windows_env/core/layout.rs` (LDR section)

2. Add x86 and x64 offset values in the corresponding `_for_arch()` function.

3. Add the field to `ProcessEnvironmentOffsets` struct in `core/layout.rs`.

4. Wire it up in `core/offsets.rs` `offsets_for_arch()`.

5. Use it via `self.offsets().field_name` everywhere.

### 5.3 Architecture Reference: Key Windows Structures

#### PEB (Process Environment Block)

| Field | x86 offset | x64 offset | Type |
|-------|-----------|-----------|------|
| BeingDebugged | 0x02 | 0x02 | BYTE |
| ImageBaseAddress | 0x08 | 0x10 | PVOID |
| Ldr | 0x0C | 0x18 | PPEB_LDR_DATA |
| ProcessParameters | 0x10 | 0x20 | PRTL_USER_PROCESS_PARAMETERS |
| ProcessHeap | 0x18 | 0x30 | PVOID |
| NumberOfHeaps | 0x1C | 0x38 | ULONG |
| ProcessHeaps | 0x20 | 0x40 | PVOID* |
| TlsBitmap | 0x40 | 0x78 | PVOID |
| NtGlobalFlag | 0x68 | 0xBC | ULONG |

#### TEB (Thread Environment Block)

| Field | x86 offset | x64 offset | Type |
|-------|-----------|-----------|------|
| ExceptionList | 0x00 | 0x00 | PVOID |
| StackBase | 0x04 | 0x08 | PVOID |
| StackLimit | 0x08 | 0x10 | PVOID |
| Self | 0x18 | 0x30 | PVOID |
| ClientId | 0x20 | 0x40 | PVOID |
| TlsPointer | 0x2C | 0x58 | PVOID |
| TlsSlots | 0xE10 | 0x1480 | PVOID[] |
| Peb | 0x30 | 0x60 | PVOID |
| LastErrorValue | 0x34 | 0x68 | ULONG |

#### LDR_DATA_TABLE_ENTRY

| Field | x86 offset | x64 offset | Type |
|-------|-----------|-----------|------|
| InLoadOrderLinks | 0x00 | 0x00 | LIST_ENTRY |
| InMemoryOrderLinks | 0x08 | 0x10 | LIST_ENTRY |
| InInitializationOrderLinks | 0x10 | 0x20 | LIST_ENTRY |
| DllBase | 0x18 | 0x30 | PVOID |
| EntryPoint | 0x1C | 0x38 | PVOID |
| SizeOfImage | 0x20 | 0x40 | ULONG |
| FullDllName | 0x24 | 0x48 | UNICODE_STRING |
| BaseDllName | 0x2C | 0x58 | UNICODE_STRING |

Entry size: x86 = 0x38, x64 = 0x100

#### RTL_USER_PROCESS_PARAMETERS

| Field | x86 offset | x64 offset | Type |
|-------|-----------|-----------|------|
| MaximumLength | 0x00 | 0x00 | ULONG |
| Length | 0x04 | 0x04 | ULONG |
| CurrentDirectory | 0x24 | 0x38 | UNICODE_STRING (curdir) |
| DllPath | 0x30 | 0x50 | UNICODE_STRING |
| ImagePathName | 0x38 | 0x60 | UNICODE_STRING |
| CommandLine | 0x40 | 0x70 | UNICODE_STRING |
| Environment | 0x48 | 0x80 | PVOID |

#### Heap Header (anti-debug)

| Field | x86 offset | x64 offset | Type |
|-------|-----------|-----------|------|
| Flags | 0x40 | 0x70 | ULONG |
| ForceFlags | 0x44 | 0x74 | ULONG |

Normal values: Flags=HEAP_GROWABLE(2), ForceFlags=0.
Debugged values: Flags=0x50000062, ForceFlags=0x40000060.

---

## 6. x86 Callback Invocation Pattern

When adding new callback invocations (timer procs, window procs, init callbacks),
use this template:

### x64 (existing)

```rust
// Set up registers per Win64 calling convention
for (regid, value, op) in [
    (UC_X86_REG_RIP, callback, "uc_reg_write(rip)"),
    (UC_X86_REG_RSP, call_rsp, "uc_reg_write(rsp)"),
    (UC_X86_REG_RCX, arg0, "uc_reg_write(rcx)"),
    (UC_X86_REG_RDX, arg1, "uc_reg_write(rdx)"),
    (UC_X86_REG_R8, arg2, "uc_reg_write(r8)"),
    (UC_X86_REG_R9, arg3, "uc_reg_write(r9)"),
] {
    unsafe { api.reg_write_raw(uc, regid, value) }
        .map_err(|detail| VmError::NativeExecution { op, detail })?;
}

// On completion, restore:
for (regid, value, op) in [
    (UC_X86_REG_RAX, retval, "uc_reg_write(rax)"),
    (UC_X86_REG_RSP, state.resume_rsp, "uc_reg_write(rsp)"),
    (UC_X86_REG_RIP, state.return_address, "uc_reg_write(rip)"),
] { ... }
```

### x86 (new)

```rust
// Push args + return address onto stack (cdecl / stdcall)
let frame_size = num_args * 4 + 4; // 4 bytes per arg + return address
let call_esp = esp.checked_sub(frame_size).ok_or(...)?;
let mut frame = Vec::new();
frame.extend_from_slice(&continuation.to_le_bytes()[..4]); // return address
for arg in args {
    frame.extend_from_slice(&(arg as u32).to_le_bytes());
}
// Write frame to memory and unicorn
self.core.modules.memory_mut().write(call_esp, &frame)?;
unsafe { api.mem_write_raw(uc, call_esp, &frame) }?;
unsafe { api.reg_write_raw(uc, UC_X86_REG_ESP, call_esp) }?;
unsafe { api.reg_write_raw(uc, UC_X86_REG_EIP, callback) }?;

// On completion, restore:
for (regid, value, op) in [
    (UC_X86_REG_EAX, retval, "uc_reg_write(eax)"),
    (UC_X86_REG_ESP, state.resume_rsp, "uc_reg_write(esp)"),
    (UC_X86_REG_EIP, state.return_address, "uc_reg_write(eip)"),
] { ... }
```

### Dispatch guard pattern

At the call site, branch by architecture:

```rust
if unicorn_context_active() {
    if self.core.arch.is_x64() {
        self.schedule_x64_callback(...)?;
    } else {
        self.schedule_x86_callback(...)?;
    }
    return Ok(0);
}
// Fallback for non-inline context:
self.call_native_with_entry_frame(callback, &args)?
```

---

## 7. Checklist for Adding New x86/x64 Dependent Code

- [ ] Does the code access a Windows structure by offset? → Use `self.offsets().field_name`
- [ ] Does the code read/write a pointer? → Use `read_pointer_value()` / `write_pointer_value()`
- [ ] Does the code return a handle to the guest? → Use `self.arch_ptr()` or `HookValue::handle()`
- [ ] Does the code return -1 or INVALID_HANDLE_VALUE? → Use `self.arch_invalid_handle()`
- [ ] Does the code invoke a guest callback? → Add both x86 and x64 paths
- [ ] Does the code use a register directly? → Use `return_value_register()`, `stack_pointer_register()`, `instruction_pointer_register()`
- [ ] Does the code write a structure to memory? → Use `write_pointer_value()` for pointer-sized fields, not `write_u32()`
