# Hook ABI Signature Migration — Phase 1 Implementation Report

> 关联原文档: `HVM/docs/hook_abi_signature_migration_plan_20260417.md`
> 实施阶段: **阶段 1 — 接通主分发链路**
> 实施日期: 2026-04-18
> 前置阶段: 阶段 0 — 设计冻结与脚手架（已完成）
> 状态: 已完成

---

## 1. 概述

阶段 1 的目标是将 Phase 0 建立的类型脚手架（`HookSignature` / `AbiAdapter` / `RawCallFrame` / `HookValue`）接入主分发链路。主分发入口不再直接操作 Unicorn 寄存器进行 x86/x64 参数提取和返回值写回，而是通过 `AbiAdapter` trait 统一处理。

核心变化：
- Registry 同时存储 `HookSignature` 与 `HookDefinition`
- `dispatch_bound_stub_with_definition` 返回 `Result<HookValue, VmError>` 而非 `Result<u64, VmError>`
- `dispatch_unicorn_bound_stub` 使用 `select_adapter()` + `AbiAdapter` 方法替代 inline x86/x64 逻辑
- `dispatch_bound_stub` 公共 API 保持 `Result<u64, VmError>` 不变，外部调用点零改动

验收标准：
- `cargo check` 零错误
- `cargo test` 无新增失败（原有 3 个预存失败不变）
- 新老模型可并行存在

---

## 2. 文件改动清单

### 2.1 `src/hooks/registry.rs` — Registry 存储 HookSignature

**新增字段:**

```rust
pub struct HookRegistry {
    next_stub: u64,
    definitions: HashMap<(String, String), HookDefinition>,
    signatures: HashMap<(String, String), HookSignature>,   // ← 新增
    bindings_by_name: HashMap<(String, String), u64>,
    bindings_by_address: HashMap<u64, (String, String)>,
    import_bindings_by_thunk: HashMap<u64, ImportThunkBinding>,
}
```

**新增方法:**

| 方法 | 说明 |
|------|------|
| `signature_for_address(&self, address: u64) -> Option<&HookSignature>` | 根据已绑定的 stub 地址查找签名 |
| `signature(&self, module: &str, function: &str) -> Option<&HookSignature>` | 根据模块名+函数名查找签名 |
| `signature_from_key(&self, key: &(String, String)) -> Option<&HookSignature>` | 内部：从 normalized key 查找 |
| `signature_from_parts(&self, module: &str, function: &str) -> Option<&HookSignature>` | 内部：带 hook-space 映射的查找 |

**修改方法:**

- `register_library()` — 每条 `HookDefinition` 同时通过 `From<&HookDefinition>` 桥接写入 `signatures` map
- `for_tests()` — 新增 `signatures: HashMap::new()`
- `bound_lookup()` — 填充新增的 `signature` 字段

**BoundHookLookup 新增字段:**

```rust
pub struct BoundHookLookup<'a> {
    pub module: &'a str,
    pub function: &'a str,
    pub definition: Option<&'a HookDefinition>,
    pub signature: Option<&'a HookSignature>,   // ← 新增
}
```

**签名查找逻辑:** `signature_from_parts` 与 `definition_from_parts` 采用相同的查找策略：
1. 直接 lowercase 匹配
2. `normalized_hook_space_module()` 映射匹配
3. 线性扫描 `modules_share_hook_space` 匹配

**新增 import:** `use crate::hooks::signature::HookSignature;`

---

### 2.2 `src/runtime/engine/hooks/family_dispatch.rs` — 核心 dispatch 返回 HookValue

**函数签名变化:**

```rust
// 旧:
pub(super) fn dispatch_bound_stub_with_definition(
    &mut self, definition: &HookDefinition, stub_address: u64,
    return_address: Option<u64>, args: &[u64],
) -> Result<u64, VmError>

// 新:
pub(super) fn dispatch_bound_stub_with_definition(
    &mut self, definition: &HookDefinition, _signature: &HookSignature,
    stub_address: u64, return_address: Option<u64>, args: &[u64],
) -> Result<HookValue, VmError>
```

**新增 import:**
```rust
use crate::hooks::signature::HookSignature;
```

（`HookValue` 通过 `super::*` 访问，来自 `engine.rs` 的 `pub(super) use hook_value::HookValue;`）

**内部改造:**

- 内部 37 个 `dispatch_xxx_hook` 函数仍返回 `Option<Result<u64, VmError>>`，通过 `HookValue::from(retval?)` 自动转换
- `HookValue` 实现了 `From<u64>` / `From<u32>` / `From<i32>`，所有旧 handler 的 `Ok(N)` 返回值自动适配
- 未知 API 返回 `HookValue::Raw(0)` 而非 `Ok(0)`
- `log_api_call()` 仍接收 `&HookDefinition`（不变）
- `log_api_return()` 接收 `retval.into_raw_u64()` 作为 `u64` 参数（不变）
- 诊断 `eprintln!` 中 `retval` 格式化改为 `retval.into_raw_u64()`

**未改动:** 所有 37 个 `dispatch_xxx_hook` 内部实现、`log_api_call`、`log_api_return` 签名

---

### 2.3 `src/runtime/engine.rs` — 主分发链路 AbiAdapter 接入

**新增 import:**

```rust
use crate::hooks::signature::HookSignature;
use abi::select_adapter;
pub(super) use hook_value::HookValue;
```

**`dispatch_bound_stub()` 改造 (line ~1928):**

- 内部从 `signature_for_address()` 获取 `HookSignature`
- 若 registry 中无签名（理论上不会发生），通过 `HookSignature::from(&definition)` 桥接
- 调用 `dispatch_bound_stub_with_definition` 后用 `.map(|hv| hv.into_raw_u64())` 转回 `u64`
- **公共 API 签名 `Result<u64, VmError>` 不变**

```rust
let signature = self.core.hooks.signature_for_address(address)
    .cloned()
    .unwrap_or_else(|| HookSignature::from(&definition));
self.dispatch_bound_stub_with_definition(&definition, &signature, address, None, args)
    .map(|hv| hv.into_raw_u64())
```

**`dispatch_unicorn_bound_stub()` 改造 (line ~1963):**

这是本次改动最核心的部分。原来的 inline x86/x64 参数提取（约 90 行）被替换为 `AbiAdapter` 调用。

**改造前（已删除的代码逻辑）:**

1. `if self.core.arch.is_x86()` 分支手动读取 ESP + 栈内存
2. `else` (x64) 分支手动读取 RSP + RCX/RDX/R8/R9 + 栈内存
3. 返回值直接 `api.reg_write_raw(uc, UC_X86_REG_EAX/RAX, retval)`
4. 栈清理通过 `match definition.call_conv { Stdcall/Cdecl/Win64 }` 硬编码

**改造后:**

```rust
let signature = signature.unwrap_or_else(|| HookSignature::from(&definition));

// 1. 保存 x86 非易失寄存器（engine 层关注点，不属于 ABI adapter）
let saved_x86_nonvolatile = if self.core.arch.is_x86() {
    Some((ebx, ebp, esi, edi))  // 读取 EBX/EBP/ESI/EDI
} else { None };

// 2. 通过 AbiAdapter 抓取调用帧
let adapter = select_adapter(&self.core.arch, &signature.abi);
let frame = {
    let mut reg_read = |regid: i32| unsafe { api.reg_read_raw(uc, regid) };
    let mut mem_read = |addr, size| unsafe { api.mem_read_raw(uc, addr, size) };
    adapter.capture_call_frame(&self.core.arch, &signature, &mut reg_read, &mut mem_read)?
};

let return_address = frame.return_address.unwrap_or(0);
let stack_pointer = frame.stack_pointer;
let args: Vec<u64> = frame.args.to_vec();

// 3. 调用 dispatch（返回 HookValue）
let retval = self.dispatch_bound_stub_with_definition(
    &definition, &signature, address, Some(return_address), &args,
)?;

// 4. 返回值编码 + 写回
let raw_retval = retval.into_raw(&self.core.arch);
{
    let mut reg_write = |regid, value| unsafe { api.reg_write_raw(uc, regid, value) };
    adapter.write_return_value(&self.core.arch, raw_retval, &mut reg_write)?;
}

// 5. 特殊路径: VerSetConditionMask EDX 写回（保留）
if self.core.arch.is_x86() && definition.function == "VerSetConditionMask" {
    api.reg_write_raw(uc, UC_X86_REG_EDX, raw_retval >> 32)?;
}

// 6. 恢复 x86 非易失寄存器
// 7. 栈清理通过 adapter.adjust_stack_after_call()
let new_sp = adapter.adjust_stack_after_call(&self.core.arch, &signature, stack_pointer);
```

**保留不变的逻辑:**
- 无 definition 时的 fallback 路径（line ~1976-2027）
- `pending_context_restore` 上下文恢复
- `defer_api_return` 延迟返回
- `force_native_return` 强制原生返回
- `thread_yield_requested` 线程让步

**关键变量名:**

| 变量 | 类型 | 说明 |
|------|------|------|
| `signature` | `HookSignature` | 从 `bound_lookup().signature` 或 `From<&HookDefinition>` 桥接获取 |
| `adapter` | `&'static dyn AbiAdapter` | `select_adapter(&self.core.arch, &signature.abi)` 返回 |
| `frame` | `RawCallFrame` | ABI adapter 从 CPU 状态抓取的原始帧 |
| `raw_retval` | `u64` | `retval.into_raw(&self.core.arch)` 架构适配后的值 |
| `new_sp` | `u64` | `adapter.adjust_stack_after_call()` 计算的新栈指针 |
| `saved_x86_nonvolatile` | `Option<(u64, u64, u64, u64)>` | EBX/EBP/ESI/EDI 保存值 |

---

### 2.4 `src/runtime/engine/shared/seh.rs` — SEH NtContinue 调用适配

**改动 (line ~217):**

```rust
// 旧:
let _ = self.dispatch_bound_stub_with_definition(
    &definition, stub_address, None, &[context_address, 0],
)?;

// 新:
let _ = self.dispatch_bound_stub_with_definition(
    &definition, &HookSignature::from(&definition),
    stub_address, None, &[context_address, 0],
)?;
```

`HookSignature` 通过 `use super::*` 访问（`shared/mod.rs` 的 `pub(in crate::runtime::engine) use super::*;` 重新导出了 `engine.rs` 中的所有公开项）。

返回值仍为 `let _ = ...` 忽略，不受 `HookValue` 变化影响。

---

### 2.5 `src/runtime/engine/x86_interpreter_helpers.rs` — x86 解释器调用适配

**改动 (line ~407):**

```rust
// 旧:
let retval = self.dispatch_bound_stub_with_definition(
    &definition, state.eip as u64, Some(return_address), &args,
)?;
state.eax = retval as u32;

// 新:
let signature = bound.signature.cloned()
    .unwrap_or_else(|| HookSignature::from(&definition));
let retval = self.dispatch_bound_stub_with_definition(
    &definition, &signature, state.eip as u64, Some(return_address), &args,
)?;
state.eax = retval.into_raw_u64() as u32;
```

`HookSignature` 通过 `use super::*` 访问。

**注意:** x86 interpreter 的栈清理逻辑（`match definition.call_conv { Stdcall/Cdecl/Win64 }`）保持原样不变，因为 interpreter 有自己的 CPU 状态管理，不走 `AbiAdapter`。

---

## 3. 类型映射表（与原文档对应关系）

| 原文档概念 | Phase 0 位置 | Phase 1 接入点 |
|-----------|-------------|---------------|
| 第 2 层 ABI Adapter | `runtime/engine/abi/adapter.rs` | `engine.rs: select_adapter(&self.core.arch, &signature.abi)` |
| 第 2 层 x86 参数提取 | `runtime/engine/abi/x86.rs` | `engine.rs: adapter.capture_call_frame()` 替代 inline ESP 读取 |
| 第 2 层 x64 参数提取 | `runtime/engine/abi/x64.rs` | `engine.rs: adapter.capture_call_frame()` 替代 inline RSP+RCX/RDX/R8/R9 |
| 第 2 层 返回值写回 | `runtime/engine/abi/x86.rs` / `x64.rs` | `engine.rs: adapter.write_return_value()` |
| 第 2 层 栈清理 | `runtime/engine/abi/x86.rs` / `x64.rs` | `engine.rs: adapter.adjust_stack_after_call()` |
| 第 4 层 Hook Runtime | `runtime/engine/hooks/family_dispatch.rs` | 返回 `HookValue` 替代 `u64` |
| 第 5.5 HookValue | `runtime/engine/hook_value.rs` | `into_raw(arch)` 用于寄存器写回，`into_raw_u64()` 用于兼容 API |
| 第 5.6 RawCallFrame | `runtime/engine/abi/frame.rs` | `frame.args` / `frame.return_address` / `frame.stack_pointer` |
| 第 7.1 HookDefinition→HookSignature | `hooks/base.rs` `From<&HookDefinition>` | `engine.rs` / `seh.rs` / `x86_interpreter` 桥接调用 |
| 第 7.2 Registry 存储 HookSignature | `hooks/registry.rs` | `signatures` map + `signature_for_address()` |
| 第 7.4 engine.rs 分发改造 | `runtime/engine.rs` | `dispatch_unicorn_bound_stub` 全面使用 AbiAdapter |
| 第 7.5 family_dispatch 签名驱动 | `runtime/engine/hooks/family_dispatch.rs` | `dispatch_bound_stub_with_definition` 接收 `&HookSignature` |

---

## 4. 数据流图（改造后的 dispatch 链路）

```
Unicorn code hook
  │
  ▼
dispatch_unicorn_bound_stub()
  ├── bound_lookup(address) → { module, function, definition, signature }
  ├── signature = bound.signature OR HookSignature::from(&definition)
  │
  ├── adapter = select_adapter(&arch, &signature.abi)
  ├── frame = adapter.capture_call_frame(arch, signature, reg_read, mem_read)
  │     ├── x86: X86StdcallAdapter / X86CdeclAdapter → ESP + 栈读取
  │     └── x64: X64Adapter → RSP + RCX/RDX/R8/R9 + 栈读取
  │
  ├── retval: HookValue = dispatch_bound_stub_with_definition(definition, signature, ...)
  │     ├── dispatch_kernel32_hook() → Option<Result<u64>>  ─→ HookValue::from(u64)
  │     ├── dispatch_manual_contract_hook() → ...           ─→ HookValue::from(u64)
  │     ├── dispatch_known_family_hook() → ...              ─→ HookValue::from(u64)
  │     └── unknown → HookValue::Raw(0)
  │
  ├── raw_retval = retval.into_raw(&arch)
  │     ├── Handle: x64 符号扩展
  │     ├── InvalidHandle: x86=0xFFFFFFFF, x64=0xFFFFFFFFFFFFFFFF
  │     ├── I32: x64 符号扩展
  │     └── Ptr: x86 截断到 32 位
  │
  ├── adapter.write_return_value(arch, raw_retval, reg_write)
  │     ├── x86: 写 EAX
  │     └── x64: 写 RAX
  │
  ├── adapter.adjust_stack_after_call(arch, signature, stack_pointer)
  │     ├── x86 stdcall: SP + 4 + argc*4
  │     ├── x86 cdecl:   SP + 4
  │     └── x64:         SP + 8
  │
  └── reg_write(sp_reg, new_sp) + reg_write(pc_reg, return_address)
```

---

## 5. 关键设计决策

### 5.1 dispatch_bound_stub 保持 u64 返回

`dispatch_bound_stub()` 是公共 API，被 initterm / ldr_enum / enum_windows / mfc42u / 测试等约 30 处调用。内部通过 `.map(|hv| hv.into_raw_u64())` 转换，避免一次性改动所有调用点。

### 5.2 x86 非易失寄存器不属于 AbiAdapter

EBX/EBP/ESI/EDI 的保存/恢复是 engine 层的执行完整性关注点，不属于 ABI 调用约定。AbiAdapter 只负责参数提取、返回值写回、栈清理。非易失寄存器仍在 `dispatch_unicorn_bound_stub` 中直接处理。

### 5.3 VerSetConditionMask 特殊路径保留

该函数在 x86 上通过 EDX:EAX 返回 64 位值，不属于标准 ABI。保留在 engine 层作为硬编码特殊路径。

### 5.4 x86 interpreter 不走 AbiAdapter

`step_x86_interpreter` 有自己的 CPU 状态管理（`X86State` 结构体），不走 Unicorn 寄存器。其栈清理逻辑保持原样，仅适配 `dispatch_bound_stub_with_definition` 的新签名和 `HookValue` 返回。

---

## 6. 未改动的部分（供后续阶段参考）

- 所有 37 个 `dispatch_xxx_hook` 内部实现 — 仍返回 `Option<Result<u64, VmError>>`
- `log_api_call` / `log_api_return` — 仍用 `&HookDefinition`
- `describe_api_call_args()` — 仍用 `api_parameter_specs()`
- `api_parameter_specs()` — 保留
- `CallConv` / `HookDefinition` — 保留作为主数据结构
- `FromHookParam` trait — Phase 0 定义，未接入
- `HookContext` — Phase 0 定义，未接入
- `arm64.rs` — Phase 0 占位，无 trait 实现
