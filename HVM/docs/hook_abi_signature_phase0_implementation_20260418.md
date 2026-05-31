# Hook ABI Signature Migration — Phase 0 Implementation Report

> 关联原文档: `HVM/docs/hook_abi_signature_migration_plan_20260417.md`
> 实施阶段: **阶段 0 — 设计冻结与脚手架**
> 实施日期: 2026-04-18
> 状态: 已完成

---

## 1. 概述

阶段 0 的目标是建立完整的类型脚手架，使新模型（`HookSignature` / `AbiAdapter` / `HookContext` / 语义化 `HookValue`）能够与旧模型（`HookDefinition` / `CallConv` / 裸 `u64` 返回值）共存，不迁移任何 Hook 业务代码。

验收标准：
- `cargo check` 零错误
- `cargo test` 无新增失败（原有 3 个预存失败不变）
- 新旧模型可并行存在

---

## 2. 新增文件清单

### 2.1 `src/hooks/types.rs` — 核心类型定义

定义了 Hook 签名体系所需的所有基础类型。

| 类型名 | 种类 | 说明 |
|--------|------|------|
| `LogicalAbi` | `enum` | 逻辑 ABI，解耦平台调用约定。7 个变体：`WinApi`, `Cdecl`, `VariadicCdecl`, `Win64Only`, `ComMethod`, `Callback`, `Custom(&'static str)` |
| `ParamDirection` | `enum` | 参数方向：`In`, `Out`, `InOut`。默认 `In` |
| `LogPolicy` | `enum` | 日志渲染策略：`Skip`, `Default`, `Hex`, `Truncate(usize)`, `Custom(&'static str)`。默认 `Default` |
| `ParamFlags` | `struct(u8)` | 参数扩展标志位，手写 bitflags（无外部依赖）。常量：`IS_VARIADIC=0x01`, `IS_OPTIONAL=0x02`, `IS_COMPOUND=0x04`。方法：`empty()`, `from_bits()`, `bits()`, `contains()`, `insert()` |
| `HookFlags` | `struct(u8)` | Hook 扩展标志位。常量：`NO_LOG=0x01`, `NO_RETURN_LOG=0x02`, `VARIADIC=0x04`。方法同 `ParamFlags` |
| `ParamType` | `enum` | 参数类型分类，涵盖标量、句柄、指针、字符串、Buffer、Windows 结构体、Opaque。共约 40 个变体。带参数变体：`CountedAnsi{len_param, code_page_param}`, `CountedWide{len_param}`, `Buffer{len_param}`, `OutBuffer{len_param}`, `ByteSlice{len_param}`, `WideBuffer{len_param}`, `GuestPtrTo(ParamTypeDiscriminant)`, `OpaqueStructPtr(&'static str)` |
| `ParamTypeDiscriminant` | `enum` | `GuestPtrTo` 内部使用的轻量类型判别。变体：`U32`, `I32`, `Handle`, `GuestPtr`, `GuidPtr`, `Void` |

**设计决策**：
- `ParamFlags` / `HookFlags` 使用手写 bitflags 而非 `bitflags` crate，因为 Cargo.toml 无此依赖，且字段极少（3 个常量），不值得引入外部依赖
- `ParamType::GuestPtrTo` 使用 `ParamTypeDiscriminant` 而非 `Box<ParamType>` 以保持 `Copy` 语义；完整类型信息在 decode 阶段由运行时上下文恢复

---

### 2.2 `src/hooks/signature.rs` — 签名与规格结构体

| 类型名 | 说明 |
|--------|------|
| `ParamSpec` | 单个参数的完整描述。字段：`name: &'static str`, `ty: ParamType`, `dir: ParamDirection`, `log: LogPolicy`, `flags: ParamFlags`。构造器：`new()`, `with_dir()`, `with_log()` — 均为 `const fn` |
| `ReturnSpec` | 返回值语义枚举。10 个变体：`Void`, `Bool32`, `I32`, `U32`, `NtStatus`, `Win32Error`, `Handle`, `Pointer`, `PointerSizedUInt`, `PointerSizedInt`。默认 `U32` |
| `HookSignature` | 单一真相源签名结构体。字段：`module: &'static str`, `function: &'static str`, `abi: LogicalAbi`, `params: &'static [ParamSpec]`, `ret: ReturnSpec`, `flags: HookFlags`。方法：`argc() -> usize`（返回 `params.len()`） |

---

### 2.3 `src/hooks/builders.rs` — 宏工具

| 宏名 | 说明 |
|------|------|
| `hook_sig!` | 构造 `HookSignature` 的声明式宏。两个 arm：不带 `flags`（默认空）和带 `flags`。输出为 `const` 兼容的表达式 |
| `param!` | 构造 `ParamSpec` 的简写宏。三个 arm：`($name, $ty)` 默认方向、`($name, $ty, dir=$dir)` 显式方向、`($name, $ty, log=$log)` 显式日志策略 |

**注意**：宏使用 `$crate::hooks::signature::HookSignature` 完整路径，确保在任意模块中使用时路径正确。

---

### 2.4 `src/runtime/engine/abi/mod.rs` — ABI 模块入口

导出 `AbiAdapter` trait 和 `select_adapter()` 工厂函数。

---

### 2.5 `src/runtime/engine/abi/frame.rs` — 原始调用帧

| 类型名 | 说明 |
|--------|------|
| `AbiSnapshot` | ABI 状态快照。字段：`callee_cleanup: bool`（是否由 callee 清栈），`callee_stack_pop: u32`（callee 应弹出字节数，x86 only） |
| `RawCallFrame` | 从 CPU 状态抓取的原始参数帧。字段：`args: SmallVec<[u64; 8]>`，`return_address: Option<u64>`，`stack_pointer: u64`，`instruction_pointer: u64`，`abi_snapshot: AbiSnapshot`。方法：`arg(index) -> u64`，`argc() -> usize` |

**设计决策**：`args` 使用 `SmallVec<[u64; 8]>` 避免热路径堆分配（大多数 Windows API ≤8 参数）。依赖 `smallvec = "1"` 已存在于 Cargo.toml。

---

### 2.6 `src/runtime/engine/abi/adapter.rs` — AbiAdapter trait 与工厂

| 项目 | 说明 |
|------|------|
| `AbiAdapter` trait | 3 个方法：`capture_call_frame()`, `write_return_value()`, `adjust_stack_after_call()`。`reg_read`/`reg_write` 闭包使用 `i32` 寄存器 ID（匹配 Unicorn `c_int` 常量） |
| `select_adapter(arch, abi)` | 工厂函数，返回 `&'static dyn AbiAdapter`。x86 + Cdecl/VariadicCdecl → `X86CdeclAdapter`，x86 + 其他 → `X86StdcallAdapter`，x64 → `X64Adapter` |

**trait 闭包签名**：
```rust
reg_read: &mut dyn FnMut(i32) -> Result<u64, String>
mem_read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, String>
reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>
```

这些闭包抽象了 Unicorn 引擎的直接调用，使 adapter 可测试且解耦。

---

### 2.7 `src/runtime/engine/abi/x86.rs` — x86 ABI 适配器

| 结构体 | 说明 |
|--------|------|
| `X86StdcallAdapter` | x86 stdcall：全栈传参，callee 清栈（`ESP + 4 + argc*4`） |
| `X86CdeclAdapter` | x86 cdecl：全栈传参，caller 清栈（`ESP + 4`） |

内部共享函数 `capture_x86_frame()` 从 ESP 读取返回地址 + `argc` 个 32 位参数。

---

### 2.8 `src/runtime/engine/abi/x64.rs` — x64 ABI 适配器

| 结构体 | 说明 |
|--------|------|
| `X64Adapter` | Win64 ABI：前 4 参数 RCX/RDX/R8/R9，剩余在 RSP+0x28（跳过 shadow space）。callee 不清栈 |

---

### 2.9 `src/runtime/engine/abi/arm64.rs` — ARM64 占位

仅包含 `pub struct Arm64Adapter;`，无 trait 实现。占位用。

---

### 2.10 `src/runtime/engine/hook_context.rs` — Hook 上下文

| 类型名 | 说明 |
|--------|------|
| `HookContext<'a, Engine>` | 泛型 hook 上下文。字段：`signature: &'a HookSignature`，`frame: &'a RawCallFrame`，`engine: &'a mut Engine`。方法：`new()`, `raw(index)`, `module()`, `function()`, `argc()` |
| `FromHookParam` trait | typed decode 核心。方法 `fn decode<E>(ctx: &HookContext<'_, E>, index: usize) -> Result<Self, VmError>` |

**设计决策**：`HookContext` 使用泛型参数 `Engine` 而非直接引用 `VirtualExecutionEngine`，避免 `engine.rs` ↔ `hook_context.rs` 循环模块依赖。engine 模块作为父模块，在使用点单态化。

---

## 3. 修改文件清单

### 3.1 `src/hooks/base.rs` — 添加桥接转换

新增 `impl From<&HookDefinition> for HookSignature`，将旧的 `CallConv` 映射到 `LogicalAbi`：
- `Stdcall` → `WinApi`
- `Cdecl` → `Cdecl`
- `Win64` → `WinApi`

桥接产生的签名 `params` 为空切片 `&[]`，`ret` 为 `ReturnSpec::U32`（默认值）。后续阶段各 family 迁移后将提供完整签名。

### 3.2 `src/hooks/mod.rs` — 新增模块声明

```rust
pub mod builders;
pub mod signature;
pub mod types;
```

### 3.3 `src/runtime/engine.rs` — 新增模块声明

```rust
mod abi;
mod hook_context;
```

### 3.4 `src/runtime/engine/hook_value.rs` — 升级为语义枚举

**旧形态**：`struct HookValue { raw: u64 }`（newtype 包装）

**新形态**：`enum HookValue` 含 9 个语义变体：`Void`, `Raw(u64)`, `U32(u32)`, `I32(i32)`, `Ptr(u64)`, `Handle(u64)`, `InvalidHandle`, `NtStatus(u32)`, `Win32Error(u32)`

保留的兼容接口：
- `From<u64>` → `Raw(v)`
- `From<u32>` → `U32(v)`
- `From<i32>` → `I32(v)`
- `into_raw_u64()` — 无 arch 参数，假设 x64 编码

新增接口：
- `into_raw(arch: &ArchSpec) -> u64` — 根据 arch 做正确的宽度适配（pointer 截断、handle 符号扩展、InvalidHandle 宽度）
- `i32_value(value, arch)` — 替代旧的 `i32(value, arch)`，避免与 `I32` 变体命名冲突

---

## 4. 类型映射表（原文档对应关系）

| 原文档概念 | 实现位置 | 类型/路径 |
|-----------|----------|-----------|
| 第 1 层 Signature Definition | `hooks/signature.rs` | `HookSignature` |
| 第 2 层 ABI Adapter | `runtime/engine/abi/` | `AbiAdapter` trait |
| 第 3 层 Hook Context | `runtime/engine/hook_context.rs` | `HookContext<'a, Engine>` |
| 第 5.1 LogicalAbi | `hooks/types.rs:6` | `LogicalAbi` |
| 第 5.2 ParamSpec | `hooks/signature.rs:5` | `ParamSpec` |
| 第 5.3 ParamType | `hooks/types.rs:139` | `ParamType` |
| 第 5.4 ReturnSpec | `hooks/signature.rs:53` | `ReturnSpec` |
| 第 5.5 HookValue | `runtime/engine/hook_value.rs:12` | `HookValue` (enum) |
| 第 5.6 RawCallFrame | `runtime/engine/abi/frame.rs:29` | `RawCallFrame` |
| 第 6.1 hook_sig! | `hooks/builders.rs:23` | `hook_sig!` 宏 |
| 第 8.1 FromHookParam | `runtime/engine/hook_context.rs:67` | `FromHookParam` trait |
| 第 9.1 ABI 映射表 | `runtime/engine/abi/adapter.rs:56` | `select_adapter()` |

---

## 5. 目录结构（新增部分）

```
src/
├── hooks/
│   ├── base.rs                      [修改] 添加 From<&HookDefinition> 桥接
│   ├── builders.rs                  [新增] hook_sig! / param! 宏
│   ├── mod.rs                       [修改] 添加 3 个新模块声明
│   ├── signature.rs                 [新增] ParamSpec / ReturnSpec / HookSignature
│   └── types.rs                     [新增] LogicalAbi / ParamType / HookFlags 等
│
└── runtime/engine/
    ├── engine.rs                    [修改] 添加 abi / hook_context 模块声明
    ├── hook_value.rs                [修改] 从 newtype 升级为语义 enum
    ├── hook_context.rs              [新增] HookContext / FromHookParam
    └── abi/
        ├── mod.rs                   [新增] 模块入口 + re-exports
        ├── adapter.rs               [新增] AbiAdapter trait + select_adapter()
        ├── frame.rs                 [新增] RawCallFrame / AbiSnapshot
        ├── x86.rs                   [新增] X86StdcallAdapter / X86CdeclAdapter
        ├── x64.rs                   [新增] X64Adapter
        └── arm64.rs                 [新增] Arm64Adapter 占位
```

---

## 6. 后续阶段接入指南

### 阶段 1（接通主分发链路）需要改动的关键文件

1. **`hooks/registry.rs`** — `definitions` 字段类型从 `HashMap<(String, String), HookDefinition>` 迁移为同时存储 `HookSignature`。`BoundHookLookup.definition` 改为返回 `&HookSignature`。

2. **`runtime/engine.rs` → `dispatch_unicorn_bound_stub()`** (约 line 2020) — 当前直接操作 Unicorn 寄存器抓参。改为调用 `select_adapter().capture_call_frame()` + `write_return_value()`。

3. **`runtime/engine/hooks/family_dispatch.rs` → `dispatch_bound_stub_with_definition()`** (line 272) — 签名从接收 `&HookDefinition` 改为接收 `&HookSignature`，内部创建 `HookContext`，返回值从 `Result<u64, VmError>` 改为 `Result<HookValue, VmError>`。

4. **旧 Hook handler 兼容** — 所有当前返回 `Result<u64, VmError>` 的 handler 通过 `From<u64> for HookValue` 自动适配，无需立即修改。

### 阶段 1 接入 AbiAdapter 的代码路径

```
engine.rs:dispatch_unicorn_bound_stub()
  ├── select_adapter(arch, signature.abi)           ← 替换当前 if arch.is_x86()
  ├── adapter.capture_call_frame(arch, sig, ...)    ← 替换当前 inline 寄存器读取
  ├── dispatch_bound_stub_with_definition(sig, ...) ← 签名驱动
  ├── adapter.write_return_value(arch, retval, ...) ← 替换当前 inline EAX/RAX 写
  └── adapter.adjust_stack_after_call(arch, sig, sp)← 替换当前 match call_conv
```

### 阶段 2（日志收敛）需要关注

- `logging_helpers.rs` 中的 `describe_api_call_args()` 改为遍历 `signature.params`
- `shared/api_logging.rs` 中的 `api_parameter_specs()` 在阶段 2 完成后应删除
- 返回值渲染改用 `signature.ret` + `HookValue` 的变体信息

### 阶段 3（核心 DLL 迁移）签名注册模式

迁移后的 family 注册将改为提供 `&'static HookSignature` 数组。推荐模式：

```rust
// hooks/families/core/kernel32.rs
static KERNEL32_SIGNATURES: &[HookSignature] = &[
    hook_sig!(
        module: "kernel32.dll",
        function: "CreateFileW",
        abi: LogicalAbi::WinApi,
        params: [
            param!("lpFileName", ParamType::PCWStr),
            param!("dwDesiredAccess", ParamType::Hex32),
            // ...
        ],
        ret: ReturnSpec::Handle,
    ),
];
```

---

## 7. 已知限制

1. `arm64.rs` 仅为占位，无 `AbiAdapter` 实现
2. `AbiAdapter::capture_call_frame()` 使用 `dyn FnMut` 闭包，阶段 1 接入时可考虑改为与 Unicorn API 更贴近的接口
3. `HookValue::i32_value()` 方法名带 `_value` 后缀，因为 `i32` 既是变体名又是 Rust 原始类型
4. `param!` 宏名可能与其它 crate 冲突，后续可考虑改名为 `pspec!`
5. 新模块当前有 unused import 警告，阶段 1 接入主链路后消除
