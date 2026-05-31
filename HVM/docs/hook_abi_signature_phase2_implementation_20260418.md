# Hook ABI Signature Migration — Phase 2 Implementation Report

> 关联原文档: `HVM/docs/hook_abi_signature_migration_plan_20260417.md`
> 实施阶段: **阶段 2 — 日志系统收敛**
> 实施日期: 2026-04-18
> 前置阶段: 阶段 0 — 设计冻结与脚手架（已完成）、阶段 1 — 接通主分发链路（已完成）
> 状态: 已完成

---

## 1. 概述

阶段 2 将日志系统的参数渲染从独立维护的 `api_parameter_specs()` 大型 match 表迁移为直接读取 `HookSignature.params`。

核心策略：**渐进收敛**。三层优先级共存：

1. `describe_custom_api_call_args()` — 复杂 API 自定义渲染（最高优先级）
2. 签名驱动路径 — 当 `signature.params` 非空时使用 `ParamType` + `LogPolicy` 渲染
3. 旧回退路径 — `api_parameter_specs()` + `ApiArgKind`（当 `params` 为空时）

当前绝大多数 `HookSignature` 的 `params` 为空（通过 Phase 0 的 `From<&HookDefinition>` 桥接），因此旧回退路径仍是运行时主路径。Phase 3 为各 family 补齐签名后，第 3 层自然废弃。

验收标准：
- `cargo check` 零错误
- `cargo test` 无新增失败（原有 3 个预存失败不变）

---

## 2. 改动文件清单

| 文件 | 改动类型 | 说明 |
|------|---------|------|
| `src/runtime/engine/logging_helpers.rs` | 修改 | 新增 3 个方法，修改 3 个方法签名 |
| `src/runtime/engine/hooks/family_dispatch.rs` | 修改 | 激活 `_signature` 参数，传入日志链路 |
| `docs/hook_abi_signature_phase2_implementation_20260418.md` | 新增 | 本文档 |

---

## 3. `logging_helpers.rs` 详细改动

### 3.1 新增 import（文件顶部）

```rust
use crate::hooks::signature::{HookSignature, ReturnSpec};
use crate::hooks::types::LogPolicy;
use crate::hooks::types::ParamType;
use crate::hooks::types::ParamTypeDiscriminant;
```

### 3.2 新增方法 `format_param_type_value()` — line 475

**签名：**

```rust
pub(super) fn format_param_type_value(
    &self,
    ty: &ParamType,           // 参数类型（来自 ParamSpec.ty）
    value: u64,               // 该参数的原始 u64 值
    all_args: &[u64],         // 完整参数列表（用于跨参数引用，如 Buffer{len_param}）
    log_policy: LogPolicy,    // 日志策略（来自 ParamSpec.log）
) -> Option<String>           // None = 跳过该参数（LogPolicy::Skip）
```

**行为：**

- `LogPolicy::Skip` → 立即返回 `None`，调用方通过 `filter_map` 丢弃该参数
- `LogPolicy::Hex` → 覆盖默认渲染，强制输出 `0x{value:X}`（`Hex32`/`Hex64` 除外，它们本身就输出十六进制）
- `LogPolicy::Default` / `LogPolicy::Truncate(_)` / `LogPolicy::Custom(_)` → 按 `ParamType` 渲染

**ParamType 渲染映射：**

```rust
match ty {
    // 标量 — 直接格式化
    Bool32              → "TRUE" / "FALSE"
    I32 | SSizeT        → format!("{}", value as u32 as i32)
    U32                 → format!("{}", value as u32)
    Hex32               → format!("0x{:X}", value as u32)
    Hex64               → format!("0x{value:X}")
    I64                 → format!("{}", value as i64)
    U64                 → format!("{value}")
    SizeT               → format!("0x{:X}", value)
    PointerSizedUInt    → format!("0x{value:X}")
    PointerSizedInt     → format!("{}", value as i64)

    // 句柄 — 复用已有 describe_pointer()
    Handle | PseudoHandle → self.describe_pointer(value, false)

    // 模块句柄 — 复用已有 describe_module_handle()
    ModuleHandle         → self.describe_module_handle(value)

    // 指针 — 复用已有 describe_pointer()
    GuestPtr | FunctionPtr | GuestPtrTo(_) → self.describe_pointer(value, false)

    // 字符串 — 复用已有 describe_string_pointer()
    PCStr | PStr  → self.describe_string_pointer(value, false)
    PCWStr | PWStr → self.describe_string_pointer(value, true)

    // 计数字符串 — 从 all_args 获取关联参数
    CountedAnsi { len_param, code_page_param } →
        let count = all_args.get(*len_param).copied().unwrap_or(0);
        let cp = code_page_param.and_then(|i| all_args.get(i).copied()).unwrap_or(0);
        self.describe_ansi_input_pointer(value, count, cp)
            .unwrap_or_else(|| self.describe_pointer(value, false))

    CountedWide { len_param } →
        let count = all_args.get(*len_param).copied().unwrap_or(0) as usize;
        self.describe_wide_counted_pointer(value, count)
            .unwrap_or_else(|| self.describe_pointer(value, false))

    // Buffer — 从 all_args 获取长度
    Buffer { len_param } | ByteSlice { len_param } →
        let len = all_args.get(*len_param).copied().unwrap_or(0);
        self.describe_buffer_pointer(value, len)

    WideBuffer { len_param } →
        let len = all_args.get(*len_param).copied().unwrap_or(0);
        self.describe_buffer_pointer(value, len.saturating_mul(2))

    // 输出 buffer — 不预读内容，仅显示地址
    OutBuffer { .. } → self.describe_pointer(value, false)

    // 结构体指针 — 统一显示地址
    GuidPtr | SidPtr | SecurityAttributesPtr | StartupInfoPtr
    | ProcessInformationPtr | OverlappedPtr | FileTimePtr
    | SystemTimePtr | OpaqueStructPtr(_) → self.describe_pointer(value, false)

    // ntdll 字符串结构体 — 复用已有方法
    AnsiStringStruct    → self.describe_ansi_string_struct(value)
    UnicodeStringStruct → self.describe_unicode_string_struct(value)
}
```

**后续阶段注意：**
- `CountedAnsi` / `CountedWide` / `Buffer` / `ByteSlice` / `WideBuffer` 通过 `all_args.get(len_param)` 获取关联参数值，这意味着签名中的 `len_param` 索引必须与实际参数位置匹配
- `LogPolicy::Truncate(n)` 目前未在渲染中生效（字符串截断由 `truncate_api_log_text()` 全局配置控制），后续可细化
- `LogPolicy::Custom(name)` 目前走 `Default` 渲染，后续阶段可添加 named custom renderer 分发

### 3.3 新增方法 `param_type_to_kind_str()` — line 543

**签名：**

```rust
pub(super) fn param_type_to_kind_str(ty: &ParamType) -> &'static str
```

**输出值用于 `ApiLogArg.kind` 字段（JSON 日志中可见）。** 完整映射：

| ParamType | kind 字符串 |
|-----------|-----------|
| `Bool32` | `"bool32"` |
| `I32` | `"i32"` |
| `U32` | `"u32"` |
| `Hex32` | `"hex32"` |
| `Hex64` | `"hex64"` |
| `I64` | `"i64"` |
| `U64` | `"u64"` |
| `SizeT` | `"size_t"` |
| `SSizeT` | `"ssize_t"` |
| `PointerSizedUInt` | `"ptr_uint"` |
| `PointerSizedInt` | `"ptr_int"` |
| `Handle` | `"handle"` |
| `PseudoHandle` | `"pseudo_handle"` |
| `ModuleHandle` | `"module"` |
| `GuestPtr` | `"ptr"` |
| `GuestPtrTo(U32)` | `"ptr_to_u32"` |
| `GuestPtrTo(I32)` | `"ptr_to_i32"` |
| `GuestPtrTo(Handle)` | `"ptr_to_handle"` |
| `GuestPtrTo(GuestPtr)` | `"ptr_to_ptr"` |
| `GuestPtrTo(GuidPtr)` | `"ptr_to_guid"` |
| `GuestPtrTo(Void)` | `"ptr_to_void"` |
| `FunctionPtr` | `"fn_ptr"` |
| `PCStr` | `"pcstr"` |
| `PCWStr` | `"pcwstr"` |
| `PStr` | `"pstr"` |
| `PWStr` | `"pwstr"` |
| `CountedAnsi { .. }` | `"counted_ansi"` |
| `CountedWide { .. }` | `"counted_wide"` |
| `Buffer { .. }` | `"buffer"` |
| `OutBuffer { .. }` | `"out_buffer"` |
| `ByteSlice { .. }` | `"byte_slice"` |
| `WideBuffer { .. }` | `"wide_buffer"` |
| `GuidPtr` | `"guid_ptr"` |
| `SidPtr` | `"sid_ptr"` |
| `SecurityAttributesPtr` | `"security_attributes"` |
| `StartupInfoPtr` | `"startup_info"` |
| `ProcessInformationPtr` | `"process_info"` |
| `OverlappedPtr` | `"overlapped"` |
| `FileTimePtr` | `"filetime"` |
| `SystemTimePtr` | `"systemtime"` |
| `OpaqueStructPtr(name)` | 使用 `name` 值本身（`&'static str`） |
| `AnsiStringStruct` | `"ansi_string"` |
| `UnicodeStringStruct` | `"unicode_string"` |

### 3.4 新增方法 `format_return_from_signature()` — line 253

**签名：**

```rust
fn format_return_from_signature(
    &self,
    signature: Option<&HookSignature>,  // 签名（可能为 None）
    retval: u64,                        // 原始返回值
) -> Option<String>                    // None = 无签名，不渲染
```

**ReturnSpec 渲染：**

```rust
match ret_spec {
    Void              → "void"
    Bool32            → "BOOL=TRUE" / "BOOL=FALSE"
    I32               → format!("i32={}", retval as u32 as i32)
    U32               → format!("u32={}", retval as u32)
    NtStatus          → format!("NTSTATUS=0x{code:08X}<NAME>") 或 "NTSTATUS=0x{code:08X}"
    Win32Error        → format!("ERROR=0x{:X}", retval as u32)
    Handle            → self.describe_pointer(retval, false)
    Pointer           → self.describe_pointer(retval, false)
    PointerSizedUInt  → format!("ptr_uint=0x{retval:X}")
    PointerSizedInt   → format!("ptr_int={}", retval as i64)
}
```

**优先级机制（在 `log_api_return()` 中）：**

```rust
let decoded_text = self.describe_api_return_decoded_text(definition, args, retval)
    .or_else(|| self.format_return_from_signature(signature, retval));
```

即：自定义返回值解码（如 WideCharToMultiByte 输出缓冲区） > `ReturnSpec` 通用渲染。

### 3.5 修改方法 `log_api_call()` — line 160

**签名变化：**

```rust
// 旧:
pub(super) fn log_api_call(
    &mut self,
    definition: &HookDefinition,
    pc: u64,
    return_to: Option<u64>,
    args: &[u64],
) -> Result<u64, VmError>

// 新:
pub(super) fn log_api_call(
    &mut self,
    definition: &HookDefinition,
    signature: Option<&HookSignature>,   // ← 新增
    pc: u64,
    return_to: Option<u64>,
    args: &[u64],
) -> Result<u64, VmError>
```

**内部变化：**

```rust
// 旧:
let rendered_args = self.describe_api_call_args(definition, args);

// 新:
let rendered_args = self.describe_api_call_args(definition, signature, args);
```

其余逻辑（高频 API 抑制、call_id 生成、api_logger 调用）不变。

### 3.6 修改方法 `log_api_return()` — line 216

**签名变化：**

```rust
// 旧:
pub(super) fn log_api_return(
    &mut self,
    call_id: u64,
    definition: &HookDefinition,
    pc: u64,
    args: &[u64],
    retval: u64,
) -> Result<(), VmError>

// 新:
pub(super) fn log_api_return(
    &mut self,
    call_id: u64,
    definition: &HookDefinition,
    signature: Option<&HookSignature>,   // ← 新增
    pc: u64,
    args: &[u64],
    retval: u64,
) -> Result<(), VmError>
```

**内部变化：**

```rust
// 旧:
self.describe_api_return_decoded_text(definition, args, retval),

// 新:
let decoded_text = self.describe_api_return_decoded_text(definition, args, retval)
    .or_else(|| self.format_return_from_signature(signature, retval));
// decoded_text 传入 api_logger
```

### 3.7 修改方法 `describe_api_call_args()` — line 296

**签名变化：**

```rust
// 旧:
fn describe_api_call_args(&self, definition: &HookDefinition, args: &[u64]) -> Vec<ApiLogArg>

// 新:
fn describe_api_call_args(
    &self,
    definition: &HookDefinition,
    signature: Option<&HookSignature>,   // ← 新增
    args: &[u64],
) -> Vec<ApiLogArg>
```

**新内部逻辑（三层优先级）：**

```
① describe_custom_api_call_args(definition, args) → 有则直接返回

② signature 非空且 params 非空 → 签名驱动路径:
   args.iter().enumerate().filter_map(|(index, &value)| {
       let spec = sig.params.get(index);
       let (name, ty, log) = match spec {
           Some(p) => (p.name, &p.ty, p.log),     // 有 ParamSpec → 使用签名元数据
           None => ("", &ParamType::U64, LogPolicy::Default),  // 无 → 通用 u64
       };
       let name = if name.is_empty() { format!("arg{index}") } else { name.to_string() };
       let text = self.format_param_type_value(ty, value, args, log)
           .unwrap_or_else(|| "SKIPPED".to_string());
       let kind_str = spec
           .map(|p| Self::param_type_to_kind_str(&p.ty).to_string())
           .unwrap_or_else(|| "auto".to_string());
       Some(ApiLogArg { index, name, kind: kind_str, value, text })
   }).collect()

③ 旧回退路径:
   api_parameter_specs(module, function) → specs
   args.iter().enumerate().map(|(index, value)| {
       let spec = specs.get(index).copied().unwrap_or(ApiParameterSpec {
           name: "", kind: ApiArgKind::Auto,
       });
       // ... 旧渲染逻辑
   }).collect()
```

**关键变量名：**

| 变量 | 类型 | 说明 |
|------|------|------|
| `sig` | `&HookSignature` | 从 `signature` Option 解包 |
| `spec` | `Option<&ParamSpec>` | `sig.params.get(index)`，可能为 None（参数数量不匹配） |
| `name` | `&'static str` | 从 `spec.name` 获取 |
| `ty` | `&ParamType` | 从 `spec.ty` 获取，fallback 为 `ParamType::U64` |
| `log` | `LogPolicy` | 从 `spec.log` 获取，fallback 为 `LogPolicy::Default` |
| `kind_str` | `String` | `param_type_to_kind_str(ty)` 的结果 |
| `text` | `String` | `format_param_type_value()` 的结果 |

---

## 4. `family_dispatch.rs` 详细改动

### 4.1 `dispatch_bound_stub_with_definition()` — line 273

**参数名变化：**

```rust
// 旧:
definition: &HookDefinition,
_signature: &HookSignature,     // 未使用（下划线前缀）

// 新:
definition: &HookDefinition,
signature: &HookSignature,      // 激活，传入日志链路
```

**调用点变化（2 处）：**

```rust
// 旧 (line 297):
let call_id = self.log_api_call(definition, stub_address, return_address, args)?;

// 新:
let call_id = self.log_api_call(definition, Some(signature), stub_address, return_address, args)?;

// 旧 (line 365):
self.log_api_return(call_id, definition, stub_address, args, retval.into_raw_u64())?;

// 新:
self.log_api_return(call_id, definition, Some(signature), stub_address, args, retval.into_raw_u64())?;
```

---

## 5. 未改动的文件（后续阶段需关注）

| 文件 | 当前状态 | 后续阶段动作 |
|------|---------|------------|
| `shared/api_logging.rs` → `api_parameter_specs()` | 保留作为旧回退路径 | Phase 6 删除 |
| `shared/api_logging.rs` → `describe_custom_api_call_args()` | 保留，优先级最高 | Phase 3+ 视需要迁移复杂 API |
| `shared/api_logging.rs` → `describe_api_return_decoded_text()` | 保留，返回值自定义解码 | Phase 3+ 视需要迁移 |
| `logging_helpers.rs` → `ApiArgKind` enum | 保留，仅旧回退路径使用 | Phase 6 删除 |
| `logging_helpers.rs` → `format_api_value()` | 保留，仅旧回退路径使用 | Phase 6 删除 |
| `api_logger.rs` | 无改动 | — |
| `hooks/registry.rs` | Phase 1 已改 | — |
| `engine.rs` → `dispatch_unicorn_bound_stub()` | Phase 1 已改 | — |

---

## 6. 数据流图（Phase 2 改造后的日志渲染链路）

```
dispatch_bound_stub_with_definition(definition, signature, ...)
  │
  ├── log_api_call(definition, Some(signature), pc, return_to, args)
  │     │
  │     ├── describe_api_call_args(definition, signature, args)
  │     │     │
  │     │     ├── ① describe_custom_api_call_args(definition, args)
  │     │     │     → memcmp/memcpy/WideCharToMultiByte/... 自定义渲染
  │     │     │
  │     │     ├── ② 签名驱动（signature.params 非空时）
  │     │     │     → format_param_type_value(ParamType, value, all_args, LogPolicy)
  │     │     │     → param_type_to_kind_str(ParamType)
  │     │     │
  │     │     └── ③ 旧回退（signature 为 None 或 params 为空时）
  │     │           → api_parameter_specs(module, function)
  │     │           → format_api_value(ApiArgKind, value)
  │     │
  │     └── api_logger.log_api_call(..., &rendered_args, ...)
  │
  └── log_api_return(call_id, definition, Some(signature), pc, args, retval)
        │
        ├── describe_api_return_decoded_text(definition, args, retval)
        │     → WideCharToMultiByte/MultiByteToWideChar/SEH 自定义返回值解码
        │
        ├── format_return_from_signature(signature, retval)   ← or_else 回退
        │     → ReturnSpec::NtStatus → "NTSTATUS=0x...<NAME>"
        │     → ReturnSpec::Bool32 → "BOOL=TRUE/FALSE"
        │     → ReturnSpec::Handle → describe_pointer(retval)
        │     → ...
        │
        └── api_logger.log_api_return(..., decoded_text, ...)
```

---

## 7. 与原文档对应关系

| 原文档条目 | Phase 2 实现 |
|-----------|-------------|
| 阶段 2 动作 1: 日志层改为直接读 `signature.params` | `describe_api_call_args()` 的签名驱动路径 |
| 阶段 2 动作 2: 删除 `ApiArgKind::Auto` 主路径 | 签名驱动路径不使用 Auto；旧回退保留 |
| 阶段 2 动作 3: 复杂 API 用 custom decoder | `describe_custom_api_call_args()` 优先级最高 |
| 阶段 2 动作 4: 返回值日志基于 `ReturnSpec` | `format_return_from_signature()` |
| 第 5.2 ParamSpec | 签名驱动路径使用 `p.name` / `p.ty` / `p.log` |
| 第 5.3 ParamType（约 40 变体） | `format_param_type_value()` 完整覆盖 |
| 第 5.4 ReturnSpec（10 变体） | `format_return_from_signature()` 完整覆盖 |
| 第 7.5 family_dispatch 签名驱动 | `_signature` → `signature`，传入日志 |
| 第 7.6 logging_helpers 改造 | 新增签名驱动渲染，旧路径保留 |
