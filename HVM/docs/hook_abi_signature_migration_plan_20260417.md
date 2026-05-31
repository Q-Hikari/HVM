# HVM Hook ABI / Signature / Typed Argument 大迁移方案

> 状态: 设计冻结前草案
> 日期: 2026-04-17
> 适用范围: `HVM/` 全量 Hook 体系
> 改造级别: 允许破坏式重构
> 背景约束: 当前业务尚未上线，允许为未来 `x86` / `x64` / `arm64` 扩展预留大面积改造

---

## 1. 文档目标

这份文档不是“局部修补建议”，而是 HVM 当前 Hook 体系的一次结构性迁移方案。

目标只有四个:

1. 让 `x86` / `x64` / 未来 `arm64` 的 ABI 差异收敛到统一抽象层。
2. 让 Hook 定义时就能声明参数类型、返回类型和解构策略。
3. 让参数解构、日志渲染、返回值宽度处理共用同一份元数据。
4. 让未来新增 Hook 时，不再需要在三个地方重复维护:
   - Hook 定义
   - Hook 参数读取
   - API 日志参数规格

这次改造建议按“破坏式升级”执行，不优先保留旧接口形式。兼容层只保留短期迁移窗口，不作为最终架构目标。

---

## 2. 当前问题总结

结合现有实现，当前 Hook 体系有六个根问题。

### 2.1 定义层信息不足

当前 `HookDefinition` 只有:

- `module`
- `function`
- `argc`
- `call_conv`

缺少:

- 参数名称
- 参数类型
- 参数读取策略
- 返回值语义
- 特殊 ABI 标记
- 是否为可变参数函数
- 是否需要自定义日志渲染

结果是 Hook 定义层无法成为“单一真相源”。

### 2.2 ABI 差异散落在运行时分发和 Hook 代码里

当前引擎已经在分发入口按 `x86` / `x64` 正确提取原始参数，但提取结果仍然只是 `&[u64]`。

后续所有 Hook 代码仍需手工决定:

- 第几个参数是什么
- 这个参数是不是字符串
- 是 ANSI 还是 UTF-16
- 是句柄还是普通整数
- 是 32 位字段还是 pointer-sized 值

这导致 ABI 抽象只做了一半。

### 2.3 参数元数据与日志系统分裂

当前 `api_parameter_specs()` 已经维护了一张大型参数规格表，用于日志渲染。

但这张表:

- 不参与 Hook 参数读取
- 不参与返回值语义
- 不参与 callback 参数准备
- 缺失时会退化到 `Auto` 猜测

这意味着“定义一处，到处生效”没有成立。

### 2.4 返回值语义仍然是裸 `u64`

仓库已经新增 `HookValue`，但尚未接入主分发链路。

当前大多数 Hook 仍然返回:

- `Ok(1)`
- `Ok(handle as u64)`
- `Ok(ptr as u64)`
- `Ok(0xFFFF_FFFF)`

这类写法在 `x64` 上容易遗漏:

- pseudo handle 的符号扩展
- `INVALID_HANDLE_VALUE`
- `int32 -> u64` 的符号位传播
- pointer 截断

### 2.5 Hook 代码中手工 `arg(args, i)` 过多

当前工程中，`runtime/engine/hooks` 与 `runtime/engine/shared` 下至少有约 2331 处 `arg(args, N)` 调用。

这说明:

- 参数读取方式没有被抽象
- 改 ABI 时需要大面积改业务代码
- 参数语义只能靠人脑记忆，不可维护

### 2.6 未来 `arm64` 扩展没有位置放

当前 `CallConv` 只有:

- `Stdcall`
- `Cdecl`
- `Win64`

它本质上是“当前支持架构的调用约定枚举”，不是“面向未来的逻辑 ABI 模型”。

后续如果引入:

- Windows ARM64 ABI
- variadic CRT ABI
- callback ABI
- COM vtable method ABI

当前抽象会迅速变得不够用。

---

## 3. 改造总体策略

这次迁移建议明确采用以下原则。

### 3.1 单一真相源

每个 Hook 的元数据只能有一份主定义，统一包含:

- 参数列表
- 参数类型
- 返回值类型
- 逻辑 ABI
- 可选扩展标记

日志、运行时参数读取、callback 准备、返回值写回，全部从这份定义派生。

### 3.2 ABI 与业务语义分层

必须把两个问题拆开:

1. “这个函数调用时参数从哪里来”。
2. “这个参数在业务上代表什么”。

前者属于 ABI 层，后者属于签名层。

### 3.3 惰性解构

不能在每次 Hook 分发时无脑把所有参数都读成字符串或结构体。

正确做法:

1. 先抓取 raw call frame。
2. 再按需要懒解构 typed parameter。
3. 日志和业务都消费同一份 lazy decode 接口。

这样才能兼顾性能和可维护性。

### 3.4 明确允许破坏式重构

因为业务尚未上线，本次方案建议:

- 不优先兼容旧 `HookDefinition` 结构
- 不优先兼容旧 `api_parameter_specs()` 模式
- 不优先兼容“所有 Hook 继续返回 `u64`”的长期接口

兼容层只作为迁移过渡，不作为终态。

### 3.5 保留特殊路径扩展点

系统必须从一开始就为这些情况预留:

- variadic CRT
- callback / synthetic call
- COM vtable method
- ordinal-based API
- out buffer / inout buffer
- pointer-to-pointer
- counted string
- opaque struct pointer
- future `arm64`

---

## 4. 目标架构

目标是把当前 Hook 体系重构为五层。

### 4.1 第 1 层: Signature Definition

位于 `HVM/src/hooks/`。

职责:

- 声明每个 Hook 的静态签名
- 作为日志和运行时的元数据源

建议核心结构:

```rust
pub struct HookSignature {
    pub module: &'static str,
    pub function: &'static str,
    pub abi: LogicalAbi,
    pub params: &'static [ParamSpec],
    pub ret: ReturnSpec,
    pub flags: HookFlags,
}
```

### 4.2 第 2 层: ABI Adapter

位于 `HVM/src/runtime/engine/abi/`。

职责:

- 根据样本架构提取 raw args
- 准备 callback 调用现场
- 写回返回值
- 处理 caller/callee 清栈规则

建议核心 trait:

```rust
pub trait AbiAdapter {
    fn capture_call_frame(
        &self,
        engine: &VirtualExecutionEngine,
        signature: &HookSignature,
    ) -> Result<RawCallFrame, VmError>;

    fn write_return_value(
        &self,
        engine: &mut VirtualExecutionEngine,
        signature: &HookSignature,
        value: HookValue,
    ) -> Result<(), VmError>;

    fn prepare_callback_frame(
        &self,
        engine: &mut VirtualExecutionEngine,
        callback: &CallbackSignature,
        args: &[HookValue],
    ) -> Result<PreparedCallbackFrame, VmError>;
}
```

### 4.3 第 3 层: Hook Context

位于 `HVM/src/runtime/engine/hook_context.rs`。

职责:

- 暴露 raw args
- 提供 typed getter
- 统一 guest memory 解构入口
- 为日志层和业务层提供相同的 decode 能力

建议核心结构:

```rust
pub struct HookContext<'a> {
    pub signature: &'a HookSignature,
    pub frame: &'a RawCallFrame,
    pub engine: &'a mut VirtualExecutionEngine,
}
```

典型接口:

```rust
ctx.raw(0)
ctx.get::<PCWSTR>(0)?
ctx.get::<Handle>(6)?
ctx.get::<U32>(4)?
ctx.get::<GuestPtr<SecurityAttributes>>(3)?
ctx.decode_for_log(0)?
```

### 4.4 第 4 层: Hook Runtime

位于 `HVM/src/runtime/engine/hooks/`。

职责:

- 实现业务语义
- 不再直接关心 ABI 差异
- 尽量使用 typed getter 和 `HookValue`

目标形式:

```rust
fn handle_create_file_w(ctx: &mut HookContext) -> Result<HookValue, VmError> {
    let path = ctx.get::<PCWSTR>(0)?;
    let desired_access = ctx.get::<U32>(1)?;
    let creation = ctx.get::<U32>(4)?;
    ...
    Ok(HookValue::handle(handle as u64, ctx.arch()))
}
```

### 4.5 第 5 层: Unified Logging

位于 `runtime/engine/logging_helpers.rs` 与 `runtime/api_logger.rs`。

职责:

- 不再依赖独立参数规格表
- 直接用 `HookSignature.params`
- 通过统一 decode policy 渲染参数和返回值

---

## 5. 新的数据模型设计

## 5.1 `LogicalAbi`

不要再把 ABI 直接写死成当前平台调用约定，建议定义逻辑 ABI。

```rust
pub enum LogicalAbi {
    WinApi,
    Cdecl,
    VariadicCdecl,
    Win64Only,
    ComMethod,
    Callback,
    Custom(&'static str),
}
```

推荐语义:

- `WinApi`: Windows API 默认 ABI
  - x86 -> stdcall
  - x64 -> Win64
  - arm64 -> WinArm64
- `Cdecl`: x86 cdecl, x64/arm64 走各自平台标准 ABI
- `VariadicCdecl`: 专门给 CRT 格式化函数
- `ComMethod`: 为 COM vtable `this` 约定预留
- `Callback`: 为 EnumWindows/TimerProc/SEH 等回调保留
- `Custom`: 给极少量异常路径兜底

这层非常关键。未来引入 `arm64` 时，大部分 Hook 不需要改签名，只需要让 `WinApi` 映射到新的 ABI 适配器。

## 5.2 `ParamSpec`

```rust
pub struct ParamSpec {
    pub name: &'static str,
    pub ty: ParamType,
    pub dir: ParamDirection,
    pub log: LogPolicy,
    pub flags: ParamFlags,
}
```

字段建议:

- `name`: 参数名
- `ty`: 参数类型
- `dir`: `In` / `Out` / `InOut`
- `log`: 是否渲染、如何渲染、是否截断
- `flags`: 扩展标记

## 5.3 `ParamType`

建议第一版至少覆盖以下类别。

标量:

- `Bool32`
- `I32`
- `U32`
- `I64`
- `U64`
- `Hex32`
- `Hex64`
- `SizeT`
- `SSizeT`
- `PointerSizedUInt`
- `PointerSizedInt`

句柄/地址:

- `Handle`
- `PseudoHandle`
- `ModuleHandle`
- `GuestPtr`
- `GuestPtrTo(Box<ParamType>)`
- `FunctionPtr`

字符串:

- `PCStr`
- `PCWStr`
- `PWStr`
- `PStr`
- `AnsiStringStruct`
- `UnicodeStringStruct`
- `CountedAnsi { len_param: usize, code_page_param: Option<usize> }`
- `CountedWide { len_param: usize }`

Buffer / Slice:

- `Buffer { len_param: usize }`
- `OutBuffer { len_param: usize }`
- `ByteSlice { len_param: usize }`
- `WideBuffer { len_param: usize }`

结构体:

- `Struct(&'static StructDecoder)`
- `OptionalStruct(&'static StructDecoder)`
- `OpaqueStructPtr(&'static str)`

专用 Windows 类型:

- `GuidPtr`
- `SidPtr`
- `SecurityAttributesPtr`
- `StartupInfoPtr`
- `ProcessInformationPtr`
- `OverlappedPtr`
- `FileTimePtr`
- `SystemTimePtr`

建议第一版不追求把所有 Windows 结构体都 typed 到字段级，而是先分三档:

1. 字符串/句柄/基本 buffer 全覆盖。
2. 常用结构体部分覆盖。
3. 复杂结构体先标记成 `OpaqueStructPtr`。

## 5.4 `ReturnSpec`

```rust
pub enum ReturnSpec {
    Void,
    Bool32,
    I32,
    U32,
    NtStatus,
    Win32Error,
    Handle,
    Pointer,
    PointerSizedUInt,
    PointerSizedInt,
    Custom(ReturnCodec),
}
```

这层的作用不是为了日志好看，而是为了系统自动做:

- pointer 截断
- signed i32 扩展
- handle 符号扩展
- invalid handle 宽度适配
- future arm64 pointer 宽度适配

## 5.5 `HookValue`

`HookValue` 保留并升级为返回值标准载体。

建议最终接口:

```rust
pub enum HookValue {
    Void,
    Raw(u64),
    U32(u32),
    I32(i32),
    Ptr(u64),
    Handle(u64),
    InvalidHandle,
    NtStatus(u32),
    Win32Error(u32),
}
```

然后由统一编码器在写回寄存器前，基于当前架构转成 raw `u64`。

当前已有的 `HookValue` 可以作为第一阶段基础，但建议最终升级为“带语义的 enum”，而不是只存一个 `raw: u64`。

原因:

- 日志层可以直接知道返回值语义
- callback/bridge 层也能复用
- 更适合后续扩展

## 5.6 `RawCallFrame`

```rust
pub struct RawCallFrame {
    pub args: SmallVec<[u64; 8]>,
    pub return_address: Option<u64>,
    pub stack_pointer: u64,
    pub instruction_pointer: u64,
    pub abi_snapshot: AbiSnapshot,
}
```

要求:

- 热路径避免堆分配
- 保留 `return_address`
- 保留必要的 ABI 快照，为 callback/continuation 使用

---

## 6. 新目录结构建议

建议新增或调整如下目录。

```text
HVM/src/
├── hooks/
│   ├── base.rs                      # 保留基础 trait，但升级为签名模型
│   ├── signature.rs                 # 新增: HookSignature / ParamSpec / ReturnSpec
│   ├── types.rs                     # 新增: ParamType / HookFlags / ParamDirection
│   ├── builders.rs                  # 新增: 静态签名构造辅助
│   └── families/
│       └── ...                      # 各模块族定义改为返回静态签名
│
└── runtime/engine/
    ├── abi/
    │   ├── mod.rs
    │   ├── adapter.rs               # AbiAdapter trait
    │   ├── x86.rs
    │   ├── x64.rs
    │   ├── arm64.rs                 # 第一阶段可空实现/占位
    │   ├── callback.rs              # 回调 ABI 准备
    │   └── frame.rs                 # RawCallFrame / AbiSnapshot
    ├── hook_context.rs              # HookContext / typed getter
    ├── hook_decode/
    │   ├── mod.rs
    │   ├── scalar.rs
    │   ├── string.rs
    │   ├── buffer.rs
    │   ├── pointer.rs
    │   ├── structs.rs
    │   └── windows.rs
    ├── hook_value.rs                # 升级
    └── ...
```

### 6.1 为什么要新增 `arm64.rs` 占位

即使第一阶段没有 `arm64` 执行后端，也建议新增空占位。

原因:

1. 强迫签名与 ABI 层设计时不把 x86/x64 写死。
2. 强迫返回值编码、pointer-sized 逻辑走统一接口。
3. 后续接入 `arm64` 时，不需要再翻新主设计。

---

## 7. 对现有文件的改造清单

下面是建议的文件级改造。

## 7.1 `HVM/src/hooks/base.rs`

### 现状

- 定义 `CallConv`
- 定义 `HookDefinition`
- 定义 `HookLibrary`

### 改造目标

替换为:

- `LogicalAbi`
- `HookSignature`
- `HookLibrary` 返回静态签名列表

### 建议动作

1. 弃用 `HookDefinition.argc`，改为 `params.len()`。
2. 弃用 `CallConv` 作为主模型，保留仅作兼容别名。
3. `HookLibrary::collect()` 改为返回 `Vec<HookSignature>` 或 `&'static [HookSignature]`。
4. 优先推动静态数组，不再在热路径组装 `Vec`。

### 推荐最终状态

- `HookDefinition` 彻底移除，或只保留极短期兼容层。

## 7.2 `HVM/src/hooks/registry.rs`

### 改造目标

Registry 绑定的不是“只有 argc 和 callconv 的定义”，而是完整签名。

### 建议动作

1. `definitions: HashMap<(String, String), HookSignature>`
2. `definition_for_address()` 返回 `&HookSignature`
3. 所有 stub 绑定流程切换到新签名
4. 如果仍保留兼容层，确保签名转换只发生在注册阶段，不发生在运行热路径

## 7.3 `HVM/src/hooks/families/*`

### 改造目标

各模块族定义文件从“只声明函数名和参数个数”升级为“完整静态签名表”。

### 建议动作

1. 给每个导出函数补 `params` 和 `ret`
2. 优先补高频 DLL:
   - `kernel32`
   - `ntdll`
   - `advapi32`
   - `user32`
   - `msvcrt`
3. 允许大型 DLL 分拆为:
   - `exports.rs`
   - `signatures.rs`
   - `builders.rs`

### 推荐风格

```rust
hook_sig!(
    module: "kernel32.dll",
    function: "CreateFileW",
    abi: LogicalAbi::WinApi,
    params: [
        p!("lpFileName", ParamType::PCWStr),
        p!("dwDesiredAccess", ParamType::Hex32),
        p!("dwShareMode", ParamType::Hex32),
        p!("lpSecurityAttributes", ParamType::SecurityAttributesPtr),
        p!("dwCreationDisposition", ParamType::U32),
        p!("dwFlagsAndAttributes", ParamType::Hex32),
        p!("hTemplateFile", ParamType::Handle),
    ],
    ret: ReturnSpec::Handle,
);
```

## 7.4 `HVM/src/runtime/engine.rs`

### 改造目标

把当前分发入口里“架构取参 + 返回写回”的逻辑迁到 ABI 适配层。

### 建议动作

1. 抽离 `capture_call_frame_x86`
2. 抽离 `capture_call_frame_x64`
3. 抽离 `write_return_value_x86`
4. 抽离 `write_return_value_x64`
5. 主流程只保留:
   - 取 `AbiAdapter`
   - 采 `RawCallFrame`
   - 传给 `HookContext`
   - 处理返回值

### 推荐最终状态

`engine.rs` 中不再直接出现:

- `RCX/RDX/R8/R9` 取参细节
- `ESP/RSP` 清栈细节
- `EAX/RAX` 写回细节

这些逻辑全部下沉到 `runtime/engine/abi/*`。

## 7.5 `HVM/src/runtime/engine/hooks/family_dispatch.rs`

### 改造目标

总分发改成 typed context 驱动。

### 建议动作

1. `dispatch_bound_stub_with_definition(...)` 改为接收 `HookSignature`
2. 在这里创建 `HookContext`
3. 统一返回 `HookValue`
4. `log_api_call` / `log_api_return` 直接消费签名元数据

### 推荐最终流程

1. Registry 找到 `HookSignature`
2. ABI adapter 抓 `RawCallFrame`
3. `HookContext::new(signature, frame, engine)`
4. 路由到 DLL handler
5. handler 返回 `HookValue`
6. ABI adapter 写回
7. 日志层记录参数和返回

## 7.6 `HVM/src/runtime/engine/logging_helpers.rs`

### 改造目标

日志层不再自己维护参数类型表。

### 建议动作

1. 删除 `ApiArgKind::Auto` 作为默认主路径
2. `describe_api_call_args()` 改为直接遍历 `signature.params`
3. 返回值渲染基于 `signature.ret`
4. 增加 `decode_param_for_log(param_spec, raw_value, ctx)` 统一逻辑

### 推荐最终状态

- `logging_helpers.rs` 只负责“渲染”
- 参数类型定义不再留在这里

## 7.7 `HVM/src/runtime/engine/shared/api_logging.rs`

### 改造目标

彻底取消独立参数规格表。

### 建议动作

1. 删除 `api_parameter_specs()`
2. 把里面的参数信息迁回 `hooks/families/*`
3. 把少量复杂 custom render 保留为:
   - 自定义 decoder
   - 自定义 formatter

### 特别说明

这一步是本次迁移最重要的收敛动作之一。

如果这一层不删，系统会重新回到“双份真相源”。

## 7.8 `HVM/src/runtime/engine/shared/guest_memory.rs`

### 改造目标

保留通用 guest memory helper，但新增 typed decode 支持。

### 建议动作

新增或拆出:

- `read_guest_cstr`
- `read_guest_wstr`
- `read_counted_ansi`
- `read_counted_wide`
- `read_guest_ptr_sized`
- `read_guest_struct<T>`
- `read_guest_slice`

### 推荐边界

`guest_memory.rs` 只做内存读取和基础 decode，不承载 Hook 业务语义。

## 7.9 `HVM/src/runtime/engine/hook_value.rs`

### 改造目标

接入主流程，并升级为强语义返回值。

### 建议动作

1. 主 dispatch 全量改为 `Result<HookValue, VmError>`
2. 增加 `encode_for_arch(arch)` 或 `into_raw_for_arch(arch)`
3. 增加返回值日志格式化
4. 删除项目里散落的 `arch_ptr / arch_i32 / invalid_handle_value_for_arch` 直接调用热点

### 兼容策略

短期可以保留:

```rust
impl From<u64> for HookValue
```

但中期要尽量把热点 Hook 全迁为显式语义返回。

---

## 8. 参数类型系统设计细节

## 8.1 typed getter 设计

建议不要在 `HookContext` 上暴露大量专用方法，而是走统一 trait。

```rust
pub trait FromHookParam: Sized {
    fn decode(ctx: &HookContext, index: usize, spec: &ParamSpec) -> Result<Self, VmError>;
}
```

这样可以支持:

- `ctx.get::<u32>(1)?`
- `ctx.get::<Handle>(0)?`
- `ctx.get::<PcWStr>(2)?`
- `ctx.get::<GuestPtr<MyStruct>>(3)?`

## 8.2 建议内建类型别名

建议内建以下业务友好类型:

- `Bool32`
- `U32`
- `I32`
- `SizeT`
- `Handle`
- `ModuleHandle`
- `PseudoHandle`
- `GuestAddress`
- `PcStr`
- `PcWStr`
- `AnsiStringRef`
- `UnicodeStringRef`
- `GuestBuffer`
- `OutBuffer`
- `InOutBuffer`
- `GuestStruct<T>`

这样运行时 handler 读起来更像业务代码。

## 8.3 指针读取策略

建议每个 pointer 类型都可声明读取策略:

- `Opaque`
- `TryString`
- `DecodeStruct`
- `DecodeBuffer(len_param)`
- `DecodePointerChain(depth_limit)`

避免所有 pointer 都默认按字符串猜。

## 8.4 字符串截断策略

建议把字符串截断从全局配置扩展为“全局限制 + 类型默认 + 参数覆盖”三层。

例如:

- 全局 `api_log_string_limit`
- `PCWStr` 默认截断 256 字符
- 某些 buffer 型参数单独指定截断 64 字节

## 8.5 out 参数策略

必须把 out 参数显式建模，而不是让 handler 自己记“哪个参数是输出指针”。

建议 `ParamDirection`:

- `In`
- `Out`
- `InOut`

这样日志层也能区分:

- 调用前值
- 返回后值

第一阶段如果不做调用后自动采样，至少要把这个信息留在模型里。

---

## 9. ABI 层设计细节

## 9.1 x86 / x64 统一入口

建议以架构 + 逻辑 ABI 双维度决定参数来源。

例如:

| 架构 | `LogicalAbi::WinApi` | `LogicalAbi::Cdecl` | `LogicalAbi::ComMethod` |
| --- | --- | --- | --- |
| `x86` | stdcall 栈传参 | cdecl 栈传参 | ecx/stack 或约定扩展 |
| `x64` | Win64 RCX/RDX/R8/R9 + stack | 同平台 ABI | RCX=this |
| `arm64` | x0-x7 + stack | 同平台 ABI | x0=this |

这张映射表必须集中管理，不能散落在 Hook 文件。

## 9.2 callback 模型

callback 不应该继续以“每个模块手写一个 x86/x64 schedule/complete”作为长期方案。

建议新增:

```rust
pub struct CallbackSignature {
    pub abi: LogicalAbi,
    pub params: &'static [ParamSpec],
    pub ret: ReturnSpec,
}
```

然后统一支持:

- User32 timer callback
- EnumWindows callback
- SendMessage callback
- CRT initterm callback
- future APC / thread start routine / VEH / SEH callback

## 9.3 variadic 函数

不要把 variadic 函数强行纳入普通静态参数数组。

建议模型:

```rust
pub enum ParamListKind {
    Fixed(&'static [ParamSpec]),
    Variadic {
        fixed: &'static [ParamSpec],
        decoder: VariadicDecoderKind,
    },
}
```

适用:

- `printf`
- `sprintf`
- `wsprintf`
- `FormatMessage`

## 9.4 synthetic call / native bridge

当前项目里存在:

- synthetic stub
- callback schedule
- native Unicorn call helper

建议全部改成共用 ABI adapter 的 frame prepare/writeback 逻辑。

这样可以避免:

- 一套主调分发 ABI
- 一套 callback ABI
- 一套 native helper ABI

三套平行逻辑持续漂移。

---

## 10. 推荐实施阶段

建议拆成 7 个阶段，每阶段都可单独提交并通过测试。

## 阶段 0: 设计冻结与脚手架

### 目标

先把主模型建好，不迁业务。

### 动作清单

1. 新增 `hooks/signature.rs`
2. 新增 `hooks/types.rs`
3. 新增 `runtime/engine/abi/`
4. 新增 `runtime/engine/hook_context.rs`
5. 升级 `hook_value.rs`
6. 允许 `HookDefinition -> HookSignature` 临时转换
7. 新增空 `arm64.rs` 占位

### 交付标准

- 不迁任何 Hook 业务也能编译
- 新老模型可并存

## 阶段 1: 接通主分发链路

### 目标

让主分发以 `HookSignature + RawCallFrame + HookValue` 运转。

### 动作清单

1. Registry 存储 `HookSignature`
2. `dispatch_bound_stub_with_definition()` 升级为签名驱动
3. x86/x64 raw frame capture 下沉到 ABI adapter
4. 返回值写回改为 `HookValue`
5. 保留 `From<u64>` 兼容旧 handler

### 验收标准

- 老 Hook 代码在兼容层下仍可跑
- 分发入口不再直接处理业务参数语义

## 阶段 2: 日志系统收敛

### 目标

移除独立的 `api_parameter_specs()`。

### 动作清单

1. 日志层改为直接读 `HookSignature.params`
2. 删除 `ApiArgKind::Auto` 主路径
3. 复杂 API 用 `custom decoder` 补齐
4. 返回值日志基于 `ReturnSpec`

### 验收标准

- `runtime/engine/shared/api_logging.rs` 不再维护大型参数规格表
- 日志渲染不再依赖双份元数据

## 阶段 3: 核心 DLL 迁移

### 目标

先迁影响面最大的家族。

### 优先级

1. `kernel32.dll`
2. `ntdll.dll`
3. `advapi32.dll`
4. `user32.dll`
5. `msvcrt.dll`

### 动作清单

1. 给这些模块补完整签名
2. 把高频 Hook 改为 typed getter
3. 返回值切到显式 `HookValue`
4. 补充 x86/x64 对比测试

### 交付标准

- 这五个模块不再新增 `arg(args, i)` 写法

## 阶段 4: callback / variadic / COM 迁移

### 目标

处理最容易漂移的特殊路径。

### 范围

- user32 callbacks
- CRT variadic
- COM vtable method
- custom native bridge

### 交付标准

- callback 准备逻辑走统一 ABI adapter
- variadic 解码模型固定下来

## 阶段 5: 全家族迁移

### 目标

把剩余模块族全部切到新模型。

### 范围

- network
- shell_services
- device
- security 其余部分
- graphics
- diagnostics
- installer
- print

### 交付标准

- `runtime/engine/hooks/` 不再出现新增旧模式 handler

## 阶段 6: 清理兼容层

### 目标

移除迁移期遗留。

### 动作清单

1. 删除旧 `HookDefinition`
2. 删除 `api_parameter_specs()`
3. 删除主路径中的 `arg(args, i)` 辅助
4. 删除多余 `arch_ptr` / `arch_i32` 业务侧直用
5. 删除旧测试中的固定 32 位 handle 假设

### 验收标准

- 新架构成为唯一主路径

---

## 11. 分模块迁移清单

下面给出建议的模块族级别清单。

## 11.1 `core`

### 重点 DLL

- `kernel32`
- `ntdll`
- `psapi`
- `version`

### 必迁点

- `CreateFileA/W`
- `CreateProcessA/W`
- `LoadLibrary*`
- `GetProcAddress`
- `GetModuleHandle*`
- `VirtualAlloc*`
- `VirtualProtect*`
- `VirtualQuery*`
- `GetCurrentProcess`
- `GetCurrentThread`
- `GetProcessHeap`
- `Tls*`
- `Heap*`
- `MapViewOfFile`
- `CreateFileMapping*`
- `Nt*` handle / pointer / status 系列

### 风险点

- pseudo handle 返回
- `INVALID_HANDLE_VALUE`
- x86/x64 `UNICODE_STRING`
- pointer-sized out 参数

## 11.2 `crt`

### 重点 DLL

- `msvcrt`
- `vcruntime140`

### 必迁点

- `malloc/free/realloc`
- `memcpy/memmove/memset`
- `strlen/wcslen/strcmp`
- `printf/sprintf/wsprintf`
- `_initterm`
- `_onexit`

### 风险点

- variadic ABI
- signed return
- char / wchar_t buffer 渲染

## 11.3 `ui`

### 重点 DLL

- `user32`
- `comctl32`
- `mfc42u`

### 必迁点

- 窗口句柄返回
- callback 类 API
- message 结构体指针
- atom 返回

### 风险点

- callback `this` / user data
- pointer-sized handle

## 11.4 `com`

### 重点 DLL

- `ole32`
- `oleaut32`
- `combase`
- `rpcrt4`

### 必迁点

- GUID / IID / CLSID 指针
- `BSTR`
- `VARIANT`
- `DISPPARAMS`
- `IUnknown` / `IDispatch` 方法

### 风险点

- 非字符串指针被日志误判
- pointer-to-pointer
- out object pointer

## 11.5 `network`

### 重点 DLL

- `winhttp`
- `wininet`
- `ws2_32`
- `iphlpapi`
- `mpr`
- `netapi32`

### 必迁点

- socket handle
- hostname / url / header 字符串
- input/output buffer
- counted string

### 风险点

- ANSI code page
- buffer length 参数成对出现

## 11.6 `security`

### 重点 DLL

- `advapi32`
- `crypt32`
- `bcrypt`
- `ncrypt`
- `secur32`

### 风险点

- SID / ACL / TOKEN / CERT 结构体
- opaque struct pointer
- handle / status 混合返回

## 11.7 `device` / `graphics` / `diagnostics` / `print` / `installer`

### 策略

这些家族可以放到后置阶段，按“先把参数元数据补齐，再逐步 typed 化”执行。

---

## 12. 推荐的落地顺序

如果只考虑推进效率，建议顺序如下。

### 第一批

- `kernel32`
- `ntdll`
- `advapi32`
- `user32`
- `msvcrt`

### 第二批

- `winhttp`
- `wininet`
- `ws2_32`
- `ole32`
- `oleaut32`
- `combase`

### 第三批

- `psapi`
- `shell32`
- `shlwapi`
- `wtsapi32`
- `setupapi`
- `cfgmgr32`

### 第四批

- `graphics`
- `diagnostics`
- `print`
- `installer`

理由:

1. 第一批覆盖返回值和字符串问题最集中。
2. 第二批覆盖 buffer / struct pointer / COM 复杂指针问题。
3. 第三批开始清理边缘系统 API。
4. 第四批风险最低，适合收尾。

---

## 13. 性能要求

本次改造不能以可维护性为名，显著恶化热路径性能。

## 13.1 强约束

1. Hook 分发热路径不能频繁堆分配。
2. 参数解码必须惰性执行。
3. 日志关闭时，不应触发额外字符串解码。
4. 静态签名必须以 `'static` 形式存在，不能每次组装 `Vec`。

## 13.2 推荐实现

1. `RawCallFrame.args` 使用 `SmallVec<[u64; 8]>`
2. `HookSignature.params` 使用 `&'static [ParamSpec]`
3. `decode_for_log()` 只在 logger 启用时调用
4. `typed getter` 读字符串或结构体前先检查参数值是否为 `0`

## 13.3 禁止事项

1. 禁止每次 Hook 调用重新构造参数规格数组
2. 禁止日志系统默认对所有 pointer 自动探测字符串
3. 禁止为了统一接口，把所有参数预先 decode 成 `String`

---

## 14. 测试计划

测试要跟随“语义层”而不是“表面接口”迁移。

## 14.1 新增测试类型

### A. ABI 抽取测试

目标:

- 验证 x86 / x64 参数来源正确
- 验证 caller/callee stack cleanup 正确

覆盖:

- `WinApi`
- `Cdecl`
- callback
- variadic

### B. typed decode 测试

目标:

- `PCStr`
- `PCWStr`
- counted string
- handle
- pointer-sized value
- struct pointer
- out buffer

### C. return encoding 测试

目标:

- `Handle`
- `InvalidHandle`
- `I32(-1)`
- `Pointer`
- `NtStatus`

必须覆盖 `x86` / `x64`，为 `arm64` 预留空测试模板。

### D. logging render 测试

目标:

- 参数文字渲染正确
- 不再出现 `Auto` 误判乱码
- 返回值渲染与 `ReturnSpec` 一致

### E. callback roundtrip 测试

目标:

- user32 timer callback
- sendmessage callback
- CRT initterm callback

## 14.2 现有测试修正项

当前测试里存在部分固定 32 位假设，需要统一修正。

必须修正:

1. `INVALID_HANDLE_VALUE == u32::MAX` 的硬编码断言
2. handle 返回值未按架构扩展的断言
3. pointer-sized out 参数读取固定 4 字节的断言

建议统一提供:

- `runtime_invalid_handle_value(engine)`
- `runtime_pointer_size(engine)`
- `read_runtime_pointer(engine, addr)`

作为测试基线工具，避免各测试重复写错。

## 14.3 验收指标

迁移完成后至少满足:

1. 核心 DLL 全部存在显式签名
2. 不再新增 `ApiArgKind::Auto` 主路径
3. 关键返回值都有 x86/x64 对照测试
4. callback / variadic / COM 至少各有一条回归链路

---

## 15. 迁移期间的工程规则

为防止迁移过程中再次散乱，建议从现在开始执行以下规则。

### 规则 1

新增 Hook 不允许只写 `argc`，必须写完整签名。

### 规则 2

新增 pointer 参数，不允许依赖日志自动探测字符串。

### 规则 3

新增返回值，如果语义不是 plain `u32 error code`，必须显式使用 `HookValue`。

### 规则 4

新增 callback，不允许直接在模块文件里复制一套 x86/x64 schedule/complete 逻辑，必须先复用 ABI adapter。

### 规则 5

新增 variadic Hook，不允许假装是固定参数 Hook，必须挂到 variadic 模型。

### 规则 6

大型 DLL 如果签名过多，允许拆 `signatures.rs`，但不能把参数元数据重新塞回 `logging_helpers.rs`。

---

## 16. 推荐的破坏式决策

既然业务尚未上线，下面这些决策建议一次性做掉，不要拖成长期历史包袱。

### 决策 A

删除独立 `api_parameter_specs()`。

原因:

- 双份真相源是未来维护的最大隐患。

### 决策 B

让 `HookSignature` 取代 `HookDefinition`。

原因:

- 旧定义模型信息不足，不值得继续维护。

### 决策 C

主 dispatch 统一返回 `HookValue`。

原因:

- 返回值语义问题已经被文档明确识别，继续保留裸 `u64` 只会反复出错。

### 决策 D

新增 `arm64` ABI 占位模块。

原因:

- 强迫设计面向未来，而不是围绕当前实现缝补。

### 决策 E

把 callback / synthetic call / native bridge 全部纳入 ABI 层。

原因:

- 当前多条并行路径后续极易继续漂移。

---

## 17. 预计工作量

按当前代码规模估算，这不是“小改造”。

可粗略按以下量级理解:

- `arg(args, N)` 现存调用约 2331 处
- 依赖 `u64` 返回的 handler 签名约 352 处
- 独立日志参数规格约 382 条

这意味着真正的一次性迁移需要分阶段推进。

### 建议人力预估

如果由 1 名熟悉代码的主工程师推进:

- 基础设施 + 设计冻结: 3 到 5 天
- 主分发 + 日志收敛: 5 到 7 天
- 核心 DLL 迁移: 7 到 10 天
- 特殊路径和全家族收尾: 7 到 10 天

总体:

- 3 到 5 周

如果有 2 人并行:

- 1 人负责 ABI / dispatch / logging 主链
- 1 人负责 family signatures + hook 迁移

可压缩到:

- 2 到 3 周

---

## 18. 最终验收标准

以下条件全部满足，才算迁移完成。

### 架构层

1. 主分发不再直接写死 x86/x64 参数提取逻辑
2. `arm64` ABI 占位已存在
3. callback 走统一 ABI 适配层

### 签名层

1. 所有核心 DLL 均由 `HookSignature` 描述
2. 参数类型、返回类型、逻辑 ABI 都在签名中
3. 不再维护独立参数规格表

### 业务层

1. 核心 Hook 不再依赖 `arg(args, i)` 手工读参
2. 核心 Hook 返回 `HookValue`
3. 新增 Hook 开发流程只需要维护一份签名

### 日志层

1. 不再走 `Auto` 猜测主路径
2. 字符串、指针、结构体、buffer 日志由统一 decode policy 驱动
3. 返回值日志按 `ReturnSpec` 渲染

### 测试层

1. x86 / x64 返回值语义有对照测试
2. callback / variadic / COM 各至少有一条回归链路
3. 所有固定 32 位 handle 假设已清理

---

## 19. 结论

这次改造的核心不是“做一个 x86/x64 的薄封装”，而是把 Hook 体系从“裸 ABI + 手工取参 + 分裂日志规则”升级成“签名驱动 + ABI 适配 + typed decode + 语义化返回”的系统。

如果只做局部补丁:

- `x86` / `x64` 差异仍会在 Hook 文件里继续扩散
- 日志规格和业务参数仍会继续漂移
- future `arm64` 仍会把现有设计打穿

如果按本文方案一次性做结构升级，后续新增 Hook 的成本会明显下降，未来引入 `arm64` 也会有明确落点。

这次建议按破坏式重构推进，不要为旧模型保留长期债务。
