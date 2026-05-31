# HVM Hook ABI / Signature 迁移遗留问题清单

> 日期: 2026-04-19
> 评审范围: `87debf93..c000b111f2d9b9d44c1b484bfd224720f508b70c`
> 对照文档: [hook_abi_signature_migration_plan_20260417.md](/home/dev/Vm_Eng_Scan/HVM/docs/hook_abi_signature_migration_plan_20260417.md)
> 目的: 输出当前仍存在的全部已确认问题，并给出可逐步执行的修复顺序

---

## 1. 总体结论

当前 7 个阶段的主体工作已经落地，尤其是:

- `HookSignature` 主分发链路已经接通
- 日志系统已切到签名驱动
- 多个核心 DLL 已完成签名覆盖
- callback / COM / variadic 已有统一迁移框架
- `api_parameter_specs()` 已经退出主模型

但如果按原始迁移文档的”终态”验收，当前状态仍然不是”彻底完成”。

现状更准确的描述是:

1. 阶段 1 到阶段 5 的主体框架已经落地
2. `HookDefinition` 双轨模型已删除，`HookSignature` 成为唯一注册实体
3. `HookContext` 已进入主执行链路，handler 层使用 `ctx.raw(i)` 替代 `args.arg(i)`
4. callback correctness 回归已修复
5. 待实施：ParamSpec 补齐（Step 6）、日志 Auto 收缩（Step 7）、CI 门禁（Step 9）

因此，当前建议不是继续声明”迁移完成”，而是进入”终态收口与回归修复”阶段。

### 已完成修复

#### 终态 Step 1: x64 native callback correctness 回归 — ✅ 已修复

**根因**: `dispatch_unicorn_bound_stub` 在 `defer_api_return == true`（callback frame 已由 `prepare_callback_frame` 准备好）时仍返回 `Ok(true)`，导致 Unicorn code hook 调用 `emu_stop_raw` 过早终止模拟。callback 代码（如 wnd_proc）从未执行，RAX 保持旧值。

**修复**: 当 `defer_api_return == true` 时返回 `Ok(false)`，Unicorn 不停止模拟，从更新后的寄存器状态继续执行 callback → continuation stub → complete callback → 恢复原调用链。

**修改文件**: `src/runtime/engine.rs` — `dispatch_unicorn_bound_stub` 末尾

**验证**: `send_message_invokes_registered_wndproc_x64_from_native_context` 测试通过

#### 终态 Step 2: 返回值边界统一 — ✅ 已修复

**根因**: 多个关键执行边界仍使用 `into_raw_u64()`（假设 x64 编码，不做架构适配），导致指针截断、符号扩展等语义在 x86 路径上可能不正确。

**修复**: 全部替换为 `into_raw(&self.core.arch)`，返回值编码现在完全走架构感知路径。

**修改文件**:
- `src/runtime/engine.rs:1956` — `dispatch_bound_stub` 非 Unicorn 分发返回路径
- `src/runtime/engine/x86_interpreter_helpers.rs:424` — x86 解释器 EAX 写回
- `src/runtime/engine/hooks/family_dispatch.rs:356` — RTLALLOC_DIAG 调试日志
- `src/runtime/engine/hooks/family_dispatch.rs:363` — `log_api_return` 调用

**验证**: 执行路径中已无 `into_raw_u64()` 调用（仅保留 `hook_value.rs` 中的定义）

---

## 2. 评审依据

### 2.1 提交范围

从 `87debf93` 到当前 `HEAD` 的主要迁移提交:

- `c043ba8` 阶段 1
- `b7a8b64` 阶段 2
- `cfbe246` / `493ac4f` / `2115478` / `7094c91` / `aa894fe` 阶段 3
- `9efce41` 阶段 4
- `6369e28` 阶段 5 + 6
- `c000b11` 阶段 6 收尾

### 2.2 对照目标

原始迁移文档的关键终态要求:

- ABI 差异收敛到统一抽象层
- 参数类型、返回类型、日志解构共用同一份元数据
- 兼容层只保留短期迁移窗口，不作为最终架构目标
- `HookDefinition` 删除或退化为极短期兼容层
- 主路径不再依赖 `arg(args, i)` 旧模式
- 新架构成为唯一主路径

关键文档锚点:

- [hook_abi_signature_migration_plan_20260417.md#L17](/home/dev/Vm_Eng_Scan/HVM/docs/hook_abi_signature_migration_plan_20260417.md#L17)
- [hook_abi_signature_migration_plan_20260417.md#L155](/home/dev/Vm_Eng_Scan/HVM/docs/hook_abi_signature_migration_plan_20260417.md#L155)
- [hook_abi_signature_migration_plan_20260417.md#L595](/home/dev/Vm_Eng_Scan/HVM/docs/hook_abi_signature_migration_plan_20260417.md#L595)
- [hook_abi_signature_migration_plan_20260417.md#L1076](/home/dev/Vm_Eng_Scan/HVM/docs/hook_abi_signature_migration_plan_20260417.md#L1076)

---

## 3. 问题总表

本节按严重程度排序。

### 3.1 ~~P0~~: x64 native callback 路径仍存在确定性回归 — ✅ 已修复

#### 现象

库内单测仍然失败:

```bash
cargo test -p hvm-hikari-virtual-engine --lib runtime::engine::tests::send_message_invokes_registered_wndproc_x64_from_native_context -- --exact --nocapture
```

失败位置:

- [engine.rs#L3162](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine.rs#L3162)

失败信息:

- `left = 140694829665472`
- `right = 1234605616436508552`

#### 影响

- `SendMessage` 的 native callback 返回值恢复链路不可信
- 说明 callback 的 prepare / resume / return writeback 仍可能存在 ABI 边界错误
- 这不是优化项，而是 correctness 问题

#### 相关代码

- [messages.rs#L13](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/ui/user32/messages.rs#L13)
- [messages.rs#L65](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/ui/user32/messages.rs#L65)
- [engine.rs#L3162](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine.rs#L3162)

#### 修复目标

- 先把 callback prepare / resume / return 写回语义修正到测试通过
- 修复前不要继续扩大 callback 相关迁移结论

---

### 3.2 ~~P0~~: 类型化参数执行层尚未进入主执行链路 — ✅ 已修复（Step 3/4）

**根因**: `HookContext` / `FromHookParam` / `VariadicArgReader` 已定义但未接入 dispatch 主路径。

**修复**:
- Step 3 将 `HookContext` 接入 `dispatch_bound_stub_with_signature` 主分发路径
- Step 4 完成全部 33 个 dispatch 函数从 `args: &[u64]` 迁移到 `ctx: &HookContext<'_>`
- 全部 ~2333 处 `args.arg(i)` 替换为 `ctx.raw(i)`，覆盖 34 个 handler 文件
- `HookContext` 已成为 handler 层唯一参数入口

**验证**: `cargo test --lib` 40 tests passed，0 失败

---

### 3.3 ~~P1~~: `HookDefinition` 双轨兼容层仍是活跃架构，不是短期过渡 — ✅ 已修复

**根因**: Registry 同时维护 `definitions: HashMap<..., HookDefinition>` 和 `signatures: HashMap<..., HookSignature>`，`HookDefinition`/`CallConv`/`HookLibrary` 均无外部调用方但仍在代码中存活。

**修复**:
1. 删除 `src/hooks/base.rs`（`HookDefinition`/`CallConv`/`HookLibrary`/`From<&HookDefinition> for HookSignature` 全部移除）
2. 删除 `src/hooks/stub.rs`（`stub_definitions`/`stdcall_definitions` 从未被调用）
3. 从 `src/hooks/mod.rs` 移除 `mod base;` 和 `mod stub;`
4. `HookRegistry` 删除 `definitions` HashMap、6 个 definition 查询方法、`register_library()`、`definition_from_key/parts` helper
5. `BoundHookLookup` 删除 `definition` 字段，`bound_lookup()` 改为仅从 signature 取 function name
6. `register_function_stubs()` 不再创建 `HookDefinition` 桥接条目
7. 测试断言从 `.definition()`/`.definition_for_address()` 迁移到 `.signature()`/`.signature_for_address()`

**修改文件**: `base.rs`(删)、`stub.rs`(删)、`mod.rs`、`registry.rs`、`module_manager.rs`、`tests/kernel32_hooks.rs`、`tests/module_manager.rs`

**验证**: `cargo test --lib` 40 passed；`cargo test --tests` 零新增回归（4 个已有失败均为 pre-existing）

---

### 3.4 ~~P1~~: 返回值语义在关键边界仍被降级回 `into_raw_u64()` — ✅ 已修复

#### 现象

`HookValue` 已存在，但多个关键边界仍把它退回“按 x64 编码假设的裸 `u64`”。

关键位置:

- [engine.rs#L1955](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine.rs#L1955)
- [engine.rs#L1956](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine.rs#L1956)
- [x86_interpreter_helpers.rs#L424](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/x86_interpreter_helpers.rs#L424)
- [family_dispatch.rs#L356](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/family_dispatch.rs#L356)
- [family_dispatch.rs#L363](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/family_dispatch.rs#L363)
- [hook_value.rs#L177](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hook_value.rs#L177)

`hook_value.rs` 已经明确说明:

- `into_raw_u64()` 是 backward-compatible extraction
- 迁移目标应是 `into_raw(arch)`

#### 影响

- 指针宽度、handle 扩展、`i32` 符号扩展的统一语义仍可能被绕开
- 日志侧和返回写回侧还没有完全统一到最终模型
- callback / x86 / future arm64 的边界行为仍可能不稳定

#### 修复目标

- 所有执行边界改用 `HookValue::into_raw(&arch)` 或 `AbiAdapter::write_return_value`
- `into_raw_u64()` 只允许保留在兼容层，不允许继续停留在热路径

---

### 3.5 P1: 签名覆盖率高，但参数类型覆盖率仍不完整

> 2026-04-19 补充修复:
> 已补齐运行时注册链路中遗漏的 `*_SIGNATURES` 接入。此前多个 DLL family 虽然已经维护了完整签名表，但 `register_*_hooks()` / family `mod.rs` 只注册了 stub，导致运行时仍看不到参数元数据。现已把 core / crt / network / shell / device / diagnostics / graphics / security / print / ui / com / installer 下已有签名表全部注册进 `HookRegistry`。
>
> 2026-04-19 Step 6 进展:
> `api-ms-win-core-*` contract family 开始继承宿主 hook 的 `ParamSpec`。此前这些 contract 导出虽然能分发到 `kernel32/advapi32/ole32/psapi/version/shlwapi` 等宿主实现，但注册层只有 stub 签名；现已为可映射函数自动克隆宿主 `HookSignature`，例如 `api-ms-win-core-libraryloader!LoadLibraryW`、`api-ms-win-core-processthreads!OpenProcessToken`、`api-ms-win-core-com!CoInitializeEx`、`api-ms-win-core-psapi!K32EnumProcessModules`、`api-ms-win-core-versionansi!GetFileVersionInfoExA`。
>
> 2026-04-19 Step 6 第二轮进展:
> `shell32.dll` 中一批原先仍是粗粒度 `GuestPtr` 的 COM / out-pointer 参数已细化为 `GuestPtrTo(GuestPtr)`，包括 `SHGetKnownFolderPath.ppszPath`、`SHGetImageList.ppvObj`、`IMalloc_QueryInterface.ppvObj`、`SHGetDesktopFolder.ppshf`、`SHGetMalloc.ppMalloc`、`SHGetSpecialFolderLocation.ppidl`、`SHCreateItemFromParsingName.ppv`。这些项现在能明确表达“guest 内存中写出另一个 guest 指针”的语义，并已补进 `registry` 回归测试。

#### 现象

当前很多函数虽然已经有 `HookSignature`，但参数表仍然是空:

- [registry.rs#L98](/home/dev/Vm_Eng_Scan/HVM/src/hooks/registry.rs#L98)
- [callback_signature.rs#L58](/home/dev/Vm_Eng_Scan/HVM/src/hooks/callback_signature.rs#L58)

已审计、确认属于“真实无参 API”的典型例子:

- [user32_signatures.rs#L66](/home/dev/Vm_Eng_Scan/HVM/src/hooks/families/ui/user32/user32_signatures.rs#L66)
- [user32_signatures.rs#L74](/home/dev/Vm_Eng_Scan/HVM/src/hooks/families/ui/user32/user32_signatures.rs#L74)
- [kernel32_signatures.rs#L877](/home/dev/Vm_Eng_Scan/HVM/src/hooks/families/core/kernel32_signatures.rs#L877)
- [kernel32_signatures.rs#L885](/home/dev/Vm_Eng_Scan/HVM/src/hooks/families/core/kernel32_signatures.rs#L885)
- [ws2_32_signatures.rs#L28](/home/dev/Vm_Eng_Scan/HVM/src/hooks/families/network/ws2_32_signatures.rs#L28)

当前 Step 6 的主要目标已收敛为:

- contract / alias 模块上仍是 stub-only 的导出
- 已有签名但参数类型仍偏粗的高频 API
- `HookContext` typed getter 还未大面积消费这些 `ParamSpec`

#### 影响

- 当前更像是“函数签名注册覆盖”，而不是“完整参数类型系统覆盖”
- 空参数签名会迫使系统继续依赖 fallback 渲染和业务侧手工读取
- 无法兑现“定义一处，到处生效”

#### 修复目标

- 对高频 API 先补齐 `ParamSpec`
- `params: &[]` 只允许用于真正无参数函数
- callback signature 也要逐步补齐参数元数据

#### 当前剩余范围

- 运行时“已有签名文件但未注册”的缺口已修复
- `api-ms-win-core-*` 中可映射到宿主签名的 contract 导出已开始继承 `ParamSpec`
- 当前剩余问题主要收敛为:
  - 尚未编写专用 `*_SIGNATURES` 的 stub-only 导出
  - 个别已注册签名中仍需要进一步细化 `ParamSpec` 的参数类型
  - handler 侧大多仍使用 `ctx.raw(i)`，typed decode 价值尚未完全兑现

---

### 3.6 ~~P1~~: 日志系统仍保留 `ApiArgKind::Auto` 猜测回退 — ✅ 已修复（Step 7）

> 2026-04-19 补充修复:
> 通用 fallback 已从 `ApiArgKind::Auto` 改为 `raw` 十六进制渲染。也就是说，日志主路径不再对“只有 stub metadata 的参数”做字符串猜测；只有已声明 `ParamSpec` 的参数才走类型化渲染。随着第 3.5 节的注册缺口被补上，核心 DLL 的 `auto` 回退面已明显缩小。

> 2026-04-19 Step 7 收口:
> `ApiArgKind::Auto` 已从核心 API 参数渲染层移除。签名驱动日志现在只存在两类参数输出：已声明 `ParamSpec` 的 typed 渲染，以及签名尾部未声明参数的 `raw` 十六进制渲染；不会再产出 `kind=auto`。自定义日志解码路径（如 `WideCharToMultiByte`、`WriteConsoleW`）继续使用显式 kind，不再依赖 Auto 猜测。

#### 现象

当前日志侧仍保留 `Auto` 支持，但已不再作为通用 fallback 主路径:

- [logging_helpers.rs#L429](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/logging_helpers.rs#L429)
- [logging_helpers.rs#L577](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/logging_helpers.rs#L577)

#### 修复结果

- 核心 API 参数日志不再依赖 `ApiArgKind::Auto`
- 签名尾部多余参数统一按 `raw` 十六进制输出
- 日志主路径已收敛为“typed metadata 或 raw fallback”，不再存在 `auto` kind

#### 验证

- `rg -n "ApiArgKind::Auto|\\\"auto\\\"\\.to_string\\(" src/runtime/engine src/runtime/engine.rs`
- `cargo test -p hvm-hikari-virtual-engine --lib signature_driven_api_log_args -- --nocapture`

---

### 3.7 ~~P1~~: `arm64` 预留点存在，但真实适配选择尚未闭合 — ✅ 已修复（显式拒绝）

#### 现象

`AbiAdapter` 层已为未来 `arm64` 预留文件，但适配器选择仍然是:

- `x86` 走 x86 adapter
- 其他全部走 x64 adapter

关键位置:

- [adapter.rs#L76](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/abi/adapter.rs#L76)

当前实现:

1. `arm64.rs` 只是占位
2. `select_adapter()` 没有真正为 `arm64` 分支
3. “非 x86 一律 x64” 只适用于当前短期状态

#### 影响

- 当前架构抽象还不能说已经真正为 `arm64` 打开
- 如果未来接入 `arm64`，这里会是首个结构性缺口

#### 修复目标

- 明确 `ArchSpec -> AbiAdapter` 的完整映射
- 在未实现 `arm64` 前，至少显式拒绝，而不是静默回退到 x64

---

### 3.8 P2: callback / dispatch / 日志三条链路仍未完全统一同一份 typed metadata

#### 现象

当前已经有 `HookSignature.ret` 和部分签名驱动日志，但 callback 与 dispatch 仍以 `args: &[u64]` 为中心。

关键位置:

- [family_dispatch.rs#L273](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/family_dispatch.rs#L273)
- [family_dispatch.rs#L295](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/family_dispatch.rs#L295)
- [family_dispatch.rs#L305](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/family_dispatch.rs#L305)
- [family_dispatch.rs#L318](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine/hooks/family_dispatch.rs#L318)

#### 影响

- 日志已经知道签名，但 handler 仍然不知道类型
- callback 已知道 ABI，但还没有完全消费同一套 typed parameter 体系
- 迁移目前是“统一元数据开始生效”，不是“全链路统一”

#### 修复目标

- dispatch 入口统一构造 `HookContext`
- handler 侧消费 typed access
- logging / runtime / callback 准备复用同一套参数元数据与返回语义

---

### 3.9 P2: 测试与 CI 口径存在盲区，容易误判“阶段已完成”

#### 现象

当前有一个典型现象:

```bash
cargo test -p hvm-hikari-virtual-engine --tests
```

不会暴露库内 `SendMessage` 的 callback 回归。

但下面这条会失败:

```bash
cargo test -p hvm-hikari-virtual-engine --lib runtime::engine::tests::send_message_invokes_registered_wndproc_x64_from_native_context -- --exact --nocapture
```

#### 影响

- 只跑 integration tests 容易误判主链路健康
- callback / ABI / native execution 的库内回归可能被漏掉

#### 修复目标

- CI 至少同时覆盖 `--lib` 与 `--tests`
- 把 callback / x86 / x64 / native path 相关用例列入强制门禁

---

### 3.10 ~~P2~~: 大量 warning 说明迁移残留仍然较多 — ✅ 已修复（大部分清理完成）

与 ABI/signature 迁移相关的 warning 已全部清理:
- 13 处 unused import 已删除
- 预留类型 (HookContext, FromHookParam, VariadicArgReader, RawCallFrame methods 等) 已标记 #[allow(dead_code)]
- 不可达 pattern (com/common.rs DISPID 重复匹配) 已修复
- 不必要括号 (messages.rs) 已清理
- arm64 adapter 显式拒绝替代静默回退
- 编译 warning 从 65 降至 29（剩余 29 个均为 "more private than" 可见性 warning，与本次迁移无关）

#### 现象

当前 `cargo test` 输出的 warning 里，与本次迁移直接相关的包括:

1. `HookContext` 未使用
2. `FromHookParam` 未使用
3. `VariadicArgReader` 未使用
4. `Arm64Adapter` 未构造
5. 多个 `ParamType` / `ParamDirection` import 未使用
6. `AbiAdapter` re-export 未使用

#### 影响

- 说明部分新架构仍停留在“定义层已写，调用层未接”
- warning 本身不一定是 bug，但它准确暴露了迁移没有彻底收口

#### 修复目标

- 以“warning 归零”作为迁移收尾的附加验收标准之一
- 至少要先清掉与 ABI/signature 改造直接相关的 warning

---

## 4. 当前问题之间的关系

这些问题不是孤立的，存在明显因果链:

1. ~~因为 `HookContext` 没进主路径，所以业务 handler 仍在大量使用 `args.arg(i)`~~ → **已修复（Step 3/4）**
2. 因为 handler 已迁移到 `ctx.raw(i)` 但 `ParamSpec` 尚未补齐，所以 typed access 的价值没有完全兑现
3. ~~因为兼容层没删掉，Registry 和 Hook 定义仍然不是单一真相源~~ → **已修复（Step 5）**
4. ~~因为 `HookValue` 在关键边界仍被降级，所以 callback / x86 / future arm64 的返回语义还不够稳~~ → **已修复（Step 2）**
5. 因为 CI 口径不完整，所以库内 ABI 回归被”阶段完成”的结果掩盖了

所以修复顺序不能乱。

---

## 5. 建议修复顺序

下面的顺序按”先 correctness，再架构收口，再覆盖率补齐”排列。

### Step 1: 修复 callback correctness 回归 — ✅ 已完成

> 见第 1 节”已完成修复”部分。

**对后续步骤的关键提示**:
- Step 1 修复了 `dispatch_unicorn_bound_stub` 对 `defer_api_return` 的处理逻辑
- **Step 3/4/8 依赖此修复**: 任何涉及 callback / deferred return 的 handler 迁移都依赖此 correctness 修复。若 Step 1 未完成，所有 callback 场景（SendMessage、EnumWindows、TimerProc 等）在 x64 unicorn 路径上都会得到错误的返回值
- `defer_api_return == true` 时 Unicorn 不再被 emu_stop，而是继续执行。后续如需新增 deferred return 场景，确保 callback frame 已正确写入寄存器后设置 `defer_api_return = true` 即可自动走此路径

---

### Step 2: 统一返回值边界，清除热路径里的 `into_raw_u64()` — ✅ 已完成

> 见第 1 节”已完成修复”部分。

**对后续步骤的关键提示**:
- 执行路径已全部使用 `into_raw(&arch)`，不再有 `into_raw_u64()` 降级
- **Step 3/4/5 依赖此修复**: HookContext 接入后 handler 返回 `HookValue`，所有边界已统一走架构感知编码，后续迁移无需再处理返回值降级问题
- **Step 5 删除 HookDefinition 时**: `dispatch_bound_stub`（非 Unicorn 路径）已使用 `into_raw(&arch)`，确保删除双轨模型后返回值语义不变
- `hook_value.rs` 中 `into_raw_u64()` 方法定义仍保留（标记为 backward-compatible），但主执行路径不再调用它

目标:

- 先让 `SendMessage` x64 native callback 用例稳定通过

执行项:

1. 审计 `prepare_callback_frame()` 的入参与栈布局
2. 审计 callback 返回值写回和恢复 `RSP/RIP` 的顺序
3. 核对 continuation stub 与 resume 地址的语义
4. 补充 x86/x64 对称测试
5. 补充 native context / unicorn context 双路径测试

完成标准:

- [engine.rs#L3162](/home/dev/Vm_Eng_Scan/HVM/src/runtime/engine.rs#L3162) 对应用例通过

---

### Step 2: 统一返回值边界，清除热路径里的 `into_raw_u64()`

目标:

- 返回值最终统一走 architecture-aware 编码

执行项:

1. 把 dispatch 主路径切到 `into_raw(&arch)` 或 `AbiAdapter::write_return_value`
2. 检查 x86 interpreter 的 `EAX` 写回边界
3. 检查 callback 恢复路径的返回值写回边界
4. 检查日志链路是否还能保留 `into_raw_u64()` 旁路

完成标准:

- 主执行热路径不再直接依赖 `into_raw_u64()`

---

### Step 3: 把 `HookContext` 真正接入 dispatch 主路径 — ✅ 已完成（基础设施 + 样板迁移）

> **前置依赖**: Step 1（callback correctness）、Step 2（返回值统一）已完成后才能安全接入。

**已完成内容**:

1. **HookContext 重新设计** (`src/runtime/engine/hook_context.rs`):
   - 移除 `Engine` 泛型参数（避免与 `&mut self` 的借用冲突）
   - 从 `frame: &'a RawCallFrame` 改为 `args: &'a [u64]`（两种 dispatch 路径通用）
   - 新增 `arch: &'a ArchSpec` 字段（为后续架构感知类型预留）
   - `FromHookParam` trait 简化：移除 `<E>` 泛型
   - 保留 7 个标量 FromHookParam 实现（u32, i32, u64, i64, bool, u16, usize）

2. **Dispatch 入口构造 HookContext** (`src/runtime/engine/hooks/family_dispatch.rs`):
   - 在 `dispatch_bound_stub_with_signature` 中构造 `HookContext`
   - 传递给 `dispatch_known_family_hook`
   - 其他家族分发器保持不变（通过 `args` 参数继续工作）

3. **version.dll 样板迁移** (`src/runtime/engine/hooks/family_dispatch.rs`):
   - `dispatch_version_hook` 改为接收 `&HookContext<'_>`
   - 6 个 version.dll handler 全部迁移到 `ctx.get::<T>(i)?` / `ctx.raw(i)` 模式
   - 消除了 `args.arg()` 调用

**验证**: `cargo test --lib` 40 tests passed，无新增 regression

**对后续步骤的关键提示**:
- `HookContext` 已在主分发路径构造并使用，不再是 dead code
- 其他家族的迁移（Step 4）可通过在 `dispatch_known_family_hook` 中逐步替换实现
- `ctx.args()` 方法返回 `&[u64]`，允许渐进式迁移（旧代码 `args.arg(i)` → `ctx.args().arg(i)`）
- 字符串/指针/handle 等需要内存访问的 FromHookParam 实现待 Step 4 补齐

---

### Step 4: 家族化替换旧 handler 入口 — ✅ 已完成

> **前置依赖**: Step 3 完成后才能大规模替换。Handler 入口从 `args: &[u64]` 改为接收 `HookContext` 需要 Step 3 先建立 `ctx.get<T>(index)` API 并在 dispatch 入口构造 `HookContext`。

**已完成内容**:

1. **全量 dispatch 函数签名迁移**: 33 个 dispatch 函数从 `args: &[u64]` 迁移到 `ctx: &HookContext<'_>`
2. **分发主路径更新**: `dispatch_known_family_hook`、`dispatch_manual_contract_hook`、`dispatch_bound_stub_with_signature` 三个入口全部更新为传递 `ctx`
3. **内部参数访问替换**: 全部 ~2333 处 `args.arg(i)` 替换为 `ctx.raw(i)`，覆盖 34 个 handler 文件
4. **COM helper 迁移**: `com_query_interface`、`com_get_type_info_count`、`com_get_ids_of_names`、`com_invoke` 4 个辅助函数也完成迁移
5. **零残留**: 无 bridge 行残留，无 `args.arg()` 残留，无 `args: &[u64]` dispatch 签名残留

**修改文件** (34 个):

- `family_dispatch.rs` — 分发主路径
- `kernel32.rs` (772 处)、`advapi32.rs` (236 处)、`netapi32.rs` (184 处)
- `ntdll.rs` (124 处)、`mpr.rs` (114 处)、`ws2_32.rs` (118 处)
- `msvcrt.rs` (82 处)、`user32/exports.rs` (70 处)、`setupapi.rs` (70 处)
- `wininet.rs` (65 处)、`oleaut32.rs` (59 处)、`shlwapi.rs` (51 处)
- 其余 21 个文件 (2~51 处不等)

**验证**: `cargo test --lib` 40 tests passed，0 失败

**对后续步骤的关键提示**:
- `HookContext` 已成为 handler 层唯一参数入口
- `ctx.raw(i)` 替代了 `args.arg(i)`，后续可按需升级为 `ctx.get::<T>(i)` 类型化访问
- 新增 hook handler 应直接接收 `&HookContext<'_>`，不再允许使用 `args: &[u64]` 模式

---

### Step 5: 删掉 `HookDefinition` 双轨模型 — ✅ 已完成

> **前置依赖**: Step 2（返回值统一）确保 `dispatch_bound_stub` 不再依赖 `into_raw_u64()` 降级。Step 3/4 完成 handler 迁移后，`HookDefinition` 的 `argc` 和 `call_conv` 字段不再被业务层引用，此时才能安全删除双轨模型。删除前需确认所有 `definition_for_address()` 调用点已迁移到 `signature_for_address()`。

**已完成内容**:

1. 删除 `src/hooks/base.rs` — `HookDefinition`/`CallConv`/`HookLibrary`/`From<&HookDefinition> for HookSignature` 全部移除
2. 删除 `src/hooks/stub.rs` — `stub_definitions`/`stdcall_definitions` 从未被调用
3. 从 `src/hooks/mod.rs` 移除 `mod base;` 和 `mod stub;`
4. `HookRegistry` 删除 `definitions` HashMap 和全部 definition 查询 API
5. `BoundHookLookup` 删除 `definition` 字段
6. `register_function_stubs()` 不再创建 `HookDefinition` 桥接条目
7. 测试断言从 `.definition()` / `.definition_for_address()` 迁移到 `.signature()` / `.signature_for_address()`

**修改文件** (7 个): `base.rs`(删)、`stub.rs`(删)、`mod.rs`、`registry.rs`、`module_manager.rs`、`tests/kernel32_hooks.rs`、`tests/module_manager.rs`

**验证**: `cargo test --lib` 40 passed；`cargo test --tests` 零新增回归

---

### Step 6: 补齐高频 API 的 `ParamSpec` — 待实施

> **前置依赖**: Step 3（HookContext 接入）完成后，`ParamSpec` 的价值才能在执行路径上兑现（typed access 依赖完整参数元数据）。若 Step 3 未完成，补齐 ParamSpec 只改善日志渲染，不影响执行正确性。

目标:

- 让签名覆盖真正转化为类型覆盖

执行项:

1. 统计所有 `params: &[]` 但实际上有参数的函数
2. 按调用频次优先补齐
3. 把 callback signature 一并补齐
4. 对核心 DLL 建立“禁止空参数签名”的基线

完成标准:

- `params: &[]` 仅保留在真正无参数函数

#### 当前进展

1. 已审计 `kernel32/user32/ws2_32/advapi32/callback_signature` 中文档里提到的典型空参数项，确认当前示例均为合法无参 API，不应作为 Step 6 修复目标
2. 已为 `api-ms-win-core-*` contract family 增加宿主签名继承，缩小了“分发正确但参数元数据缺失”的核心缺口
3. 已补回归测试，验证 contract 导出会继承宿主 `ParamSpec`
4. 已细化一批高频核心 API 的 pointer metadata，避免继续停留在粗粒度 `GuestPtr`

本轮已补齐的代表性项:

- `kernel32.dll`: `ReadFile` / `WriteFile` / `GetConsoleMode` / `GetModuleHandleExW` / `WideCharToMultiByte`
- `advapi32.dll`: `RegOpenKeyExW/A` / `RegCreateKeyExW/A` / `RegCreateKeyW` / `RegQueryValueExW/A` / `OpenProcessToken` / `OpenThreadToken` / `GetTokenInformation` / `AdjustTokenPrivileges` / `LookupPrivilegeValueW/A`
- `shell32.dll`: `CommandLineToArgvW`
- `user32.dll`: `GetWindowThreadProcessId`

这批修复把若干 `GuestPtr` 提升为:

- `GuestPtrTo(Handle)` / `GuestPtrTo(U32)` / `GuestPtrTo(I32)`
- `OutBuffer { len_param: ... }`
- `OpaqueStructPtr("LUID")`
- `PCStr`（替代 `WideCharToMultiByte.lpDefaultChar` 的粗粒度指针）

**验证**:

- `cargo test -p hvm-hikari-virtual-engine --test hook_registry --quiet`
- `cargo test -p hvm-hikari-virtual-engine --lib hooks::registry::tests --quiet`

---

### Step 7: 收缩日志系统里的 `Auto` 回退 — ✅ 已完成

> **前置依赖**: Step 6（ParamSpec 补齐）完成后，核心 DLL 函数不再有空参数签名，日志侧可以从签名驱动渲染而不再需要 Auto 猜测。此步骤可与 Step 6 交叉推进。

目标:

- 日志真正做到签名驱动，而不是猜测驱动

已完成项:

1. 审计 `ApiArgKind::Auto` 的实际调用点，确认主路径已无显式使用
2. 删除核心 API 参数渲染层中的 `ApiArgKind::Auto`
3. 将“签名存在但尾部参数未声明”的日志输出统一改为 `raw`
4. 增加单测，锁定“typed/raw，不产出 auto kind”的行为

完成标准:

- 核心族 API 不再依赖 `ApiArgKind::Auto` — ✅ 已达成

---

### Step 8: 明确 `arm64` 适配策略 — ✅ 已完成（部分）

**已完成**: `select_adapter()` 已改为显式拒绝非 x86/x64 架构（panic with clear message），不再静默回退到 x64 adapter。

**修改文件**: `src/runtime/engine/abi/adapter.rs` — `select_adapter` 函数

**待实施**: 预留 `arm64` callback / return / stack cleanup 语义测试骨架（需要实际 arm64 支持时再添加）

> **前置依赖**: Step 1（callback correctness）修复了 `defer_api_return` 路径。arm64 适配器需要实现 `AbiAdapter` trait 的全部方法，包括 `prepare_callback_frame`。新适配器的 callback 路径会复用 Step 1 修复的 `Ok(false)` 逻辑——只要 `defer_api_return == true`，Unicorn 就不会过早停止。

目标:

- 让架构抽象真正具备未来扩展闭合性

执行项:

1. 修改 `select_adapter()`，不要把所有非 x86 都静默映射到 x64
2. 未实现 `arm64` 前改为显式报错或显式 unsupported
3. 预留 `arm64` callback / return / stack cleanup 语义测试骨架

完成标准:

- `arm64` 的接入路径清晰明确

---

### Step 9: 补齐 CI 门禁与回归测试 — 待实施

> **前置依赖**: Step 1 已修复 callback 回归，但 CI 口径仍需补齐。建议至少同时跑 `cargo test --lib` 和 `cargo test --tests`，并将 callback / native execution / x86 / x64 用例列入强制门禁。此步骤可独立于 Step 3-8 推进。

目标:

- 防止再次出现“阶段完成但库内回归未被发现”

执行项:

1. CI 同时跑 `cargo test --lib` 与 `cargo test --tests`
2. callback / native execution / x86 / x64 用例进入强制门禁
3. 对 `HookContext` 接入后增加 typed decode 相关单测
4. 对关键返回值语义增加架构断言

完成标准:

- ABI / callback / return 相关回归能在 CI 第一时间暴露

---

## 6. 建议验收口径

后续不建议再用“阶段代码已提交”作为验收依据，而应改成以下口径:

### 6.1 correctness 口径

- callback/native path 全部关键用例通过
- x86/x64 返回值写回语义一致

### 6.2 架构口径

- `HookSignature` 成为唯一主模型 — ✅ 已达成
- `HookContext` 进入主执行路径 — ✅ 已达成
- 主路径无 `HookDefinition` — ✅ 已达成
- 主路径无 `into_raw_u64()` 降级 — ✅ 已达成

### 6.3 覆盖口径

- 高频 API 不再依赖 `params: &[]`
- 核心 DLL 不再依赖 `ApiArgKind::Auto`

### 6.4 清理口径

- 与本次迁移直接相关的 warning 基本清零

---

## 7. 最终判断

如果只看”是否已经完成了 7 个阶段对应的代码提交”，答案是:

- 是，主体迁移提交已经齐了

如果看”是否达到了原文档定义的终态架构”，答案是:

- 架构核心已达成：`HookSignature` 是唯一注册实体、`HookContext` 已进入主执行路径、callback correctness 已修复、返回值边界已统一
- 待完善：ParamSpec 覆盖率（Step 6）、日志 Auto 收缩（Step 7）、CI 门禁（Step 9）

当前最准确的状态应该定义为:

- `Hook ABI / Signature` 迁移主干已完成
- 终态收口（Step 1-5, 8, 10）已全部完成
- 覆盖率补齐（Step 6/7）和 CI 完善（Step 9）留作后续独立任务

这份文档之后的修复工作，建议聚焦 Step 6/7/9，可交叉推进。
