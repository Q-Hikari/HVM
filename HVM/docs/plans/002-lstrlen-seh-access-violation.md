# Plan: API Hook 无效地址 SEH 异常注入

## 修复目的

### 问题描述

A0044620 样本在 HVM 中执行时，经过两轮自解密后调用 `lstrlenA(0x901BF017)`，
该地址指向未映射的内存。HVM 的 `lstrlenA` hook 静默返回 0，导致后续
`GetProcAddress(ws2_32, 0x901BF017)` 失败，执行流程彻底偏离真实行为。

### 根因分析

样本在 `VirtualAlloc` 区域（偏移 0xB80BC）存储了 WS2_32 的序号导入项，格式为：

```
VirtualAlloc_base | IMAGE_ORDINAL_FLAG(0x80000000) | ordinal
```

在 HVM 中该值 = `0x101BF000 + 0x80000017 = 0x901BF017`。
低 16 位的 `0x17 = 23` 正是 WS2_32 的序号之一。

样本利用 **SEH 异常机制** 来区分字符串导入与序号导入：
1. 对所有函数表项调用 `lstrlenA`
2. 字符串导入（合法地址）→ lstrlenA 成功 → 正常解析
3. 序号导入（内核空间地址 ≥ 0x80000000）→ ACCESS_VIOLATION → SEH handler 捕获 → 跳过或提取序号

**HVM 的问题**：`lstrlenA` hook（kernel32.rs:1845-1851）调用
`read_c_string_bytes_from_memory`，当遇到未映射地址时返回 `Err`，
hook 用 `unwrap_or(0)` 静默返回 0，**不触发任何异常**。
样本的 SEH handler 永远不会被调用，导致代码路径分歧。

### 影响范围

所有通过 hook 实现的字符串 API 都存在同样的问题：
`lstrlenA`, `lstrlenW`, `lstrcpyA`, `lstrcmpA`, `lstrcmpiA`,
`lstrcatA`, `lstrcpynA`, `CharUpperA`, `CharLowerA` 等。
任何样本利用 SEH 处理无效指针的场景都会受影响。

---

## 修复方案

### 核心思路

当 hook 中的字符串读取函数遇到无效/未映射地址时，**构造合成的
STATUS_ACCESS_VIOLATION 并注入到 guest 的 SEH 分发链**，
复用已有的 `dispatch_x86_seh_fault_with_unicorn` 机制。

### 已有基础设施

HVM 已有完整的 x86 SEH 支持（`seh.rs`）：
- `handle_pending_unicorn_fault` → VEH → SEH → TopLevelFilter 完整分发链
- `dispatch_x86_seh_fault_with_unicorn` 遍历 FS:[0] SEH 链并调用 handler
- `pending_x86_seh_unwind` 处理 RtlUnwind 栈展开
- `force_native_return` + `pending_context_restore` 控制 hook 返回后的执行流重定向

### 实现步骤

#### Step 1: 新增辅助方法 `inject_access_violation_for_hook`

在 `seh.rs` 中新增方法：

```rust
/// 为 hook 中的无效内存访问注入合成 STATUS_ACCESS_VIOLATION。
/// 调用前：guest 刚刚调用了一个字符串 API hook（如 lstrlenA），
///         参数中包含一个无法读取的地址。
/// 调用后：如果 SEH handler 处理了异常，返回 Ok(true)，此时
///         Unicorn 寄存器已被修改为 handler 的继续执行点，
///         调用方应通过 force_native_return 跳过正常 hook 返回。
///         如果未处理，返回 Ok(false)，调用方应回退到默认行为。
pub(in crate::runtime::engine) fn inject_access_violation_for_hook(
    &mut self,
    fault_address: u64,   // 触发异常的无效地址
    fault_pc: u64,        // hook 函数的入口地址（作为"故障"指令地址）
) -> Result<bool, VmError>
```

实现逻辑：
1. 获取当前 Unicorn (api, uc) 上下文
2. 构造 `UnicornFault`：
   ```rust
   UnicornFault {
       pc: fault_pc,              // hook 函数地址
       address: fault_address,     // 无效地址
       size: 1,
       access: UnicornFaultAccess::Read,
       exception_code: Some(STATUS_ACCESS_VIOLATION),
       exception_information: [0, fault_address],  // [read, fault_addr]
       exception_information_count: 2,
   }
   ```
3. 按 `handle_pending_unicorn_fault` 的顺序依次尝试：
   a. VEH handler (`dispatch_x86_vectored_exception_handlers_with_unicorn`)
   b. SEH chain (`dispatch_x86_seh_fault_with_unicorn`)
   c. Top-level filter (`dispatch_x86_top_level_exception_filter_with_unicorn`)
4. 如果任一阶段处理了异常 → 返回 `Ok(true)`
5. 全部未处理 → 恢复原始寄存器状态，返回 `Ok(false)`

#### Step 2: 修改 `lstrlenA` hook

在 `kernel32.rs` 的 `lstrlenA` hook 中：

```rust
("kernel32.dll", "lstrlenA") => {
    if ctx.raw(0) == 0 {
        Ok(0)
    } else {
        let addr = ctx.raw(0);
        let result = self.read_c_string_bytes_from_memory(addr);
        match result {
            Ok(bytes) => Ok(bytes.len() as u64),
            Err(_) => {
                // 地址不可读 —— 注入 ACCESS_VIOLATION 到 SEH 链
                let hook_pc = ctx.pc();  // lstrlenA hook 地址
                let handled = self.inject_access_violation_for_hook(addr, hook_pc)?;
                if handled {
                    // SEH handler 已接管，跳过正常 hook 返回
                    self.dispatch.force_native_return = true;
                    return Ok(0);  // 返回值不会被使用
                }
                // 未被 SEH 处理，回退到静默返回 0
                Ok(0)
            }
        }
    }
}
```

关键点：`force_native_return = true` 使得 hook 返回后不执行正常的
"恢复 EAX 并跳转到 return_to" 逻辑，而是保持 SEH dispatch 设置的寄存器状态。

#### Step 3: 推广到其他受影响的字符串 API

对以下 hook 做同样的"无效地址 → 注入异常"处理：

| 函数 | 当前行为 | 修复后行为 |
|------|---------|-----------|
| `lstrlenA` | unwrap_or(0) | 注入 AV |
| `lstrlenW` | unwrap_or(0) | 注入 AV |
| `lstrcpyA` | 静默失败 | 注入 AV |
| `lstrcmpA` / `lstrcmpiA` | 静默返回 0 | 注入 AV |
| `lstrcatA` | 静默失败 | 注入 AV |
| `lstrcpynA` | 静默失败 | 注入 AV |
| `CharUpperA` / `CharLowerA` | 静默返回原值 | 注入 AV |

可以抽取一个通用 helper：

```rust
/// 尝试从 guest 内存读取 C 字符串。如果地址不可读，
/// 注入 ACCESS_VIOLATION 到 SEH 链。
/// 返回：
///   Ok(Some(bytes)) - 读取成功
///   Ok(None)        - SEH handler 处理了异常（调用方应设置 force_native_return）
///   Err(VmError)    - 地址无效且 SEH 未处理（调用方可回退到默认行为）
fn read_c_string_or_inject_fault(
    &mut self,
    addr: u64,
    hook_pc: u64,
) -> Result<Option<Vec<u8>>, VmError>
```

#### Step 4: 处理 `read_c_string_bytes_from_memory` 的地址校验

当前 `read_c_string_bytes_from_memory`（guest_memory.rs:108）在找不到内存区域时
返回 `MemoryError::MissingRegion`。这是检测无效地址的正确入口。

不需要修改此函数本身，而是在调用方（hook handler）中处理 `Err` 分支。

---

## 修复后怎么测试

### 测试 1: A0044620 样本回归测试

**目标**：验证 A0044620 在修复后能正确执行过 WS2_32 序号导入点。

**步骤**：
1. 使用现有配置 `configs/sample_a0044620_1b.json` 运行 HVM
2. 检查 API log 中 WS2_32.dll 加载后的行为：
   - **修复前**：`lstrlenA(0x901BF017)` → 返回 0 → `GetProcAddress(ws2_32, 0x901BF017)` → 失败
   - **修复后**：`lstrlenA` 触发 SEH → handler 处理 → 代码继续到第二阶段 API 解析
3. 验证修复后出现的 API 序列应与实际 trace 匹配：
   ```
   LoadLibraryExA("WS2_32.dll") → lstrlenA 触发 SEH → LoadLibraryA("KERNEL32.DLL") → ...
   ```
4. 对比 HVM 输出与 `Sample/xtrace.A0044620.exe.3180.log` 的 API 序列

**验证点**：
- [ ] WS2_32.dll 加载后不再出现 `GetProcAddress(ws2_32, 0x901BF017)`
- [ ] 后续出现 `LoadLibraryA("KERNEL32.DLL")`（从解密区域调用）
- [ ] 第二阶段的 API 解析（ReadFile, GetFileSize, ...）正常执行
- [ ] 最终到达 `VirtualProtect` + `WSAStartup` 阶段

### 测试 2: SEH 异常注入日志验证

**目标**：确认 SEH dispatch 被正确触发。

**步骤**：
1. 在 `inject_access_violation_for_hook` 中添加 `log_runtime_event` 日志
2. 运行 A0044620 样本
3. 检查 console log 或 JSONL 中出现：
   - `SEH_FAULT_INJECT` 事件（fault_address=0x901BF017）
   - 后续的 `SEH_HANDLER` 事件（disposition=0 或 1）
   - 可能的 `SEH_RESUME` 事件（如果 handler 返回 EXCEPTION_CONTINUE_EXECUTION）

**验证点**：
- [ ] 日志中出现合成异常注入记录
- [ ] SEH handler 返回了有效 disposition
- [ ] 执行在 handler 指定的位置继续

### 测试 3: 无效地址场景单元验证

构建简短测试用例：

1. **lstrlenA(NULL)**：应返回 0（不注入异常，NULL 是特殊情况）
2. **lstrlenA(0x00000001)**：低地址 → 注入 AV → SEH 处理
3. **lstrlenA(0xDEADBEEF)**：明显无效地址 → 注入 AV → SEH 处理
4. **lstrlenA(valid_ptr)**：正常字符串 → 正常返回长度

### 测试 4: 其他样本回归

确保修复不影响其他已有样本的正常执行：
- 之前能正常运行的 APT-C-06 等样本
- `lstrlenA` 对合法字符串地址的行为不变

---

## 风险评估

### 低风险
- SEH 机制已有完整实现，只需在 hook 层正确桥接
- `force_native_return` 已在多个地方使用（RtlUnwind、回调等），模式成熟
- 修改范围局限在 hook handler 层，不触及核心引擎

### 需注意
- **无限递归**：SEH handler 中可能再次调用 lstrlenA，需要递归保护
  - 解决方案：设置 `dispatching_synthetic_fault` 标志，防止嵌套注入
- **寄存器状态一致性**：注入异常时需要正确保存和恢复 guest 寄存器
  - 解决方案：在注入前 `capture_unicorn_thread_registers`，未处理时 `restore_unicorn_thread_registers`
- **x64 架构**：当前样本是 x86，但 x64 也应考虑
  - 解决方案：`inject_access_violation_for_hook` 内部根据 `core.arch` 分派到对应的 dispatch 函数

---

## 实现优先级

1. **P0**：`inject_access_violation_for_hook` + `lstrlenA` 修复
2. **P1**：`lstrlenW` 修复
3. **P2**：其他字符串 API 修复（lstrcpyA, lstrcmpiA 等）
4. **P3**：递归保护 + x64 支持

预计改动文件：
- `HVM/src/runtime/engine/shared/seh.rs`（新增 inject 方法）
- `HVM/src/runtime/engine/hooks/core/kernel32.rs`（修改 lstrlenA/W 等 hook）
