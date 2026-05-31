# P2-5: VirtualExecutionEngine 子系统拆分方案

> 状态: 草案  
> 日期: 2026-04-10  
> 目标: 将 3900 行 engine.rs 拆分为按功能组织的子系统，提升可维护性

---

## 1. 现状分析

### 1.1 engine.rs 当前规模

| 区域 | 行数 | 说明 |
|------|------|------|
| 辅助 struct/enum 定义 | ~300 行 (299-648) | FileHandleState, MutexState 等 20+ 个结构体 |
| `VirtualExecutionEngine` struct 定义 | ~115 行 (649-764) | 113 个字段 |
| `new()` 构造 + `load()` 加载 + `run()` 入口 | ~500 行 (766-1180) | 核心生命周期 |
| 公共访问器 (getters) | ~100 行 (1189-1316) | `pub fn modules()` 等 |
| 调度/执行逻辑 | ~400 行 (1317-1777) | dispatch_bound_stub, run_scheduler_loop |
| 运行主循环 | ~300 行 (1778-2160) | unicorn/interpreter/native 调度 |
| 内联单元测试 | ~500 行 (2178-2640) | `#[cfg(test)] mod tests` |
| Unicorn 回调 + 原生追踪 | ~1300 行 (2643-3893) | UnicornFault, NativeTraceState, 外部 "C" 回调 |
| render_run_summary | ~110 行 (3897-3909) | 输出格式化 |

### 1.2 子模块规模

`engine/` 目录共 **40039 行**，分布如下:

| 子模块 | 行数 | 说明 |
|--------|------|------|
| hooks/core/kernel32.rs | 3993 | 最大单个 hook 文件 |
| hooks/network/netapi32.rs | 4964 | 网络管理 hook |
| shared/system/filesystem.rs | 1802 | 文件系统模拟 |
| shared/seh.rs | 1894 | SEH 异常处理 |
| shared/system/processes.rs | 1759 | 进程管理 |
| shared/guest_memory.rs | 1191 | 虚拟内存读写 |
| hooks/ (其他 30+ 个文件) | ~8000 | 各 DLL hook |
| 其他 helper 文件 | ~5500 | unicorn/x86/lifecycle 等 |

### 1.3 核心问题

1. **`use super::*` 泛滥**: 所有 `impl VirtualExecutionEngine` 块通过 `use super::*` 访问 engine.rs 的全部定义，子系统边界完全不存在
2. **113 个字段平铺在单个 struct 中**: 无法从结构上理解哪些字段属于哪个功能域
3. **跨模块访问无约束**: kernel32.rs 可以直接访问 `user32_state`、网络 hook 可以直接操作 `mutex_states`，任何模块可以读写任何状态
4. **编译时间长**: engine.rs 的任何改动都迫使所有 hook 文件重编译

---

## 2. 拆分策略

### 2.1 设计原则

1. **按功能域分组字段为子结构体**: 将 113 个字段归类到 ~10 个子系统 struct
2. **渐进式迁移**: 每次只迁移一个子系统，每步都可编译+通过测试
3. **保持 `use super::*` 兼容**: 不改变现有 hook 代码的编译方式，仅在 engine.rs 中重新组织字段
4. **不引入 trait 抽象**: 避免过度设计，直接在子结构体上 `impl` 方法

### 2.2 子系统划分

根据字段功能域和访问模式，将字段分为以下子系统:

#### A. `EngineCore` — 引擎核心状态 (不可拆分的基础字段)

```rust
#[derive(Debug)]
pub(super) struct EngineCore {
    pub arch: &'static ArchSpec,
    pub config: EngineConfig,
    pub environment_profile: EnvironmentProfile,
    pub hooks: HookRegistry,
    pub modules: ModuleManager,
    pub scheduler: ThreadScheduler,
    pub process_env: WindowsProcessEnvironment,
    pub processes: ProcessManager,
    pub registry: RegistryManager,
    pub api_logger: ApiLogger,
    pub runtime_profiler: RuntimeProfiler,
    pub api_call_counts: BTreeMap<String, u64>,

    // 运行控制
    pub loaded: bool,
    pub instruction_count: u64,
    pub exit_code: Option<u32>,
    pub stop_reason: Option<RunStopReason>,
    pub process_exit_requested: bool,
    pub startup_sequence_completed: bool,
    pub native_return_sentinel: u64,

    // 入口信息
    pub main_module: Option<ModuleRecord>,
    pub entry_module: Option<ModuleRecord>,
    pub parent_process: Option<SyntheticProcessIdentity>,
    pub entry_address: Option<u64>,
    pub entry_arguments: Vec<u64>,
    pub entry_invocation: EntryInvocation,
    pub entry_module_requires_attach: bool,
    pub command_line: String,
    pub dll_directory: Option<String>,
    pub current_directory: std::path::PathBuf,
    pub current_directory_host: std::path::PathBuf,
    pub environment_variables: BTreeMap<String, RuntimeEnvironmentVariable>,
    pub main_thread_tid: Option<u32>,
    pub last_error: u32,
}
```

**依据**: 这些字段被几乎所有模块访问，是引擎的基础设施。单独拆出无意义但需要与其他子系统区分。

#### B. `SyncState` — 同步原语 (mutex, semaphore)

```rust
#[derive(Debug, Default)]
pub(super) struct SyncState {
    pub mutex_handles: BTreeSet<u32>,
    pub mutex_handle_targets: HashMap<u32, u32>,
    pub mutex_states: HashMap<u32, MutexState>,
    pub named_mutexes: HashMap<String, u32>,
    pub semaphore_handles: BTreeSet<u32>,
    pub semaphore_handle_targets: HashMap<u32, u32>,
    pub semaphore_states: HashMap<u32, SemaphoreState>,
    pub named_semaphores: HashMap<String, u32>,
}
```

**访问者**: `shared/system/waits.rs`, `hooks/core/kernel32.rs` (CreateMutex, ReleaseMutex 等)  
**行数**: 34 处访问

#### C. `HandleState` — 文件/设备/查找句柄

```rust
#[derive(Debug)]
pub(super) struct HandleState {
    pub next_file_handle: u32,
    pub next_object_handle: u32,
    pub file_handles: HashMap<u32, FileHandleState>,
    pub find_handles: HashMap<u32, FindHandleState>,
    pub volume_find_handles: HashMap<u32, VolumeFindHandleState>,
    pub device_handles: HashMap<u32, DeviceHandleState>,
    pub io_completion_ports: HashMap<u32, VecDeque<IoCompletionPacket>>,
    pub setup_device_sets: HashMap<u32, SetupDeviceInfoSetState>,
    pub token_handles: BTreeSet<u32>,
    pub etw_trace_handles: BTreeSet<u32>,
}
```

**访问者**: `shared/system/filesystem.rs`, `hooks/core/kernel32.rs`, `hooks/device/`  
**行数**: 50+ 处访问

#### D. `ProcessMemoryState` — 虚拟内存 + 进程空间

```rust
#[derive(Debug)]
pub(super) struct ProcessMemoryState {
    pub virtual_allocations: BTreeMap<u64, VirtualAllocationRecord>,
    pub process_handles: HashMap<u32, u32>,
    pub process_spaces: HashMap<u64, SyntheticProcessSpace>,
    pub process_snapshots: HashMap<u32, ToolhelpProcessSnapshot>,
    pub file_mappings: FileMappingManager,
    pub heaps: HeapManager,
}
```

**访问者**: `shared/system/virtual_memory.rs`, `shared/system/processes.rs`, `shared/system/memory_mapping.rs`  
**行数**: 25+ 处访问

#### E. `SyncObjectsState` — 内核对象 + 模块跟踪

```rust
#[derive(Debug, Default)]
pub(super) struct SyncObjectsState {
    pub dynamic_library_refs: HashMap<u64, u32>,
    pub startup_pinned_modules: BTreeSet<u64>,
    pub attached_process_modules: BTreeSet<u64>,
    pub pending_thread_attach: BTreeSet<u32>,
    pub started_threads: BTreeSet<u32>,
    pub wts_server_handles: BTreeSet<u32>,
    pub global_atoms: HashMap<u16, String>,
    pub next_atom: u16,
    pub mounted_volumes: Vec<MountedVolume>,
}
```

**访问者**: `lifecycle_helpers.rs`, `hooks/core/kernel32.rs`, `hooks/core/ntdll.rs`

#### F. `NetworkState` — 网络子系统

```rust
#[derive(Debug)]
pub(super) struct NetworkState {
    pub network: NetworkManager,
    pub crypto: CryptoManager,
    pub http_response_rule_hits: BTreeMap<usize, u64>,
    pub inet_ntoa_buffer: Option<u64>,
}
```

**访问者**: `hooks/network/*`, `shared/network_*`  
**行数**: 集中在网络 hook 文件中

#### G. `UiState` — GUI / User32 子系统

```rust
#[derive(Debug)]
pub(super) struct UiState {
    pub user32_state: User32State,
    pub shell_imalloc: Option<u64>,
    pub pending_user32_timer_callbacks: Vec<PendingUser32TimerCallback>,
    pub pending_user32_sendmessage_callbacks: Vec<PendingUser32SendMessageCallback>,
}
```

**访问者**: `hooks/ui/user32/*` (84 处访问), `logging_helpers.rs`

#### H. `CrtState` — C 运行时子系统

```rust
#[derive(Debug)]
pub(super) struct CrtState {
    pub msvcrt_globals_base: Option<u64>,
    pub msvcrt_onexit_tables: HashMap<u64, MsvcrtOnExitTable>,
    pub msvcrt_rand_seed: u32,
    pub pending_msvcrt_initterm: Vec<PendingMsvcrtInitterm>,
}
```

**访问者**: `hooks/crt/*`

#### I. `ExceptionState` — SEH 异常处理

```rust
#[derive(Debug)]
pub(super) struct ExceptionState {
    pub top_level_exception_filter: u64,
    pub dispatching_top_level_exception_filter: bool,
    pub pending_x64_top_level_filter_seed: Option<RegisterFile>,
    pub x64_top_level_exception_filter_thunks: BTreeMap<u64, u64>,
    pub pending_context_restore: Option<PendingContextRestore>,
    pub pending_x86_seh_unwind: Option<PendingX86SehUnwind>,
}
```

**访问者**: `shared/seh.rs`, `x86_interpreter_helpers.rs`

#### J. `NativeTraceState` — 原生执行追踪

```rust
#[derive(Debug)]
pub(super) struct NativeTraceSubsystem {
    pub native_trace: NativeTraceState,
    pub memory_dump_sequence: u64,
    pub dynamic_code_activities: HashMap<(u64, u64), DynamicCodeRegionActivity>,
    pub image_hash_baselines: HashMap<(u64, u64), ImageHashBaseline>,
    pub remote_shellcode_threads: HashMap<u32, RemoteShellcodeThread>,
    pub active_x64_synthetic_call: Option<ActiveX64SyntheticCall>,
    pub pending_hash_bypass_return: Option<u64>,
    pub pending_hash_bypass_target: u32,
    pub diag_sample_base: Option<u64>,
    pub diag_block_count: u64,
    pub hash_loop_counter: u64,
    pub ntdll_exports_dumped: bool,
}
```

**访问者**: `unicorn_helpers.rs`, `memory_dump_helpers.rs`, Unicorn 回调

#### K. `UnicornState` — Unicorn 引擎状态

```rust
#[derive(Debug)]
pub(super) struct UnicornState {
    pub unicorn: Option<Box<UnicornApi>>,
    pub unicorn_handle: Option<*mut UcEngine>,
    pub unicorn_intr_hook_installed: bool,
    pub unicorn_block_hook_installed: bool,
    pub unicorn_code_hook_installed: bool,
    pub unicorn_mem_write_hook_installed: bool,
    pub unicorn_mem_prot_hook_installed: bool,
    pub unicorn_mem_unmapped_hook_installed: bool,
}
```

**访问者**: `unicorn_helpers.rs`, `native_unicorn_call_helpers.rs`, Unicorn 回调

#### L. `DispatchState` — 调度/执行临时状态

```rust
#[derive(Debug, Default)]
pub(super) struct DispatchState {
    pub defer_api_return: bool,
    pub thread_yield_requested: bool,
    pub force_native_return: bool,
    pub guid_rng: StdRng,
    pub tls: TlsManager,
    pub time: TimeManager,
    pub devices: DeviceManager,
    pub services: ServiceManager,
}
```

---

## 3. 实施步骤 (分阶段)

### 阶段总览

每个阶段都是**独立的、可编译的、可测试的**。完成后立即提交。

| 阶段 | 内容 | 预计改动量 | 风险 |
|------|------|-----------|------|
| 阶段 0 | 准备工作：定义子结构体，先平铺不改变访问方式 | 小 | 无 |
| 阶段 1 | 迁移 `SyncState` | 小 | 低 |
| 阶段 2 | 迁移 `HandleState` | 中 | 低 |
| 阶段 3 | 迁移 `NetworkState` | 小 | 低 |
| 阶段 4 | 迁移 `CrtState` | 小 | 低 |
| 阶段 5 | 迁移 `UiState` | 中 | 低 |
| 阶段 6 | 迁移 `ExceptionState` | 中 | 低 |
| 阶段 7 | 迁移 `ProcessMemoryState` | 中 | 中 |
| 阶段 8 | 迁移 `UnicornState` + `NativeTraceSubsystem` | 大 | 中 |
| 阶段 9 | 迁移 `EngineCore` + `DispatchState` + 收尾 | 大 | 中 |

---

### 阶段 0: 定义子结构体 (准备工作)

**目标**: 在 `engine.rs` 中定义所有子结构体，但 `VirtualExecutionEngine` 暂时保持平铺字段不变。

**操作**:

1. 在 `engine.rs` 中 struct `VirtualExecutionEngine` 定义之前，新增所有子系统 struct 定义
2. 为每个子系统 struct 添加 `#[derive(Debug, Default)]` (Default 需要按需手动实现)
3. 编译验证

**文件**: `engine.rs` 的 299-648 行区域（辅助结构体定义区）

**验证**: `cargo check` + `cargo test`

---

### 阶段 1: 迁移 `SyncState`

**目标**: 将 mutex/semaphore 相关字段移入 `SyncState` 子结构体。

**具体操作**:

1. **修改 `VirtualExecutionEngine` struct**:
   ```rust
   // 删除这 8 个平铺字段:
   // mutex_handles, mutex_handle_targets, mutex_states, named_mutexes,
   // semaphore_handles, semaphore_handle_targets, semaphore_states, named_semaphores
   
   // 替换为:
   sync: SyncState,
   ```

2. **修改构造函数 `new()`**:
   ```rust
   // 将对应字段的初始化改为:
   sync: SyncState::default(),
   ```

3. **全局替换字段访问** (`self.mutex_states` → `self.sync.mutex_states`):
   - 涉及文件:
     - `engine.rs` (构造函数中的初始化)
     - `engine/shared/system/waits.rs` (~10 处)
     - `engine/hooks/core/kernel32.rs` (~20 处)

4. **编译测试**: `cargo check` + `cargo test`

**受影响文件**: ~3 个文件, ~34 处替换

---

### 阶段 2: 迁移 `HandleState`

**目标**: 将文件/设备/查找句柄字段移入 `HandleState`。

**具体操作**:

1. **修改 `VirtualExecutionEngine` struct**:
   ```rust
   // 删除 10 个平铺字段，替换为:
   handles: HandleState,
   ```

2. **全局替换** (`self.file_handles` → `self.handles.file_handles` 等):
   - 涉及文件:
     - `engine/shared/system/filesystem.rs` (~20 处)
     - `engine/hooks/core/kernel32.rs` (~10 处)
     - `engine/hooks/device/setupapi.rs` (~8 处)
     - `engine/hooks/device/cfgmgr32.rs` (~5 处)
     - `engine.rs` (~10 处)

**受影响文件**: ~8 个文件, ~50 处替换

---

### 阶段 3: 迁移 `NetworkState`

**目标**: 将网络相关字段移入 `NetworkState`。

**具体操作**:

1. **修改 struct**: 删除 `network`, `crypto`, `http_response_rule_hits`, `inet_ntoa_buffer`，替换为 `network_state: NetworkState`

2. **注意**: `self.network_manager()` 等 getter 需要适配:
   ```rust
   pub fn network_manager(&self) -> &NetworkManager {
       &self.network_state.network
   }
   pub fn crypto_manager(&self) -> &CryptoManager {
       &self.network_state.crypto
   }
   ```

3. **全局替换**: `self.network.` → `self.network_state.network.` 等

**受影响文件**: ~8 个网络 hook 文件 + engine.rs, ~30 处

---

### 阶段 4: 迁移 `CrtState`

**目标**: 将 CRT 运行时状态移入 `CrtState`。

**具体操作**:

1. **修改 struct**: 删除 `msvcrt_*` 字段，替换为 `crt: CrtState`

2. **全局替换**: `self.msvcrt_globals_base` → `self.crt.msvcrt_globals_base` 等

**受影响文件**: `hooks/crt/*.rs` (~5 文件), ~7 处

---

### 阶段 5: 迁移 `UiState`

**目标**: 将 User32/GUI 状态移入 `UiState`。

**具体操作**:

1. **修改 struct**: 删除 `user32_state`, `shell_imalloc`, `pending_user32_*`，替换为 `ui: UiState`

2. **全局替换**: `self.user32_state.` → `self.ui.user32_state.` 等

**受影响文件**: `hooks/ui/user32/*.rs` (~6 文件), `logging_helpers.rs`, ~84 处

---

### 阶段 6: 迁移 `ExceptionState`

**目标**: 将 SEH 异常处理状态移入 `ExceptionState`。

**具体操作**:

1. **修改 struct**: 删除 6 个 SEH 相关字段，替换为 `exception: ExceptionState`

2. **全局替换**:
   - `self.top_level_exception_filter` → `self.exception.top_level_exception_filter`
   - `self.pending_context_restore` → `self.exception.pending_context_restore`
   - 等等

**受影响文件**: `shared/seh.rs`, `x86_interpreter_helpers.rs`, `engine.rs`, ~15 处

---

### 阶段 7: 迁移 `ProcessMemoryState`

**目标**: 将虚拟内存/进程空间状态移入 `ProcessMemoryState`。

**具体操作**:

1. **修改 struct**: 删除 `virtual_allocations`, `process_handles`, `process_spaces`, `process_snapshots`, `file_mappings`, `heaps`，替换为 `process_memory: ProcessMemoryState`

2. **注意 getter 适配**: `self.heap_manager()` → `&self.process_memory.heaps`

3. **全局替换**: 涉及文件较多，需要仔细处理

**受影响文件**: `shared/system/virtual_memory.rs`, `shared/system/processes.rs`, `shared/system/memory_mapping.rs`, `engine.rs`, ~25 处

---

### 阶段 8: 迁移 `UnicornState` + `NativeTraceSubsystem`

**目标**: 将 Unicorn 引擎状态和原生追踪状态移入独立结构体。

**具体操作**:

1. **修改 struct**: 添加 `unicorn_state: UnicornState` 和 `native_trace_subsystem: NativeTraceSubsystem`

2. **UnicornState 注意事项**:
   - 包含裸指针 `*mut UcEngine`，不能 derive `Default`
   - 需要手动实现 `Default` (全部 `None`/`null`/`false`)
   - `Drop` 实现需要适配

3. **全局替换**:
   - `self.unicorn` → `self.unicorn_state.unicorn`
   - `self.native_trace` → `self.native_trace_subsystem.native_trace`
   - 等等

**受影响文件**: `unicorn_helpers.rs`, `native_unicorn_call_helpers.rs`, `memory_dump_helpers.rs`, `engine.rs` 内的 Unicorn 回调, ~60 处

---

### 阶段 9: 迁移 `EngineCore` + `DispatchState` + 收尾

**目标**: 将剩余字段归入 `EngineCore` 和 `DispatchState`，完成最终结构整理。

**具体操作**:

1. **修改 struct**: 最终的 `VirtualExecutionEngine` 变为:
   ```rust
   pub struct VirtualExecutionEngine {
       core: EngineCore,
       sync: SyncState,
       handles: HandleState,
       process_memory: ProcessMemoryState,
       objects: SyncObjectsState,
       network_state: NetworkState,
       ui: UiState,
       crt: CrtState,
       exception: ExceptionState,
       native_trace: NativeTraceSubsystem,
       unicorn_state: UnicornState,
       dispatch: DispatchState,
   }
   ```

2. **适配所有 getter**:
   ```rust
   pub fn modules(&self) -> &ModuleManager {
       &self.core.modules
   }
   pub fn scheduler(&self) -> &ThreadScheduler {
       &self.core.scheduler
   }
   // ... 约 20 个 getter 需要适配
   ```

3. **适配 test 文件**: 测试中的 `engine.scheduler().thread_snapshot(tid)` 不变 (getter 签名未改)，但 `engine.schedulers_mut()` 等需要适配

4. **验证**: 完整 `cargo test`

---

## 4. 字段→子系统完整映射表

| 字段 | 目标子系统 | 访问频率 |
|------|-----------|---------|
| `arch` | EngineCore | ★★★ |
| `config` | EngineCore | ★ |
| `environment_profile` | EngineCore | ★ |
| `hooks` | EngineCore | ★★★ |
| `modules` | EngineCore | ★★★ |
| `scheduler` | EngineCore | ★★★ |
| `process_env` | EngineCore | ★★★ |
| `processes` | EngineCore | ★★ |
| `registry` | EngineCore | ★★ |
| `api_logger` | EngineCore | ★★★ |
| `runtime_profiler` | EngineCore | ★ |
| `api_call_counts` | EngineCore | ★ |
| `main_module` | EngineCore | ★★ |
| `entry_module` | EngineCore | ★★ |
| `parent_process` | EngineCore | ★ |
| `entry_address` | EngineCore | ★★ |
| `entry_arguments` | EngineCore | ★ |
| `entry_invocation` | EngineCore | ★ |
| `entry_module_requires_attach` | EngineCore | ★ |
| `command_line` | EngineCore | ★ |
| `dll_directory` | EngineCore | ★ |
| `current_directory` | EngineCore | ★★ |
| `current_directory_host` | EngineCore | ★ |
| `environment_variables` | EngineCore | ★ |
| `main_thread_tid` | EngineCore | ★★★ |
| `instruction_count` | EngineCore | ★★ |
| `exit_code` | EngineCore | ★★ |
| `stop_reason` | EngineCore | ★ |
| `process_exit_requested` | EngineCore | ★ |
| `last_error` | EngineCore | ★★ |
| `loaded` | EngineCore | ★ |
| `startup_sequence_completed` | EngineCore | ★ |
| `native_return_sentinel` | EngineCore | ★★ |
| `mutex_handles` | SyncState | ★ |
| `mutex_handle_targets` | SyncState | ★ |
| `mutex_states` | SyncState | ★★ |
| `named_mutexes` | SyncState | ★ |
| `semaphore_handles` | SyncState | ★ |
| `semaphore_handle_targets` | SyncState | ★ |
| `semaphore_states` | SyncState | ★ |
| `named_semaphores` | SyncState | ★ |
| `next_file_handle` | HandleState | ★★ |
| `next_object_handle` | HandleState | ★★ |
| `file_handles` | HandleState | ★★★ |
| `find_handles` | HandleState | ★★ |
| `volume_find_handles` | HandleState | ★ |
| `device_handles` | HandleState | ★★ |
| `io_completion_ports` | HandleState | ★ |
| `setup_device_sets` | HandleState | ★ |
| `token_handles` | HandleState | ★ |
| `etw_trace_handles` | HandleState | ★ |
| `virtual_allocations` | ProcessMemoryState | ★★ |
| `process_handles` | ProcessMemoryState | ★ |
| `process_spaces` | ProcessMemoryState | ★★ |
| `process_snapshots` | ProcessMemoryState | ★ |
| `file_mappings` | ProcessMemoryState | ★ |
| `heaps` | ProcessMemoryState | ★★ |
| `dynamic_library_refs` | SyncObjectsState | ★ |
| `startup_pinned_modules` | SyncObjectsState | ★ |
| `attached_process_modules` | SyncObjectsState | ★ |
| `pending_thread_attach` | SyncObjectsState | ★ |
| `started_threads` | SyncObjectsState | ★ |
| `wts_server_handles` | SyncObjectsState | ★ |
| `global_atoms` | SyncObjectsState | ★ |
| `next_atom` | SyncObjectsState | ★ |
| `mounted_volumes` | SyncObjectsState | ★ |
| `network` | NetworkState | ★★ |
| `crypto` | NetworkState | ★★ |
| `http_response_rule_hits` | NetworkState | ★ |
| `inet_ntoa_buffer` | NetworkState | ★ |
| `user32_state` | UiState | ★★★ |
| `shell_imalloc` | UiState | ★ |
| `pending_user32_timer_callbacks` | UiState | ★ |
| `pending_user32_sendmessage_callbacks` | UiState | ★ |
| `msvcrt_globals_base` | CrtState | ★ |
| `msvcrt_onexit_tables` | CrtState | ★ |
| `msvcrt_rand_seed` | CrtState | ★ |
| `pending_msvcrt_initterm` | CrtState | ★ |
| `top_level_exception_filter` | ExceptionState | ★ |
| `dispatching_top_level_exception_filter` | ExceptionState | ★ |
| `pending_x64_top_level_filter_seed` | ExceptionState | ★ |
| `x64_top_level_exception_filter_thunks` | ExceptionState | ★ |
| `pending_context_restore` | ExceptionState | ★★ |
| `pending_x86_seh_unwind` | ExceptionState | ★ |
| `native_trace` | NativeTraceSubsystem | ★★ |
| `memory_dump_sequence` | NativeTraceSubsystem | ★ |
| `dynamic_code_activities` | NativeTraceSubsystem | ★ |
| `image_hash_baselines` | NativeTraceSubsystem | ★ |
| `remote_shellcode_threads` | NativeTraceSubsystem | ★ |
| `active_x64_synthetic_call` | NativeTraceSubsystem | ★ |
| `pending_hash_bypass_return` | NativeTraceSubsystem | ★ |
| `pending_hash_bypass_target` | NativeTraceSubsystem | ★ |
| `diag_sample_base` | NativeTraceSubsystem | ★ |
| `diag_block_count` | NativeTraceSubsystem | ★ |
| `hash_loop_counter` | NativeTraceSubsystem | ★ |
| `ntdll_exports_dumped` | NativeTraceSubsystem | ★ |
| `unicorn` | UnicornState | ★★ |
| `unicorn_handle` | UnicornState | ★★ |
| `unicorn_intr_hook_installed` | UnicornState | ★ |
| `unicorn_block_hook_installed` | UnicornState | ★ |
| `unicorn_code_hook_installed` | UnicornState | ★ |
| `unicorn_mem_write_hook_installed` | UnicornState | ★ |
| `unicorn_mem_prot_hook_installed` | UnicornState | ★ |
| `unicorn_mem_unmapped_hook_installed` | UnicornState | ★ |
| `defer_api_return` | DispatchState | ★★ |
| `thread_yield_requested` | DispatchState | ★★ |
| `force_native_return` | DispatchState | ★ |
| `guid_rng` | DispatchState | ★ |
| `tls` | DispatchState | ★★ |
| `time` | DispatchState | ★★ |
| `devices` | DispatchState | ★★ |
| `services` | DispatchState | ★★ |

---

## 5. 自动化替换模板

对于每个阶段，使用以下 sed/替换模板:

```bash
# 示例: 阶段 1 迁移 SyncState
# 在 engine/ 下所有 .rs 文件中替换

# mutex 字段
sed -i 's/self\.mutex_handles\b/self.sync.mutex_handles/g' [files]
sed -i 's/self\.mutex_handle_targets\b/self.sync.mutex_handle_targets/g' [files]
sed -i 's/self\.mutex_states\b/self.sync.mutex_states/g' [files]
sed -i 's/self\.named_mutexes\b/self.sync.named_mutexes/g' [files]

# semaphore 字段
sed -i 's/self\.semaphore_handles\b/self.sync.semaphore_handles/g' [files]
sed -i 's/self\.semaphore_handle_targets\b/self.sync.semaphore_handle_targets/g' [files]
sed -i 's/self\.semaphore_states\b/self.sync.semaphore_states/g' [files]
sed -i 's/self\.named_semaphores\b/self.sync.named_semaphores/g' [files]
```

注意: 对 `&mut self` 和 `self` 的访问都需要覆盖。

---

## 6. 不在本方案范围内的事项

1. **不引入 trait**: 不为子系统定义 trait 接口。子系统就是普通 struct + impl
2. **不改变 hook 调度方式**: `impl VirtualExecutionEngine` 在各 hook 文件中的模式不变
3. **不拆分 engine.rs 文件本身**: engine.rs 仍然保留核心生命周期方法 (`new`, `load`, `run`, `dispatch_bound_stub`)
4. **不改变 `use super::*`**: hook 文件继续通过 `use super::*` 访问所有定义
5. **不拆分 unicorn 回调**: 外部 "C" 回调函数留在 engine.rs (它们需要访问全局状态)

---

## 7. 验证策略

每个阶段完成后:

```bash
# 1. 编译检查
cargo check

# 2. 运行全部测试
cargo test

# 3. 运行样本测试 (如果配置存在)
cargo run --release -- --config configs/sample_apionly.json

# 4. 确认无新增 test failure
```

## 8. 提交策略

每个阶段独立提交，commit message 格式:

```
refactor(engine): 迁移 SyncState 子系统 (P2-5 阶段 1)

将 mutex/semaphore 相关字段从 VirtualExecutionEngine 平铺字段
移入 SyncState 子结构体。功能不变，仅重组字段归属。
```

---

## 9. 最终结构预览

迁移完成后的 `VirtualExecutionEngine`:

```rust
pub struct VirtualExecutionEngine {
    // 约 113 个字段 → 12 个子系统字段
    core: EngineCore,              // 基础设施 + 配置
    sync: SyncState,               // mutex/semaphore
    handles: HandleState,          // 文件/设备/查找句柄
    process_memory: ProcessMemoryState, // 虚拟内存 + 进程空间
    objects: SyncObjectsState,     // 内核对象 + 模块跟踪
    network_state: NetworkState,   // 网络 + 加密
    ui: UiState,                   // User32/GUI
    crt: CrtState,                 // C 运行时
    exception: ExceptionState,     // SEH 异常处理
    native_trace: NativeTraceSubsystem, // 原生执行追踪
    unicorn_state: UnicornState,   // Unicorn 引擎
    dispatch: DispatchState,       // 调度临时状态 + 辅助管理器
}
```

**收益**:
1. 从 struct 定义直接看到功能域划分
2. 新增功能时知道状态应该放在哪个子系统
3. 代码审查时能快速定位相关状态
4. IDE 跳转更精准 (`self.sync.mutex_states` 比 `self.mutex_states` 更有语义)
5. 为将来进一步拆分 (如将子系统方法迁移到子系统 impl) 奠定基础
