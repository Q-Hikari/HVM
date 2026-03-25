# Hook Module Family Conventions

这份文档描述的是 HVM-Hikari Virtual Engine 在源目录下当前 Hook 体系的结构约定。

目标只有三个：

1. 路径一眼能看出职责。
2. 同一层级的目录必须表达同一种分类轴。
3. 新增 Hook 时，先知道应该从哪一层开始，而不是先改大入口再回头找归属。

## 1. 总体原则

### 1.1 先按职责分层，再按模块族分组

当前 Hook 相关代码分成四层：

| 路径 | 作用 | 不应该放什么 |
| --- | --- | --- |
| `HVM/src/hooks/` | Hook 定义、注册、模块族入口 | 运行时执行逻辑 |
| `HVM/src/runtime/engine/hooks/` | 运行时 Hook 分发和 DLL 行为实现 | Hook 定义目录、无关公共工具 |
| `HVM/src/runtime/engine/shared/` | 跨模块族复用的运行时能力 | 某个单独 DLL 的私有逻辑 |
| `HVM/src/runtime/windows_env/` | PEB/TEB/LDR/ProcessParameters/TLS 等 Windows 运行时镜像 | 普通 Win32 API Hook 行为 |

### 1.2 文件名必须表达真实所有权

- 一个文件名如果是 DLL 名，例如 `kernel32.rs`，它就应该是这个 DLL 的定义或运行时行为所有者。
- 一个文件名如果不是 DLL 名，就必须是清晰的职责名，例如 `family_dispatch.rs`、`process_launch.rs`、`memory_mapping.rs`。
- `mod.rs` 只做入口和装配，不承载大段混合逻辑。

### 1.3 禁止重新引入模糊桶目录

后续不要再新增这类名字：

- `helpers`
- `misc`
- `remaining`
- `runtime`
- `dispatch` 作为家族内泛桶目录

如果逻辑已经大到不能继续留在 `<dll>.rs`，就按明确职责拆开，例如：

- `exports.rs`
- `messages.rs`
- `timers.rs`
- `state.rs`
- `process_launch.rs`
- `virtual_memory.rs`

## 2. 顶层目录职责

### 2.1 `HVM/src/hooks/`

当前文件职责如下：

| 路径 | 作用 |
| --- | --- |
| `HVM/src/hooks/mod.rs` | Hook 体系总入口，只暴露基础模块、模块族入口和统一注册入口 |
| `HVM/src/hooks/base.rs` | `HookDefinition`、`CallConv`、`HookLibrary` 这类基础抽象 |
| `HVM/src/hooks/registry.rs` | `HookRegistry` 及 synthetic export 绑定能力 |
| `HVM/src/hooks/stub.rs` | 生成静态 Hook 定义的通用拼装工具 |
| `HVM/src/hooks/family_registration.rs` | 统一注册所有模块族定义 |
| `HVM/src/hooks/registry_probe_exports.rs` | 注册表/兼容性测试使用的代表性导出集合 |
| `HVM/src/hooks/families/` | 按模块族组织的 Hook 定义目录 |

### 2.2 `HVM/src/hooks/families/`

这个目录只放“注册到 `HookRegistry` 的定义目录”。

每个模块族一个目录，目录名表达 API 家族，不表达执行方式。

当前模块族约定如下：

| 模块族 | 放置内容 |
| --- | --- |
| `core` | 进程、模块、基础系统 API，典型如 `kernel32`、`ntdll`、`psapi`、`version`、`appmodel_runtime` |
| `crt` | C/C++ Runtime 相关 DLL，典型如 `msvcrt`、`ucrt`、`vcruntime140`、`msvcp140` |
| `com` | COM / OLE / RPC 相关 DLL，典型如 `combase`、`ole32`、`oleaut32`、`rpcrt4` |
| `ui` | 窗口、控件、输入法、主题等 UI 能力，典型如 `user32`、`comctl32`、`comdlg32`、`imm32`、`uxtheme` |
| `graphics` | 图形、多媒体、绘图相关 DLL，典型如 `gdi32`、`gdiplus`、`msimg32`、`winmm` |
| `network` | 网络、套接字、HTTP、网络配置相关 DLL，典型如 `winhttp`、`wininet`、`ws2_32`、`mswsock`、`iphlpapi` |
| `security` | 加密、证书、凭据、安全提供方，典型如 `advapi32`、`bcrypt`、`crypt32`、`ncrypt`、`wintrust` |
| `device` | 设备、驱动安装、配置管理，典型如 `cfgmgr32`、`setupapi`、`cabinet` |
| `diagnostics` | 调试、错误报告、事件追踪，典型如 `dbghelp`、`dbgcore`、`wer`、`wevtapi`、`apphelp` |
| `installer` | 安装器相关模块，当前是 `msi` |
| `print` | 打印相关模块，当前是 `winspool`、`winspool_drv` |
| `shell_services` | Shell、会话、URL moniker、任务计划等服务层接口，典型如 `shell32`、`shlwapi`、`urlmon`、`taskschd`、`wtsapi32` |

### 2.3 `HVM/src/hooks/families/<family>/`

约定如下：

- `<dll>.rs`：这个 DLL 的 Hook 定义所有者。
- `mod.rs`：只负责暴露子模块和提供当前模块族的 `register(...)`。
- 只有当一个 DLL 体量明显过大时，才允许继续下沉成子目录。

当前只有一个特例：

| 路径 | 作用 |
| --- | --- |
| `HVM/src/hooks/families/ui/user32/` | `user32` 定义目录的子层，当前用 `exports.rs` 承载导出集合，避免把大型 UI API 都塞进 `ui/mod.rs` |

## 3. 运行时 Hook 目录职责

### 3.1 `HVM/src/runtime/engine/hooks/`

这个目录只放“运行时行为实现”，也就是 `VirtualExecutionEngine` 实际怎么处理某个 Hook。

当前文件职责如下：

| 路径 | 作用 |
| --- | --- |
| `HVM/src/runtime/engine/hooks/family_dispatch.rs` | 运行时 Hook 总分发入口，按模块名把调用路由到各个模块族 |
| `HVM/src/runtime/engine/hooks/<family>/` | 某个模块族在运行时的行为实现 |

注意：

- 不是每个定义模块族都一定有运行时目录。
- 只有“真的实现了运行时行为”的家族，才在这里有对应目录。
- 如果某个 DLL 目前只有 synthetic export 定义，没有专门语义实现，就不需要为了对齐目录而强行创建 runtime 文件。

### 3.2 `HVM/src/runtime/engine/hooks/<family>/`

约定如下：

- `<dll>.rs`：这个 DLL 的运行时行为入口，通常包含 `dispatch_<dll>_hook(...)`。
- `mod.rs`：只负责挂载子模块。
- 非 DLL 文件只能是明确职责文件。

当前典型职责文件：

| 路径 | 作用 |
| --- | --- |
| `HVM/src/runtime/engine/hooks/com/common.rs` | COM 家族内部复用逻辑 |
| `HVM/src/runtime/engine/hooks/network/http.rs` | `winhttp` / `wininet` 共用的 HTTP 处理逻辑 |
| `HVM/src/runtime/engine/hooks/core/kernel32_firmware.rs` | `kernel32` 下单独拆出的固件相关行为 |
| `HVM/src/runtime/engine/hooks/crt/data_imports.rs` | CRT 运行时数据导入布局 |
| `HVM/src/runtime/engine/hooks/crt/globals.rs` | CRT 全局状态镜像 |
| `HVM/src/runtime/engine/hooks/crt/initterm.rs` | CRT 初始化项执行逻辑 |
| `HVM/src/runtime/engine/hooks/crt/onexit.rs` | CRT on-exit 表逻辑 |

### 3.3 `HVM/src/runtime/engine/hooks/ui/user32/`

`user32` 是当前体量最大的 UI 运行时模块，已经按职责拆分：

| 路径 | 作用 |
| --- | --- |
| `exports.rs` | `user32.dll` 的导出入口分发 |
| `handles.rs` | 窗口、图标、DC、句柄相关逻辑 |
| `messages.rs` | 消息队列和消息泵行为 |
| `timers.rs` | 定时器行为 |
| `windows_hooks.rs` | Windows hook callback / install / unhook |
| `state.rs` | `User32State` 和常量 |
| `mod.rs` | 入口装配 |

这个目录是后续“大型 DLL 应该怎么拆”的示范模板。

## 4. 共享运行时目录职责

### 4.1 `HVM/src/runtime/engine/shared/`

这个目录只放“跨模块族可复用的运行时能力”。

当前文件职责如下：

| 路径 | 作用 |
| --- | --- |
| `api_logging.rs` | API 调用与返回日志 |
| `guest_memory.rs` | 来宾内存读写通用能力 |
| `network_profile.rs` | 环境画像中的网络侧共享逻辑 |
| `registry.rs` | 共享注册表运行时逻辑 |
| `remote_thread.rs` | 远程线程注入/恢复相关共享逻辑 |
| `seh.rs` | 结构化异常处理共享能力 |
| `services.rs` | 服务管理相关共享逻辑 |
| `unwind.rs` | RTL / unwind 共享逻辑 |
| `system/` | 系统基础能力的再分层 |

### 4.2 `HVM/src/runtime/engine/shared/system/`

这个目录只放“跨家族的系统基础能力”，不放某个单独 DLL 的私有语义。

当前文件职责如下：

| 路径 | 作用 |
| --- | --- |
| `environment.rs` | 环境变量、环境字符串扩展 |
| `filesystem.rs` | 文件系统路径与宿主文件访问共性逻辑 |
| `formatting.rs` | 格式化输出、字符串拼装等公共逻辑 |
| `memory_mapping.rs` | 文件映射/视图共享逻辑 |
| `process_launch.rs` | 进程启动和 shell launch 共性逻辑 |
| `processes.rs` | 进程对象、快照、进程枚举共性逻辑 |
| `thread_context.rs` | 线程上下文读写共性逻辑 |
| `virtual_memory.rs` | 虚拟内存区域、保护、查询共性逻辑 |
| `waits.rs` | wait / signal / waitable object 共性逻辑 |
| `mod.rs` | 入口装配 |

## 5. Windows 运行时镜像目录职责

### 5.1 `HVM/src/runtime/windows_env/`

这个目录不是普通 Hook 层，而是 Windows 进程环境镜像层。

如果需求涉及这些对象，就应该从这里开始，而不是先去改某个 DLL Hook：

- `PEB`
- `TEB`
- `LDR`
- `ProcessParameters`
- `TLS`
- 虚拟环境内存 materialization

### 5.2 `HVM/src/runtime/windows_env/` 子目录职责

| 路径 | 作用 |
| --- | --- |
| `core/` | 整个环境镜像的布局、偏移、构造入口 |
| `memory/` | 稀疏内存存取与 materialization |
| `process/` | `PEB`、loader、`ProcessParameters` |
| `thread/` | `TEB`、GDT、TLS、线程布局 |

更细一级职责如下：

| 路径 | 作用 |
| --- | --- |
| `core/bootstrap/` | 启动期布局初始化缓冲区 |
| `core/factory/` | 构造环境镜像时的工厂逻辑 |
| `memory/io/` | 脏页、读、写三类内存 I/O 能力 |
| `process/loader/` | Loader 列表与模块链表镜像 |
| `process/parameters/` | `ProcessParameters` 布局、字符串和环境块 |
| `thread/teb/` | TEB 绑定与初始化 |
| `thread/tls/` | TLS 位图、槽位与布局 |

## 6. 新增代码时应该从哪里开始

### 6.1 新增一个 DLL 的 Hook 定义

从这里开始：

1. 先确定 DLL 属于哪个模块族。
2. 在 `HVM/src/hooks/families/<family>/<dll>.rs` 新增或扩展定义。
3. 在对应 `HVM/src/hooks/families/<family>/mod.rs` 的 `register(...)` 中挂上它。
4. 如果只是 synthetic export 定义，到这里就够了。

不要从这里开始：

- `HVM/src/runtime/engine.rs`
- `HVM/src/runtime/engine/hooks/family_dispatch.rs`

只有当你需要真实运行时行为时，才进入 runtime 层。

### 6.2 新增一个 DLL 的运行时行为

从这里开始：

1. 先确认这个 DLL 已经有 `HVM/src/hooks/families/<family>/<dll>.rs` 定义。
2. 在 `HVM/src/runtime/engine/hooks/<family>/<dll>.rs` 新增或扩展 `dispatch_<dll>_hook(...)`。
3. 在 `HVM/src/runtime/engine/hooks/family_dispatch.rs` 把模块名路由接上。
4. 补测试。

什么时候要拆成子目录：

- 单文件已经同时承载导出入口、状态、消息流、对象句柄、回调机制。
- 拆分后可以形成稳定职责名，例如 `state.rs`、`messages.rs`、`timers.rs`。

什么时候不要拆：

- 只是函数多一点，但职责仍然单一。
- 拆完只会产生 `helpers.rs` / `misc.rs` 这种更模糊的名字。

### 6.3 新增跨 DLL 的共享逻辑

先判断它属于哪一类：

| 情况 | 起点 |
| --- | --- |
| 只在同一家族内复用 | `HVM/src/runtime/engine/hooks/<family>/` |
| 多个家族都能复用 | `HVM/src/runtime/engine/shared/` |
| 属于系统基础能力，如进程、等待、虚拟内存 | `HVM/src/runtime/engine/shared/system/` |

判断标准：

- 如果离开某个 DLL 仍然成立，就是共享逻辑。
- 如果离开某个 DLL 就失去语义，多半仍应留在该 DLL 文件内。

### 6.4 新增 PEB / TEB / ProcessParameters / TLS 相关逻辑

直接从 `HVM/src/runtime/windows_env/` 开始，不要先去改 `kernel32` 或 `ntdll`。

推荐顺序：

1. 先判断属于 `core`、`process`、`thread` 还是 `memory`。
2. 再决定是布局、初始化、字符串、列表、槽位还是 I/O。
3. 最后才回到 Hook 层，把 API 调用接到镜像层能力上。

## 7. 命名规则

后续新增文件和目录应遵守下面规则：

1. 目录名用“领域/家族”名，不用“动作”名。
2. 文件名优先用 DLL 名；如果不是 DLL 名，就必须是职责名。
3. `mod.rs` 只做聚合，不堆业务逻辑。
4. 同目录内文件名要能并列阅读，例如 `messages.rs`、`timers.rs`、`state.rs`。
5. 不允许新增“临时兼容层”顶层 shim 文件。
6. 如果确实需要兼容层，必须单独说明生命周期和清理计划。

## 8. 最简落地模板

### 8.1 新增 definition-only DLL

```text
HVM/src/hooks/families/<family>/<dll>.rs
HVM/src/hooks/families/<family>/mod.rs
tests/hook_registry.rs 或对应 family 测试
```

### 8.2 新增有运行时语义的 DLL

```text
HVM/src/hooks/families/<family>/<dll>.rs
HVM/src/runtime/engine/hooks/<family>/<dll>.rs
HVM/src/runtime/engine/hooks/family_dispatch.rs
tests/<dll>_hooks.rs
```

### 8.3 新增大型 DLL 子目录

```text
HVM/src/runtime/engine/hooks/<family>/<dll>/
  mod.rs
  exports.rs
  state.rs
  <clear_responsibility>.rs
```

只有在单 DLL 已经形成明确内部分层时，才允许这样做。

## 9. 当前推荐入口

以后写新 Hook，优先按下面顺序找入口：

1. 先看 `HVM/src/hooks/families/<family>/`，决定定义归属。
2. 再看 `HVM/src/runtime/engine/hooks/<family>/`，决定运行时语义归属。
3. 如果发现逻辑跨家族，再看 `HVM/src/runtime/engine/shared/`。
4. 如果需求本质是 Windows 环境镜像，再看 `HVM/src/runtime/windows_env/`。

不要反过来从 `engine.rs`、`mod.rs`、大入口文件开始找落点。

它们只负责装配，不是写新功能的第一站。
