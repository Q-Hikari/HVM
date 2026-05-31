# HVM-Hikari Virtual Engine

HVM-Hikari Virtual Engine 是一个面向 Windows PE 的 Rust 虚拟执行引擎，用来模拟样本在用户态的装载、初始化、导入解析、API 调用和行为产出。它聚焦 `x86` / `x64` PE，目标不是复刻完整 Windows VM，而是在可控环境里尽量还原样本可观察到的执行语义，并稳定输出 API 日志、运行摘要和结构化分析结果。

## 当前能力

- PE 解析、重定位、导入修复、TLS 元数据处理
- `x86` / `x64` Unicorn 执行后端
- `PEB` / `TEB` / `LDR` / `ProcessParameters` / `TLS` Windows 运行时镜像
- 统一 ABI 分发、真实 DLL 路径解析、模块映射与可见基址控制
- 多线程调度、等待对象恢复、远程线程与进程相关语义
- 文件、内存、模块、进程、注册表、设备、网络、服务、句柄、时间等 manager
- `inspect` / `samples` / `run` / `analyze` / `batch` 五个主命令
- API human log、JSONL 事件流、console 输出、sandbox 产物、结构化分析 JSON

## 架构主轴

当前代码结构按“职责层”优先：

| 路径 | 作用 |
| --- | --- |
| `HVM/src/pe/` | PE 解析、装载、导入绑定、inspect 能力 |
| `HVM/src/runtime/windows_env.rs` | Windows 进程环境镜像入口，负责 `PEB` / `TEB` / `LDR` / `ProcessParameters` / `TLS` 初始化 |
| `HVM/src/memory/` | 虚拟地址空间与页级权限管理 |
| `HVM/src/managers/` | 文件、模块、进程、注册表、网络、服务、设备、时间、加密等运行时 manager |
| `HVM/src/hooks/families/` | Hook 定义层，只负责导出注册、签名和模块族归属 |
| `HVM/src/runtime/engine/` | Hook 运行时分发、参数解码、ABI 适配、日志、观测点与执行主循环 |
| `HVM/src/runtime/scheduler.rs` | 线程调度与等待恢复 |
| `collector/` | 在真实 Windows 主机采集环境画像，生成可直接给 HVM 使用的 profile |
| `tools/` | 批跑、汇总和辅助脚本 |

Hook 相关代码遵循两条主线：

1. 定义层从 `HVM/src/hooks/families/<family>/<dll>.rs` 开始。
2. 运行时语义从 `HVM/src/runtime/engine/hooks/<family>/<dll>.rs` 开始。

如果需求不是某个 DLL 私有逻辑，而是跨家族复用能力，优先放到 `HVM/src/runtime/engine/shared/` 或 `HVM/src/runtime/engine/shared/system/`。如果需求本质上是 Windows 进程环境镜像，不要先改 Hook，而是直接从 `runtime/windows_env` 与相关 manager 下手。

## 仓库结构

```text
.
├── Cargo.toml
├── README.md
├── Sample/                  # 仓库内默认样本
├── configs/
│   ├── environment_profile.example.json
│   ├── profiles/            # 可公开环境画像
│   └── templates/           # 可公开运行模板
├── collector/               # Windows 环境画像采集器
├── docs/                    # 使用说明与分析文档
├── HVM/                     # HVM Rust crate 源码
└── tools/                   # 批跑与辅助脚本
```

## 构建要求

- Rust stable
- `cmake`
- 可用的 C/C++ 编译工具链

`vendor/unicorn` 会在构建时一并编译并静态链接进主程序，所以首次 `release` 构建会比普通 Rust 项目慢一些，但最终产物不再依赖额外的 `unicorn` 动态库。

生成 HVM release 二进制：

```bash
cargo build -p hvm-hikari-virtual-engine --release
```

生成最小 Linux 发布包：

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
CC_x86_64_unknown_linux_musl=musl-gcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
cargo build -p hvm-hikari-virtual-engine --release --target x86_64-unknown-linux-musl
```

生成最小 Windows 发布包：

```bash
cargo build -p hvm-hikari-virtual-engine --release --target x86_64-pc-windows-msvc
```

构建环境画像采集器：

```bash
cargo build --manifest-path collector/Cargo.toml --release
```

说明：

- `x86_64-unknown-linux-musl` 产物会把 Linux libc 一并静态进二进制，适合直接发单文件。
- `x86_64-pc-windows-msvc` 已通过 [`.cargo/config.toml`](.cargo/config.toml) 启用 `crt-static`，并同步让 `vendor/unicorn` 使用静态 CRT，避免额外依赖 VC 运行库。
- 仓库内置了 [`.github/workflows/release.yml`](.github/workflows/release.yml)，推送 `v*` tag 后会自动生成 Linux `musl` `tar.gz` 和 Windows `zip` 并挂到 GitHub Release。

## 公开配置资产

公开仓库只保留模板化、可复用的配置文件：

- `configs/templates/default_x64.json`
- `configs/templates/default_x86.json`
- `configs/templates/light_x64.json`
- `configs/templates/light_x86.json`
- `configs/profiles/*.json`
- `configs/environment_profile.example.json`

说明：

- 样本专用配置、内部调试配置和私有路径配置不会进入公开发布。
- 模板中的 `system_dll/System32`、`system_dll/SysWOW64` 只是本地目录约定，不是仓库自带内容。使用时需要自行准备真实 DLL 目录，并按本机路径修改 `module_search_paths`、`allowed_read_dirs`、`module_directory_x86`、`module_directory_x64`。
- 如果要从真实 Windows 主机采集环境画像，推荐在目标机器上运行 `collector`，再把生成的 profile 交给 `environment_profile` 使用。

## 快速开始

列出样本：

```bash
cargo run -p hvm-hikari-virtual-engine -- samples --dir Sample
```

查看 PE 元数据：

```bash
cargo run -p hvm-hikari-virtual-engine -- inspect Sample/example.exe
```

准备公开模板配置：

```bash
cp configs/templates/default_x64.json run.local.json
```

然后至少修改这些字段：

- `main_module`
- `process_image`
- `command_line`
- `sandbox_output_dir`
- `module_search_paths`
- `allowed_read_dirs`
- `module_directory_x64` 或 `module_directory_x86`
- `environment_profile` 或 `environment_overrides`

按配置运行样本：

```bash
cargo run -p hvm-hikari-virtual-engine -- run --config run.local.json
```

采集一份真实 Windows 环境画像：

```bash
collector/target/release/hvm-collector.exe profile.json
```

输出结构化分析 JSON：

```bash
cargo run -p hvm-hikari-virtual-engine -- analyze \
  --sample Sample/example.exe \
  --profile win10_21h2_x64 \
  --output out/example.json
```

批量输出结构化分析 JSON：

```bash
cargo run -p hvm-hikari-virtual-engine -- batch \
  --dir Sample \
  --profile win10_21h2_x64 \
  --output-dir out/batch
```

运行测试：

```bash
cargo test -p hvm-hikari-virtual-engine --tests
```

## CLI

```text
hvm-hikari-virtual-engine inspect <path>
hvm-hikari-virtual-engine samples --dir <sample_dir>
hvm-hikari-virtual-engine run --config <config.json>
hvm-hikari-virtual-engine analyze --sample <path> --output <result.json> [--profile ...]
hvm-hikari-virtual-engine batch --dir <sample_dir> --output-dir <dir> [--profile ...]
```

- `inspect`：静态查看 PE 头、架构、入口点、导入导出等信息
- `samples`：扫描样本目录并输出样本清单
- `run`：按 JSON 配置加载环境并执行样本
- `analyze`：执行单样本并输出结构化 JSON 结果
- `batch`：批量执行目录内样本并输出结构化结果目录

## 配置入口

运行配置由 `configs/` 下的 JSON 驱动。常用字段如下：

| 字段 | 作用 |
| --- | --- |
| `main_module` | 主样本路径 |
| `process_image` | 暴露给 `PEB` / `GetModuleHandle(NULL)` 的进程镜像 |
| `parent_process_image` / `parent_process_pid` / `parent_process_command_line` | 父进程画像覆盖 |
| `entry_module` | 指定实际执行入口所在模块 |
| `entry_export` / `entry_ordinal` | DLL 导出入口 |
| `entry_args` | DLL 导出或原生调用参数，支持整数、空指针、字符串、字节数组 |
| `module_search_paths` | 真实模块搜索路径 |
| `module_directory_x86` / `module_directory_x64` | 指定架构对应的真实 DLL 根目录 |
| `modules_always_exist` / `functions_always_exist` | 缺失模块或导出是否允许退化为合成对象 |
| `whitelist_modules` / `preload_modules` | 强制真实装载或预先装载的模块列表 |
| `prologue_source_paths` | 允许提取真实模块导出前导字节的来源路径 |
| `volumes` / `auto_mount_module_dirs` | 盘符、卷 GUID 与模块目录自动挂载 |
| `allowed_read_dirs` / `blocked_read_dirs` | 宿主读路径白名单 / 黑名单 |
| `hidden_device_paths` / `hidden_registry_keys` | 反虚拟化路径隐藏规则 |
| `http_response_rules` | HTTP 层的静态响应规则 |
| `interception_rules` | 对注册表、文件、系统查询、设备 IOCTL 的细粒度返回控制 |
| `trace_api_calls` / `trace_native_events` | API / native 事件追踪开关 |
| `api_log_to_console` | 是否把 API 日志直接打印到宿主终端 |
| `api_log_include_return` / `api_log_include_context` | 是否记录返回值与上下文 |
| `api_log_stack_words` / `api_log_string_limit` | 参数栈与字符串解码控制 |
| `api_log_path` / `api_jsonl_path` / `api_human_log_path` | API 日志输出路径 |
| `console_output_to_console` / `console_output_path` | console 输出同步与落盘 |
| `sandbox_output_dir` | 样本产物根目录 |
| `unknown_api_policy` | 未实现 API 策略，常用 `log_zero` |
| `stack_reserve_size` | 栈保留区大小覆盖 |
| `environment_profile` / `environment_overrides` | 环境画像及覆盖项 |
| `observation_checkpoints` | 按指令数插入观测点 |
| `exit_on_unsupported_hook` | 遇到未支持 Hook 时直接退出 |
| `max_instructions` | 单次执行最大指令数 |
| `command_line` | 暴露给样本的命令行 |

补充说明：

- `environment_profile` 可以直接引用 `configs/profiles/` 下的公开画像，也可以指向 `collector` 生成的 JSON。
- `interception_rules` 适合对环境探测、设备读取、注册表比较和系统信息读取做统一建模，而不是对单一样本硬编码。
- `observation_checkpoints` 适合在长链路样本里做阶段性观测，配合 API 日志与 runtime event log 一起使用。

## 输出与日志

一次 `run` 常见会产生以下内容：

- `run.stdout.log`：标准 summary，包含 `instructions`、`exit_code`、`stop_reason`
- `logs/*.api.human.log`：人类可读 API trace
- `logs/*.api.jsonl`：结构化 API / runtime 事件流
- `logs/*.console.log`：console 输出
- `sandbox_output_dir/`：文件落地、内存 dump、虚拟文件系统等分析产物

`analyze` 和 `batch` 还会额外输出结构化 JSON，方便后续做 IOC 提取、规则归档和平台对接。

## 发布与打包

`v0.1.1` 通过 GitHub Actions 自动构建发布产物：

- Linux `x86_64-unknown-linux-musl` 二进制包
- Windows `x86_64-pc-windows-msvc` 二进制包
- Windows `hvm-collector.exe`
- `README.md`
- `configs/templates/*.json`
- `configs/profiles/*.json`
- `configs/environment_profile.example.json`

本地仓库可以继续保留私有样本配置与调试物料；公开 release 只携带可复用的模板和画像。

## 路线图

后续优先方向如下：

- 权限管理与虚拟机刺探黑名单的统一建模和管控
- 常见反虚拟机 / 反沙箱探针的黑名单治理
- 引入 ML 驱动的执行序列建模
- 自动化提取 IOC
- 行为输出与报告格式文档化
- 对接 IDA / Binary Ninja 辅助分析
- 加入 net 调用器
