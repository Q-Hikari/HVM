# HVM-Hikari Virtual Engine

HVM-Hikari Virtual Engine 是一个面向 Windows PE 的 Rust 虚拟执行引擎，用来模拟恶意样本在用户态的装载、初始化、API 调用和行为产出。它聚焦 `x86` / `x64` PE，目标不是复刻完整 Windows VM，而是在可控环境里尽量还原样本可观察到的执行语义，并稳定输出行为日志、运行摘要和分析产物。


## 当前能力

- PE 解析、重定位、导入修复、TLS 元数据处理
- x86 / x64 Unicorn 执行后端
- `PEB` / `TEB` / `LDR` / `ProcessParameters` / `TLS` Windows 运行时镜像
- 按职责和模块族组织的 Hook 体系，覆盖注册定义、运行时分发和共享运行时能力
- 文件、内存、模块、进程、注册表、设备、网络、服务、句柄、TLS、时间等 manager
- `inspect` / `samples` / `run` 三个主命令
- API trace、native 事件、console 输出、sandbox 产物、执行摘要

## 架构主轴

当前代码结构按“职责层”优先

| 路径 | 作用 |
| --- | --- |
| `HVM/src/pe/` | PE 解析、装载、导入绑定、inspect 能力 |
| `HVM/src/runtime/windows_env/` | Windows 进程环境镜像，负责 `PEB` / `TEB` / `LDR` / `ProcessParameters` / `TLS` |
| `HVM/src/memory/` | 内存管理模块，负责虚拟地址空间与页级权限等基础能力 |
| `HVM/src/managers/` | 文件、模块、进程、注册表、网络、服务、设备、句柄等运行时 manager |
| `HVM/src/hooks/families/` | Hook 定义层，只负责导出注册、synthetic export 和模块族归属 |
| `HVM/src/runtime/engine/hooks/` | Hook 运行时行为层，只负责 DLL 语义分发和执行逻辑 |
| `HVM/src/runtime/engine/shared/` | 跨模块族共享的运行时能力 |
| `docs/` | 模块族约定等工程内结构文档 |


## Hook 模块族约定

Hook 相关代码现在遵循两条主线：

1. 定义层从 `HVM/src/hooks/families/<family>/<dll>.rs` 开始。
2. 运行时语义从 `HVM/src/runtime/engine/hooks/<family>/<dll>.rs` 开始。

如果需求不是某个 DLL 私有逻辑，而是跨家族复用能力，就放到：

- `HVM/src/runtime/engine/shared/`
- `HVM/src/runtime/engine/shared/system/`

如果需求本质上是 Windows 进程环境镜像，不要先改 Hook，而是直接从：

- `HVM/src/runtime/windows_env/`

更完整的约定见：

- [docs/hook_module_family_conventions.md](docs/hook_module_family_conventions.md)

## 仓库结构

```text
.
├── Cargo.toml
├── README.md
├── Sample/                  # 样本集
├── configs/                 # 运行配置与环境画像
├── docs/                    # 使用说明、日志协议、对照验证
├── HVM/                     # HVM-Hikari Virtual Engine Rust crate 源码
└── tools/                   # 批跑与辅助脚本
```

## 构建要求

- Rust stable
- `cmake`
- 可用的 C/C++ 编译工具链

`vendor/unicorn` 会在构建时一并编译并静态链接进主程序，所以首次 `release` 构建会比普通 Rust 项目慢一些，但最终产物不再依赖额外的 `unicorn` 动态库。

## 快速开始

列出样本：

```bash
cargo run -p hvm-hikari-virtual-engine -- samples --dir Sample
```

查看样本 PE 元数据：

```bash
cargo run -p hvm-hikari-virtual-engine -- inspect Sample/567dbfa9f7d29702a70feb934ec08e54
```

按配置运行样本：

```bash
cargo run -p hvm-hikari-virtual-engine -- run --config configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json
cargo run -p hvm-hikari-virtual-engine -- run --config configs/sample_58ac2f65e335922be3f60e57099dc8a3_trace.json
```

运行测试：

```bash
cargo test -p hvm-hikari-virtual-engine --tests
```

生成 release 二进制：

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

说明：

- `x86_64-unknown-linux-musl` 产物会把 Linux libc 一并静态进二进制，适合直接发单文件。
- `x86_64-pc-windows-msvc` 已通过 [`.cargo/config.toml`](.cargo/config.toml) 启用 `crt-static`，并同步让 `vendor/unicorn` 使用静态 CRT，避免额外依赖 VC 运行库。
- 仓库内置了 [`.github/workflows/release.yml`](.github/workflows/release.yml)，推送 `v*` tag 后会自动生成 Linux `musl` `tar.gz` 和 Windows `zip` 并挂到 GitHub Release。
- 如果不想推 tag，也可以在 GitHub Actions 里手动触发 `release` workflow，并显式填写目标 tag。

## CLI

```text
hvm-hikari-virtual-engine inspect <path>
hvm-hikari-virtual-engine samples --dir <sample_dir>
hvm-hikari-virtual-engine run --config <config.json>
```

- `inspect`：静态查看 PE 头、架构、入口点、导入导出等信息
- `samples`：扫描 `Sample/` 下的 PE 文件并输出样本清单
- `run`：按 JSON 配置加载环境并执行样本

## 配置入口

运行配置由 [`configs/`](configs/) 中的 JSON 驱动。常用字段如下：

| 字段 | 作用 |
| --- | --- |
| `main_module` | 主样本路径 |
| `process_image` | 暴露给 `PEB` / `GetModuleHandle(NULL)` 的进程镜像 |
| `entry_module` | 指定实际执行入口所在模块 |
| `entry_export` / `entry_ordinal` | DLL 导出入口 |
| `entry_args` | DLL 导出或原生调用参数，支持整数值和带类型对象 |
| `module_search_paths` | 真实模块搜索路径 |
| `whitelist_modules` / `preload_modules` | 强制视为存在或预先装载的模块列表 |
| `volumes` | 把宿主目录挂载到客体盘符或卷根，供多盘符、多卷 GUID、磁盘遍历类样本使用 |
| `allowed_read_dirs` / `blocked_read_dirs` | 宿主读路径白名单 / 黑名单 |
| `hidden_device_paths` / `hidden_registry_keys` | 反虚拟化路径隐藏规则 |
| `trace_api_calls` / `trace_native_events` | API / native 事件追踪开关 |
| `api_log_to_console` | 是否把 API 日志直接打印到宿主终端 |
| `api_log_include_return` | 是否记录 `API_RET` 返回事件 |
| `api_log_string_limit` | API 参数与返回值字符串解码上限 |
| `api_log_path` / `api_jsonl_path` / `api_human_log_path` | API 日志输出路径 |
| `console_output_to_console` | 是否把样本 console 输出同步到宿主终端 |
| `console_output_path` | console 输出路径 |
| `sandbox_output_dir` | 样本产物根目录 |
| `unknown_api_policy` | 未实现 API 策略，当前常用 `log_zero` |
| `environment_profile` / `environment_overrides` | 环境画像及覆盖项 |
| `max_instructions` | 单次执行最大指令数 |
| `command_line` | 暴露给样本的命令行 |

补充说明：

- `entry_args` 当前稳定配置里既有 `0x180000000` 这类整数参数，也有 `{"type":"wstring","value":""}` 这类显式类型参数。
- `environment_profile` 指向独立画像文件时，可参考 [`configs/environment_profile.example.json`](configs/environment_profile.example.json)。当前示例里常见段落包括 `machine`、`os_version`、`locale`、`display`、`volume`、`module_search_paths`、`environment_variables`、`processes`、`registry`。
- `environment_overrides.volume.physical_drive_count` 用于控制向样本暴露多少个 `\\.\PhysicalDriveN` 设备；磁盘遍历或擦盘类样本如果会连续探测 `PhysicalDrive0..N`，这个值需要按样本行为放大。
- `volumes` 会额外生成盘符根和 `\\?\Volume{GUID}` 视图；如果样本既枚举物理盘又枚举卷，仅靠 `allowed_read_dirs` 不够，通常需要同时配置 `volumes` 与 `environment_overrides.volume`。

最小可运行示例：

```json
{
  "main_module": "Sample/567dbfa9f7d29702a70feb934ec08e54",
  "module_search_paths": [
    "Sample",
    "C:/Windows/System32",
    "C:/Windows/SysWOW64"
  ],
  "allowed_read_dirs": [
    "Sample",
    "C:/Windows/System32",
    "C:/Windows/SysWOW64"
  ],
  "blocked_read_dirs": [
    "C:/Users"
  ],
  "trace_api_calls": false,
  "console_output_to_console": false,
  "unknown_api_policy": "log_zero",
  "max_instructions": 10000000,
  "command_line": "567dbfa9f7d29702a70feb934ec08e54"
}
```

磁盘遍历/擦盘类样本常用补充片段：

```json
{
  "volumes": [
    {
      "host_path": "Sample",
      "guest_path": "D:\\",
      "recursive": true
    },
    {
      "host_path": "Sample",
      "guest_path": "E:\\",
      "recursive": true
    }
  ],
  "environment_overrides": {
    "volume": {
      "physical_drive_count": 10
    }
  }
}
```

当前 `567dbfa9f7d29702a70feb934ec08e54` 就使用这类配置，显式暴露 `PhysicalDrive0..9` 与多卷挂载来验证磁盘遍历行为。

## 输出与日志

一次 `run` 常见会产生以下内容：

- `run.stdout.log`：标准 summary，包含 `instructions`、`exit_code`、`stop_reason`
- `logs/*.api.human.log`：人类可读 API trace
- `logs/*.api.jsonl`：结构化 API 事件流
- `logs/*.console.log`：console 输出
- `sandbox_output_dir/`：文件落地、内存 dump、虚拟文件系统等分析产物

默认输出根目录已经收敛到 `.hvm_hikari_virtual_engine/output`。

`tools/run_samples_config_aware.py` 会把这些路径汇总进 `summary.tsv`，并记录 `elapsed_seconds` 方便做单核基线。脚本主参数已经切换为 `--engine-bin`，同时保留 `--vm-engine` 兼容别名；实际指向的二进制应为 `hvm-hikari-virtual-engine`。

批跑示例：

```bash
taskset -c 0 python3 tools/run_samples_config_aware.py \
  --engine-bin .cargo-target/release/hvm-hikari-virtual-engine \
  --samples-dir Sample \
  --configs-dir configs \
  --output-root run_outputs/hvm_hikari_virtual_engine_20260325_batch \
  --latest-link '' \
  --max-instructions 10000000 \
  --respect-config-max-instructions
```

## 当前样本基线

基于 `2026-03-25` 的单核 `release` 批跑结果，当前 `Sample/` 中 `10` 个样本都已经完成配置化启动并产生日志。批跑产物位于 [`run_outputs/hvm_hikari_virtual_engine_20260325_batch/`](run_outputs/hvm_hikari_virtual_engine_20260325_batch/)，索引文件见 [`summary.tsv`](run_outputs/hvm_hikari_virtual_engine_20260325_batch/summary.tsv)，目录说明见 [`run_outputs/hvm_hikari_virtual_engine_20260325_batch/README.md`](run_outputs/hvm_hikari_virtual_engine_20260325_batch/README.md)。

其中 `567dbfa9f7d29702a70feb934ec08e54` 已切换为磁盘遍历版配置，显式暴露 `10` 个 `PhysicalDrive` 和 `D:` 到 `H:` 的卷映射，用来覆盖物理磁盘与卷 GUID 枚举路径。

其中：

- `7` 个样本输出了完整 `run summary`
- `3` 个样本为 `native_error_with_logs`
- 这 `3` 个样本不是“未运行”，只是 native 阶段提前退出；`summary.tsv` 中的 `effective_instructions` 已自动采用对应 `api.jsonl` 中最后可观测的 `instruction_count`

整体性能统计如下：

- 单样本最大指令数：`50,000,000`
- 单样本最小指令数：`17,247`
- 单样本平均指令数：`8,392,768.30`
- 单样本最大吞吐：`5,235,053.92 instr/s`
- 单样本最小吞吐：`45,267.72 instr/s`
- 单样本平均吞吐：`1,941,444.00 instr/s`

完整样本基线，指令数与吞吐均按 `effective_instructions` 统计：

| 样本 | 样本归属 | 用时(s) | 指令数 | 指令/秒 | 结果 |
| --- | ---: | ---: | ---: | ---: | --- |
| `0a678fc36c23026032a297e48335233d` |`银狐`| `9.854` | `50,000,000` | `5,235,053.92` | `样本内部反调（可能和权限相关后期调整），核心行为未能展现` |
| `18fdde4bf8d3a369514b0bc8ddcf35dc` |`APT-C-60/APT-Q-12`| `7.286` | `10,000,000` | `1,450,116.01` | `关键 IOC 已出现，HTTP URL、下载释放路径等` |
| `23f0eaf307a6d7dd25b1ae85a5a7466b` |`APT-C-60/APT-Q-12`| `0.978` | `5,896,046` | `3,833,965.78` | `C2 已出` |
| `42c4b1eaeba9de5a873970687b4abc34` |`APT-C-60/APT-Q-12`| `1.430` | `6,596,395` | `4,574,546.78` | `C2 IOC 已出现` |
| `567dbfa9f7d29702a70feb934ec08e54` |`未知-硬盘破坏`| `0.385` | `17,247` | `45,267.72` | `磁盘遍历版：已打开并写入 PhysicalDrive0..9，同时枚举多卷 GUID，在磁盘尾部写入0破坏分区表` |
| `58ac2f65e335922be3f60e57099dc8a3` |`APT(DPRK)`| `5.261` | `10,000,000` | `1,980,590.22` | `关键行为 IOC 已出现` |
| `5ccecdd7a28ebb0401cc98e7fd89ba71` |`U盘病毒`| `0.649` | `214,498` | `328,984.66` | `提前退出，但日志可用，可能仍需补参数` |
| `6b8c5c0a43610e7a69a88e805eb1f44b` |`微步下的银狐但内核是CS`| `0.363` | `56,401` | `156,235.46` | `内核 CS 内存自动 dump 已产出` |
| `9b66f94497b13dd05fc6840894374776` |`银狐`| `1.100` | `84,839` | `76,777.38` | `全量日志与 API 轨迹已落盘，可继续追 C2 IP` |
| `e862d56da1077be740ffaa7b5b699675` |`APT(DPRK)`| `0.607` | `1,062,257` | `1,732,902.12` | `API 与 human 日志已产出，可继续追踪 C2 线索` |

已输出完整 summary 的停止原因分布为：

- `instruction_budget_exhausted`: `3`
- `main_thread_terminated`: `2`
- `all_threads_terminated`: `2`

## 路线图

后续优先方向如下：

- 权限管理与虚拟机刺探黑名单的统一建模和管控
- 常见反虚拟机 / 反沙箱探针的黑名单治理
- 引入 ML 驱动的执行序列建模
- 自动化提取 IOC
- 行为输出与报告格式文档化
- 对接 IDA / Binary Ninja 辅助分析
