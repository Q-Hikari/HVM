# HVM-Hikari Virtual Engine Batch Output

这批目录对应 `2026-03-25` 的单核 `release` 全量批跑结果，已经覆盖原有同名目录数据。

## 运行命令

```bash
taskset -c 0 python3 tools/run_samples_config_aware.py \
  --engine-bin .cargo-target/release/hvm-hikari-virtual-engine \
  --samples-dir Sample \
  --configs-dir configs \
  --output-root /home/dev/Vm_Eng_Scan/run_outputs/hvm_hikari_virtual_engine_20260325_batch \
  --latest-link '' \
  --max-instructions 10000000 \
  --respect-config-max-instructions
```

## 结果概览

- 样本总数：`10`
- `summary`：`7`
- `native_error_with_logs`：`3`
- 目录大小：`220M`
- 文件总数：`78`
- 最大指令数：`50,000,000`
- 最小指令数：`17,247`
- 平均指令数：`8,392,768.30`
- 最大吞吐：`6,028,676.89 instr/s`
- 最小吞吐：`44,797.40 instr/s`
- 平均吞吐：`2,134,671.20 instr/s`

补充说明：

- `effective_instructions` 已统一用于统计；对 `native_error_with_logs` 样本，会回退到 `api.jsonl` 中最后可观测的指令数。
- `567dbfa9f7d29702a70feb934ec08e54` 仍使用磁盘遍历版配置，暴露 `PhysicalDrive0..9` 和多卷挂载。

## 目录说明

- [`summary.tsv`](./summary.tsv)：批跑总索引，记录状态、耗时、指令数和日志路径。
- 每个样本目录下固定包含 `run.config.json`、`run.stdout.log`、`run.stderr.log`、`logs/`、`sandbox/`。
- `logs/` 下包含 `.api.log`、`.api.jsonl`、`.api.human.log`、`.console.log`。

## 样本索引

| 样本 | 状态 | 用时(s) | 指令数 | 指令/秒 | 目录 | human log |
| --- | --- | ---: | ---: | ---: | --- | --- |
| `0a678fc36c23026032a297e48335233d` | `ok / summary` | `9.854` | `50,000,000` | `5,074,081.59` | [dir](./0a678fc36c23026032a297e48335233d/) / [config](./0a678fc36c23026032a297e48335233d/run.config.json) | [human](./0a678fc36c23026032a297e48335233d/logs/0a678fc36c23026032a297e48335233d.api.human.log) |
| `18fdde4bf8d3a369514b0bc8ddcf35dc` | `ok / summary` | `7.286` | `10,000,000` | `1,372,495.20` | [dir](./18fdde4bf8d3a369514b0bc8ddcf35dc/) / [config](./18fdde4bf8d3a369514b0bc8ddcf35dc/run.config.json) | [human](./18fdde4bf8d3a369514b0bc8ddcf35dc/logs/18fdde4bf8d3a369514b0bc8ddcf35dc.api.human.log) |
| `23f0eaf307a6d7dd25b1ae85a5a7466b` | `ok / summary` | `0.978` | `5,896,046` | `6,028,676.89` | [dir](./23f0eaf307a6d7dd25b1ae85a5a7466b/) / [config](./23f0eaf307a6d7dd25b1ae85a5a7466b/run.config.json) | [human](./23f0eaf307a6d7dd25b1ae85a5a7466b/logs/23f0eaf307a6d7dd25b1ae85a5a7466b.api.human.log) |
| `42c4b1eaeba9de5a873970687b4abc34` | `ok / summary` | `1.430` | `6,596,395` | `4,612,863.64` | [dir](./42c4b1eaeba9de5a873970687b4abc34/) / [config](./42c4b1eaeba9de5a873970687b4abc34/run.config.json) | [human](./42c4b1eaeba9de5a873970687b4abc34/logs/42c4b1eaeba9de5a873970687b4abc34.api.human.log) |
| `567dbfa9f7d29702a70feb934ec08e54` | `ok / summary` | `0.385` | `17,247` | `44,797.40` | [dir](./567dbfa9f7d29702a70feb934ec08e54/) / [config](./567dbfa9f7d29702a70feb934ec08e54/run.config.json) | [human](./567dbfa9f7d29702a70feb934ec08e54/logs/567dbfa9f7d29702a70feb934ec08e54.api.human.log) |
| `58ac2f65e335922be3f60e57099dc8a3` | `ok / summary` | `5.261` | `10,000,000` | `1,900,779.32` | [dir](./58ac2f65e335922be3f60e57099dc8a3/) / [config](./58ac2f65e335922be3f60e57099dc8a3/run.config.json) | [human](./58ac2f65e335922be3f60e57099dc8a3/logs/58ac2f65e335922be3f60e57099dc8a3.api.human.log) |
| `5ccecdd7a28ebb0401cc98e7fd89ba71` | `error:1 / native_error_with_logs` | `0.649` | `214,498` | `330,505.39` | [dir](./5ccecdd7a28ebb0401cc98e7fd89ba71/) / [config](./5ccecdd7a28ebb0401cc98e7fd89ba71/run.config.json) | [human](./5ccecdd7a28ebb0401cc98e7fd89ba71/logs/5ccecdd7a28ebb0401cc98e7fd89ba71.api.human.log) |
| `6b8c5c0a43610e7a69a88e805eb1f44b` | `ok / summary` | `0.363` | `56,401` | `155,374.66` | [dir](./6b8c5c0a43610e7a69a88e805eb1f44b/) / [config](./6b8c5c0a43610e7a69a88e805eb1f44b/run.config.json) | [human](./6b8c5c0a43610e7a69a88e805eb1f44b/logs/6b8c5c0a43610e7a69a88e805eb1f44b.api.human.log) |
| `9b66f94497b13dd05fc6840894374776` | `error:1 / native_error_with_logs` | `1.100` | `84,839` | `77,126.36` | [dir](./9b66f94497b13dd05fc6840894374776/) / [config](./9b66f94497b13dd05fc6840894374776/run.config.json) | [human](./9b66f94497b13dd05fc6840894374776/logs/9b66f94497b13dd05fc6840894374776.api.human.log) |
| `e862d56da1077be740ffaa7b5b699675` | `error:1 / native_error_with_logs` | `0.607` | `1,062,257` | `1,750,011.53` | [dir](./e862d56da1077be740ffaa7b5b699675/) / [config](./e862d56da1077be740ffaa7b5b699675/run.config.json) | [human](./e862d56da1077be740ffaa7b5b699675/logs/e862d56da1077be740ffaa7b5b699675.api.human.log) |
