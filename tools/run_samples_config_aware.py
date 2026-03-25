#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_SEARCH_PATHS = [
    "Sample",
    "C:/Windows/System32",
    "C:/Windows/SysWOW64",
]
DEFAULT_BLOCKED_READ_DIRS = ["C:/Users"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run all samples in a config-aware mode that reuses stable sample configs when available."
    )
    parser.add_argument(
        "--engine-bin",
        "--vm-engine",
        dest="engine_bin",
        default=".cargo-target/release/hvm-hikari-virtual-engine",
        help="Path to the HVM-Hikari Virtual Engine binary.",
    )
    parser.add_argument(
        "--samples-dir",
        default="Sample",
        help="Directory containing the sample corpus.",
    )
    parser.add_argument(
        "--configs-dir",
        default="configs",
        help="Directory containing stable JSON configs.",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        help="Directory for per-sample outputs. Defaults to .hvm_hikari_virtual_engine/all_samples_configaware_<timestamp>.",
    )
    parser.add_argument(
        "--latest-link",
        default=".hvm_hikari_virtual_engine/all_samples_configaware_latest",
        help="Symlink updated to point at the latest output root. Use an empty string to disable.",
    )
    parser.add_argument(
        "--max-instructions",
        type=int,
        default=10_000_000,
        help="Instruction budget override applied to each generated run config.",
    )
    parser.add_argument(
        "--respect-config-max-instructions",
        action="store_true",
        help="Keep max_instructions from stable configs when present; only fall back to --max-instructions when absent.",
    )
    parser.add_argument(
        "--prefer-substring",
        action="append",
        default=["trace"],
        help="Prefer configs whose filename contains this substring. Can be specified multiple times.",
    )
    parser.add_argument(
        "--sample",
        action="append",
        default=[],
        help="Only run samples whose file name contains this substring. Can be specified multiple times.",
    )
    return parser.parse_args()


def resolve_like_python(base_dir: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate.resolve()
    return (base_dir / candidate).resolve()


def project_base_for_config(config_path: Path) -> Path:
    return config_path.parent.parent if config_path.parent.parent else config_path.parent


def sanitize_name(name: str) -> str:
    cleaned = []
    for char in name:
        if char.isalnum() or char in {".", "_", "-"}:
            cleaned.append(char)
        else:
            cleaned.append("_")
    return "".join(cleaned).strip("._") or "sample"


def config_score(name: str, prefer_substrings: list[str]) -> int:
    lowered = name.lower()
    score = 0
    for index, token in enumerate(prefer_substrings):
        token = token.strip().lower()
        if token and token in lowered:
            score += 1000 - index * 100
    if lowered.startswith("sample_"):
        score += 100
    if "debug" not in lowered:
        score += 25
    if "perf" not in lowered:
        score += 10
    return score


def load_config_candidates(configs_dir: Path, prefer_substrings: list[str]) -> dict[Path, list[tuple[int, Path, dict]]]:
    candidates: dict[Path, list[tuple[int, Path, dict]]] = {}
    for config_path in sorted(configs_dir.glob("*.json")):
        if config_path.name.startswith(".tmp_"):
            continue
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[warn] skip invalid config {config_path}: {exc}", file=sys.stderr)
            continue
        main_module = raw.get("main_module")
        if not isinstance(main_module, str) or not main_module.strip():
            continue
        resolved_main = resolve_like_python(project_base_for_config(config_path), main_module)
        candidates.setdefault(resolved_main, []).append(
            (config_score(config_path.name, prefer_substrings), config_path, raw)
        )
    for resolved_main, items in candidates.items():
        items.sort(key=lambda item: (-item[0], item[1].name))
        if len(items) > 1:
            chosen = items[0][1].name
            ignored = ", ".join(path.name for _, path, _ in items[1:])
            print(
                f"[info] multiple configs for {resolved_main.name}: using {chosen}; ignored {ignored}",
                file=sys.stderr,
            )
    return candidates


def make_generic_config(sample_path: Path) -> dict:
    sample_name = sample_path.name
    return {
        "main_module": str(Path("Sample") / sample_name),
        "module_search_paths": DEFAULT_SEARCH_PATHS,
        "allowed_read_dirs": DEFAULT_SEARCH_PATHS,
        "blocked_read_dirs": DEFAULT_BLOCKED_READ_DIRS,
        "trace_api_calls": True,
        "api_log_to_console": False,
        "api_log_include_return": True,
        "api_log_string_limit": 512,
        "console_output_to_console": False,
        "unknown_api_policy": "log_zero",
        "command_line": sample_name,
    }


def overlay_runtime_outputs(
    config: dict,
    sample_output_dir: Path,
    max_instructions: int,
    respect_config_max_instructions: bool,
) -> dict:
    config = copy.deepcopy(config)
    logs_dir = sample_output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    sandbox_dir = sample_output_dir / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    sample_name = sample_output_dir.name
    config["sandbox_output_dir"] = str(sandbox_dir.resolve())
    config["api_log_path"] = str((logs_dir / f"{sample_name}.api.log").resolve())
    config["api_jsonl_path"] = str((logs_dir / f"{sample_name}.api.jsonl").resolve())
    config["api_human_log_path"] = str((logs_dir / f"{sample_name}.api.human.log").resolve())
    config["console_output_path"] = str((logs_dir / f"{sample_name}.console.log").resolve())
    existing_max = config.get("max_instructions")
    if respect_config_max_instructions and isinstance(existing_max, int) and existing_max > 0:
        config["max_instructions"] = existing_max
    else:
        config["max_instructions"] = max_instructions
    if not config.get("command_line"):
        config["command_line"] = sample_name
    if "trace_api_calls" not in config:
        config["trace_api_calls"] = True
    if "api_log_to_console" not in config:
        config["api_log_to_console"] = False
    if "api_log_include_return" not in config:
        config["api_log_include_return"] = True
    if "api_log_string_limit" not in config:
        config["api_log_string_limit"] = 512
    if "console_output_to_console" not in config:
        config["console_output_to_console"] = False
    if "unknown_api_policy" not in config:
        config["unknown_api_policy"] = "log_zero"
    return config


def parse_run_summary(stdout: str) -> dict[str, str]:
    summary: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        summary[key.strip()] = value.strip()
    return summary


def last_observed_instruction_count(api_jsonl_path: Path) -> int | None:
    if not api_jsonl_path.exists():
        return None
    last_count: int | None = None
    with api_jsonl_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            instruction_count = event.get("instruction_count")
            if isinstance(instruction_count, int):
                last_count = instruction_count
    return last_count


def ensure_latest_link(link_path: Path, target: Path) -> None:
    if not link_path:
        return
    if link_path.is_symlink() or link_path.exists():
        link_path.unlink()
    link_path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target.resolve(), link_path)


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    engine_bin = (repo_root / args.engine_bin).resolve()
    samples_dir = (repo_root / args.samples_dir).resolve()
    configs_dir = (repo_root / args.configs_dir).resolve()
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    output_root = (
        Path(args.output_root).resolve()
        if args.output_root
        else (repo_root / ".hvm_hikari_virtual_engine" / f"all_samples_configaware_{timestamp}").resolve()
    )
    latest_link = Path(args.latest_link).resolve() if args.latest_link else None

    if not engine_bin.exists():
        print(f"engine binary not found: {engine_bin}", file=sys.stderr)
        return 1
    if not samples_dir.is_dir():
        print(f"samples directory not found: {samples_dir}", file=sys.stderr)
        return 1
    if not configs_dir.is_dir():
        print(f"configs directory not found: {configs_dir}", file=sys.stderr)
        return 1

    output_root.mkdir(parents=True, exist_ok=True)
    config_candidates = load_config_candidates(configs_dir, args.prefer_substring)
    summary_rows = [
        [
            "sample",
            "status",
            "config_source",
            "stable_config",
            "run_config",
            "sample_output_dir",
            "elapsed_seconds",
            "instructions",
            "effective_instructions",
            "exit_code",
            "stop_reason",
            "result_kind",
            "max_instructions",
            "stdout_log",
            "stderr_log",
            "api_jsonl_log",
            "api_human_log",
            "console_log",
            "sandbox_output_dir",
        ]
    ]

    samples = sorted(path for path in samples_dir.iterdir() if path.is_file())
    if args.sample:
        tokens = [token.lower() for token in args.sample]
        samples = [
            path
            for path in samples
            if any(token in path.name.lower() for token in tokens)
        ]

    for sample_path in samples:
        stable_candidates = config_candidates.get(sample_path.resolve(), [])
        stable_config_path = stable_candidates[0][1] if stable_candidates else None
        config_source = "stable" if stable_config_path else "generated"
        base_config = stable_candidates[0][2] if stable_candidates else make_generic_config(sample_path)

        sample_slug = sanitize_name(sample_path.name)
        sample_output_dir = output_root / sample_slug
        sample_output_dir.mkdir(parents=True, exist_ok=True)
        runtime_config = overlay_runtime_outputs(
            base_config,
            sample_output_dir,
            args.max_instructions,
            args.respect_config_max_instructions,
        )
        preserved_config_path = sample_output_dir / "run.config.json"
        preserved_config_path.write_text(
            json.dumps(runtime_config, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        runtime_config_path = configs_dir / f".tmp_config_aware_{sample_slug}_{timestamp}.json"
        stdout_log = sample_output_dir / "run.stdout.log"
        stderr_log = sample_output_dir / "run.stderr.log"

        runtime_config_path.write_text(
            json.dumps(runtime_config, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            f"[run] sample={sample_path.name} mode={config_source} config={stable_config_path or '<generated>'}",
            file=sys.stderr,
        )
        started_at = time.perf_counter()
        completed = subprocess.run(
            [str(engine_bin), "run", "--config", str(runtime_config_path)],
            cwd=repo_root,
            text=True,
            capture_output=True,
        )
        elapsed_seconds = time.perf_counter() - started_at
        stdout_log.write_text(completed.stdout, encoding="utf-8")
        stderr_log.write_text(completed.stderr, encoding="utf-8")
        summary = parse_run_summary(completed.stdout)
        api_jsonl_path = Path(runtime_config.get("api_jsonl_path", ""))
        raw_instructions = summary.get("instructions", "")
        effective_instructions = raw_instructions
        fallback_instruction_count = None
        if not effective_instructions and api_jsonl_path:
            fallback_instruction_count = last_observed_instruction_count(api_jsonl_path)
            if fallback_instruction_count is not None:
                effective_instructions = str(fallback_instruction_count)
        status = "ok" if completed.returncode == 0 else f"error:{completed.returncode}"
        if completed.returncode == 0:
            result_kind = "summary"
        elif fallback_instruction_count is not None:
            result_kind = "native_error_with_logs"
        else:
            result_kind = "error"
        summary_rows.append(
            [
                sample_path.name,
                status,
                config_source,
                str(stable_config_path.resolve()) if stable_config_path else "",
                str(preserved_config_path.resolve()),
                str(sample_output_dir.resolve()),
                f"{elapsed_seconds:.3f}",
                raw_instructions,
                effective_instructions,
                summary.get("exit_code", ""),
                summary.get("stop_reason", ""),
                result_kind,
                str(runtime_config.get("max_instructions", "")),
                str(stdout_log.resolve()),
                str(stderr_log.resolve()),
                runtime_config.get("api_jsonl_path", ""),
                runtime_config.get("api_human_log_path", ""),
                runtime_config.get("console_output_path", ""),
                runtime_config.get("sandbox_output_dir", ""),
            ]
        )
        runtime_config_path.unlink(missing_ok=True)

    summary_path = output_root / "summary.tsv"
    with summary_path.open("w", encoding="utf-8") as handle:
        for row in summary_rows:
            handle.write("\t".join(row))
            handle.write("\n")

    if latest_link is not None:
        ensure_latest_link(latest_link, output_root)

    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
