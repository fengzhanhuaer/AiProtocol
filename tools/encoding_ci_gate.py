#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class GateError(Exception):
    pass


@dataclass
class Policy:
    default_encoding: str
    rules: List[Dict[str, str]]
    exclude: List[str]


def read_json_utf8(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GateError(f"json file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise GateError(f"json file must be utf-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"invalid json: {path}: {exc}") from exc


def load_policy(path: Path) -> Policy:
    obj = read_json_utf8(path)
    if not isinstance(obj, dict):
        raise GateError("policy root must be an object")

    default_encoding = obj.get("default_encoding", "utf-8")
    rules = obj.get("rules", [])
    exclude = obj.get("exclude", [])

    if not isinstance(default_encoding, str) or not default_encoding:
        raise GateError("policy.default_encoding must be non-empty string")
    if not isinstance(rules, list):
        raise GateError("policy.rules must be an array")
    if not isinstance(exclude, list):
        raise GateError("policy.exclude must be an array")

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise GateError(f"policy.rules[{i}] must be an object")
        if not isinstance(rule.get("glob"), str) or not rule["glob"]:
            raise GateError(f"policy.rules[{i}].glob must be non-empty string")
        if not isinstance(rule.get("encoding"), str) or not rule["encoding"]:
            raise GateError(f"policy.rules[{i}].encoding must be non-empty string")

    for i, pattern in enumerate(exclude):
        if not isinstance(pattern, str) or not pattern:
            raise GateError(f"policy.exclude[{i}] must be non-empty string")

    return Policy(default_encoding=default_encoding, rules=rules, exclude=exclude)


def match_glob(rel_posix: str, pattern: str) -> bool:
    name = rel_posix.split("/")[-1]
    return fnmatch(rel_posix, pattern) or fnmatch(name, pattern)


def is_excluded(rel_path: Path, policy: Policy) -> bool:
    rel_posix = rel_path.as_posix()
    return any(match_glob(rel_posix, pattern) for pattern in policy.exclude)


def resolve_encoding(rel_path: Path, policy: Policy) -> str:
    rel_posix = rel_path.as_posix()
    for rule in policy.rules:
        if match_glob(rel_posix, rule["glob"]):
            return rule["encoding"]
    return policy.default_encoding


def to_relative(root: Path, path: Path) -> Path:
    abs_path = path.resolve()
    try:
        return abs_path.relative_to(root)
    except ValueError as exc:
        raise GateError(f"path escapes workspace: {path}") from exc


def collect_scan_files(root: Path, scan_paths: Iterable[str], policy: Policy) -> List[Path]:
    out: List[Path] = []

    for raw in scan_paths:
        p = Path(raw)
        abs_path = (root / p).resolve() if not p.is_absolute() else p.resolve()

        if not abs_path.exists():
            raise GateError(f"scan path not found: {raw}")

        rel_root = to_relative(root, abs_path)
        if is_excluded(rel_root, policy):
            continue

        if abs_path.is_file():
            out.append(rel_root)
            continue

        if abs_path.is_dir():
            for child in abs_path.rglob("*"):
                if not child.is_file():
                    continue
                rel_child = to_relative(root, child)
                if is_excluded(rel_child, policy):
                    continue
                out.append(rel_child)
            continue

    unique = {p.as_posix(): p for p in out}
    return [unique[key] for key in sorted(unique.keys())]


def decode_error(path: Path, encoding: str) -> Optional[str]:
    try:
        _ = path.read_bytes().decode(encoding)
        return None
    except UnicodeDecodeError as exc:
        return f"decode failed with encoding={encoding}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CI encoding gate: verify file bytes can be decoded by expected encoding policy."
    )
    parser.add_argument("--policy", default="tools/encoding-policy.json", help="encoding policy json path")
    parser.add_argument("--paths", nargs="+", default=["."], help="scan paths under workspace")
    parser.add_argument("--report", default=None, help="optional json report path")
    parser.add_argument("--fail-on-empty", action="store_true", help="fail when zero files scanned")
    args = parser.parse_args()

    root = Path.cwd().resolve()
    policy_path = (root / args.policy).resolve()
    policy = load_policy(policy_path)

    files = collect_scan_files(root, args.paths, policy)

    checked = 0
    failures: List[Dict[str, str]] = []

    for rel_path in files:
        expected = resolve_encoding(rel_path, policy)
        abs_path = root / rel_path
        checked += 1
        err = decode_error(abs_path, expected)
        if err is not None:
            failures.append(
                {
                    "path": rel_path.as_posix(),
                    "expected_encoding": expected,
                    "error": err,
                }
            )

    status = "ok"
    exit_code = 0

    if checked == 0 and args.fail_on_empty:
        status = "failed"
        exit_code = 2

    if failures:
        status = "failed"
        exit_code = 1

    payload: Dict[str, Any] = {
        "status": status,
        "policy": args.policy,
        "paths": args.paths,
        "checked_files": checked,
        "failed_files": len(failures),
        "failures": failures,
    }

    if args.report:
        report_path = (root / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[encoding-ci-gate] checked={checked} failed={len(failures)} status={status}")

    if checked == 0 and args.fail_on_empty:
        print("[encoding-ci-gate] ERROR: no files scanned and --fail-on-empty is enabled", file=sys.stderr)

    if failures:
        print("[encoding-ci-gate] failed files:", file=sys.stderr)
        for item in failures:
            print(
                f"  - {item['path']} expected={item['expected_encoding']} | {item['error']}",
                file=sys.stderr,
            )

    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"[encoding-ci-gate] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
