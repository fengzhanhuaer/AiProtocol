#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class PatchError(Exception):
    pass


@dataclass
class Policy:
    default_encoding: str
    rules: List[Dict[str, str]]
    exclude: List[str]


@dataclass
class PreparedPatch:
    rel_path: Path
    abs_path: Path
    encoding: str
    newline_name: str
    original_bytes: bytes
    new_bytes: bytes
    operation_reports: List[Dict[str, Any]]


def now_tag() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def read_json_utf8(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PatchError(f"json file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise PatchError(f"json file must be utf-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PatchError(f"invalid json: {path}: {exc}") from exc


def load_policy(path: Path) -> Policy:
    obj = read_json_utf8(path)
    if not isinstance(obj, dict):
        raise PatchError("policy root must be an object")

    default_encoding = obj.get("default_encoding", "utf-8")
    rules = obj.get("rules", [])
    exclude = obj.get("exclude", [])

    if not isinstance(default_encoding, str) or not default_encoding:
        raise PatchError("policy.default_encoding must be non-empty string")
    if not isinstance(rules, list):
        raise PatchError("policy.rules must be an array")
    if not isinstance(exclude, list):
        raise PatchError("policy.exclude must be an array")

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PatchError(f"policy.rules[{i}] must be an object")
        if not isinstance(rule.get("glob"), str) or not rule["glob"]:
            raise PatchError(f"policy.rules[{i}].glob must be non-empty string")
        if not isinstance(rule.get("encoding"), str) or not rule["encoding"]:
            raise PatchError(f"policy.rules[{i}].encoding must be non-empty string")

    for i, pat in enumerate(exclude):
        if not isinstance(pat, str) or not pat:
            raise PatchError(f"policy.exclude[{i}] must be non-empty string")

    return Policy(default_encoding=default_encoding, rules=rules, exclude=exclude)


def to_relative_path(root: Path, raw_path: str) -> Path:
    p = Path(raw_path)
    if p.is_absolute():
        raise PatchError(f"path must be workspace-relative: {raw_path}")
    abs_path = (root / p).resolve()
    try:
        rel = abs_path.relative_to(root)
    except ValueError as exc:
        raise PatchError(f"path escapes workspace: {raw_path}") from exc
    return rel


def match_glob(rel_posix: str, pattern: str) -> bool:
    name = rel_posix.split("/")[-1]
    return fnmatch(rel_posix, pattern) or fnmatch(name, pattern)


def resolve_encoding(rel_path: Path, policy: Policy, explicit_encoding: Optional[str]) -> str:
    if explicit_encoding:
        return explicit_encoding
    rel_posix = rel_path.as_posix()
    for rule in policy.rules:
        if match_glob(rel_posix, rule["glob"]):
            return rule["encoding"]
    return policy.default_encoding


def detect_newline(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\n" in text:
        return "\n"
    if "\r" in text:
        return "\r"
    return "\n"


def newline_label(newline: str) -> str:
    if newline == "\r\n":
        return "CRLF"
    if newline == "\r":
        return "CR"
    return "LF"


def normalize_text_newline(value: str, newline: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", newline)


def op_replace(text: str, search: str, replace: str, count: int) -> Tuple[str, Dict[str, int]]:
    hits = text.count(search)
    if hits == 0:
        raise PatchError(f"replace not found: {search!r}")
    if count <= 0:
        new_text = text.replace(search, replace)
        applied = hits
    else:
        new_text = text.replace(search, replace, count)
        applied = min(hits, count)
    return new_text, {"hits": hits, "applied": applied}


def op_delete(text: str, search: str, count: int) -> Tuple[str, Dict[str, int]]:
    return op_replace(text, search, "", count)


def op_insert(text: str, anchor: str, content: str, count: int, after: bool) -> Tuple[str, Dict[str, int]]:
    total_hits = text.count(anchor)
    if total_hits == 0:
        raise PatchError(f"insert anchor not found: {anchor!r}")

    if count <= 0:
        count = total_hits

    applied = 0
    cursor = 0
    out: List[str] = []

    while True:
        idx = text.find(anchor, cursor)
        if idx < 0:
            out.append(text[cursor:])
            break

        if applied >= count:
            out.append(text[cursor:])
            break

        end = idx + len(anchor)
        if after:
            out.append(text[cursor:end])
            out.append(content)
        else:
            out.append(text[cursor:idx])
            out.append(content)
            out.append(anchor)

        cursor = end
        applied += 1

    if applied == 0:
        raise PatchError("insert operation applied zero times")

    return "".join(out), {"hits": total_hits, "applied": applied}


def run_operation(text: str, operation: Dict[str, Any], newline: str) -> Tuple[str, Dict[str, Any]]:
    op_type = operation.get("op")
    if not isinstance(op_type, str) or not op_type:
        raise PatchError("operation.op must be non-empty string")

    count = operation.get("count", 1)
    if not isinstance(count, int):
        raise PatchError(f"operation.count must be integer for op={op_type}")

    if op_type == "replace":
        search = operation.get("search")
        replace = operation.get("replace")
        if not isinstance(search, str) or not isinstance(replace, str):
            raise PatchError("replace requires string fields: search, replace")
        replace = normalize_text_newline(replace, newline)
        new_text, stats = op_replace(text, search, replace, count)
    elif op_type == "delete":
        search = operation.get("search")
        if not isinstance(search, str):
            raise PatchError("delete requires string field: search")
        new_text, stats = op_delete(text, search, count)
    elif op_type in ("insert_before", "insert_after"):
        anchor = operation.get("anchor")
        content = operation.get("content")
        if not isinstance(anchor, str) or not isinstance(content, str):
            raise PatchError(f"{op_type} requires string fields: anchor, content")
        content = normalize_text_newline(content, newline)
        new_text, stats = op_insert(text, anchor, content, count, after=(op_type == "insert_after"))
    else:
        raise PatchError(f"unsupported operation: {op_type}")

    expected = operation.get("expect")
    if expected is not None:
        if not isinstance(expected, int):
            raise PatchError(f"operation.expect must be integer for op={op_type}")
        if stats["applied"] != expected:
            raise PatchError(
                f"operation applied count mismatch for op={op_type}: expected={expected}, actual={stats['applied']}"
            )

    report: Dict[str, Any] = {
        "op": op_type,
        "hits": stats["hits"],
        "applied": stats["applied"],
    }
    return new_text, report


def prepare_patch(root: Path, item: Dict[str, Any], policy: Policy) -> PreparedPatch:
    raw_path = item.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise PatchError("item.path must be non-empty string")

    rel_path = to_relative_path(root, raw_path)
    abs_path = root / rel_path

    if not abs_path.exists() or not abs_path.is_file():
        raise PatchError(f"target file not found: {rel_path.as_posix()}")

    explicit_encoding = item.get("encoding")
    if explicit_encoding is not None and (not isinstance(explicit_encoding, str) or not explicit_encoding):
        raise PatchError(f"item.encoding invalid: {rel_path.as_posix()}")

    encoding = resolve_encoding(rel_path, policy, explicit_encoding)
    original_bytes = abs_path.read_bytes()

    try:
        text = original_bytes.decode(encoding)
    except UnicodeDecodeError as exc:
        raise PatchError(f"decode failed: path={rel_path.as_posix()} encoding={encoding}: {exc}") from exc

    operations = item.get("operations")
    if not isinstance(operations, list) or not operations:
        raise PatchError(f"item.operations must be non-empty array: {rel_path.as_posix()}")

    newline = detect_newline(text)
    next_text = text
    operation_reports: List[Dict[str, Any]] = []

    for idx, op in enumerate(operations):
        if not isinstance(op, dict):
            raise PatchError(f"operation[{idx}] must be object: {rel_path.as_posix()}")
        next_text, report = run_operation(next_text, op, newline)
        report["index"] = idx
        operation_reports.append(report)

    try:
        new_bytes = next_text.encode(encoding)
    except UnicodeEncodeError as exc:
        raise PatchError(f"encode failed: path={rel_path.as_posix()} encoding={encoding}: {exc}") from exc

    return PreparedPatch(
        rel_path=rel_path,
        abs_path=abs_path,
        encoding=encoding,
        newline_name=newline_label(newline),
        original_bytes=original_bytes,
        new_bytes=new_bytes,
        operation_reports=operation_reports,
    )


def save_report(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def relative_or_str(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Encoding-safe patch tool. "
            "Supports replace/insert/delete with explicit encoding and dry-run/apply modes."
        )
    )
    parser.add_argument("--config", required=True, help="utf-8 json patch config path")
    parser.add_argument("--policy", default=None, help="encoding policy json path")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run", help="execution mode")
    parser.add_argument("--report", default=None, help="json report output path")
    parser.add_argument("--backup-root", default=".encoding_patch_backups", help="backup root for apply mode")
    args = parser.parse_args()

    root = Path.cwd().resolve()
    config_path = (root / args.config).resolve()
    config_obj = read_json_utf8(config_path)
    if not isinstance(config_obj, dict):
        raise PatchError("patch config root must be object")

    policy_ref = args.policy or config_obj.get("policy") or "tools/encoding-policy.json"
    if not isinstance(policy_ref, str) or not policy_ref:
        raise PatchError("policy path must be non-empty string")
    policy_path = (root / policy_ref).resolve()
    policy = load_policy(policy_path)

    items = config_obj.get("items")
    if not isinstance(items, list) or not items:
        raise PatchError("config.items must be non-empty array")

    prepared: List[PreparedPatch] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise PatchError(f"config.items[{i}] must be object")
        prepared.append(prepare_patch(root, item, policy))

    backup_root = (root / args.backup_root).resolve()
    backup_dir = backup_root / now_tag()

    changed_count = 0
    file_reports: List[Dict[str, Any]] = []

    for patch in prepared:
        changed = patch.original_bytes != patch.new_bytes
        if changed:
            changed_count += 1
            if args.mode == "apply":
                backup_path = backup_dir / patch.rel_path
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                backup_path.write_bytes(patch.original_bytes)
                patch.abs_path.write_bytes(patch.new_bytes)

        file_reports.append(
            {
                "path": patch.rel_path.as_posix(),
                "encoding": patch.encoding,
                "newline": patch.newline_name,
                "changed": changed,
                "bytes_before": len(patch.original_bytes),
                "bytes_after": len(patch.new_bytes),
                "operations": patch.operation_reports,
            }
        )

    if args.report:
        report_path = (root / args.report).resolve()
    else:
        report_path = (root / f".encoding_patch_reports/{args.mode}-{now_tag()}.json").resolve()

    payload: Dict[str, Any] = {
        "mode": args.mode,
        "config": relative_or_str(root, config_path),
        "policy": relative_or_str(root, policy_path),
        "total_files": len(prepared),
        "changed_files": changed_count,
        "backup_dir": relative_or_str(root, backup_dir) if args.mode == "apply" else None,
        "files": file_reports,
    }

    save_report(report_path, payload)

    print(f"[encoding-safe-patch] mode={args.mode} total={len(prepared)} changed={changed_count}")
    print(f"[encoding-safe-patch] report={relative_or_str(root, report_path)}")
    if args.mode == "apply":
        print(f"[encoding-safe-patch] backup={relative_or_str(root, backup_dir)}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PatchError as exc:
        print(f"[encoding-safe-patch] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
