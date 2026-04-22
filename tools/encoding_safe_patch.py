#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from encoding_policy_core import (
        BOM_CHOICES,
        NEWLINE_CHOICES,
        NEWLINE_LF,
        NEWLINE_NONE,
        Policy,
        PolicyError,
        apply_bom,
        decode_text,
        detect_newline,
        encode_text,
        enforce_newline_policy,
        load_policy,
        normalize_text_newline,
        normalize_workspace_path,
        relative_or_str,
        resolve_spec,
    )
except ModuleNotFoundError:
    from tools.encoding_policy_core import (
        BOM_CHOICES,
        NEWLINE_CHOICES,
        NEWLINE_LF,
        NEWLINE_NONE,
        Policy,
        PolicyError,
        apply_bom,
        decode_text,
        detect_newline,
        encode_text,
        enforce_newline_policy,
        load_policy,
        normalize_text_newline,
        normalize_workspace_path,
        relative_or_str,
        resolve_spec,
    )


class PatchError(Exception):
    pass


@dataclass
class PreparedPatch:
    rel_path: Path
    abs_path: Path
    encoding: str
    matched_glob: Optional[str]
    bom: str
    newline_policy: str
    detected_newline: str
    original_had_utf8_bom: bool
    original_bytes: bytes
    new_bytes: bytes
    original_text: str
    new_text: str
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



def _normalize_bom(value: Optional[str], field: str) -> str:
    if value is None:
        return "preserve"
    if not isinstance(value, str):
        raise PatchError(f"{field} must be string")
    norm = value.strip().lower()
    if norm not in BOM_CHOICES:
        raise PatchError(f"{field} must be one of {sorted(BOM_CHOICES)}")
    return norm



def _normalize_newline(value: Optional[str], field: str) -> str:
    if value is None:
        return "preserve"
    if not isinstance(value, str):
        raise PatchError(f"{field} must be string")
    norm = value.strip().lower()
    if norm not in NEWLINE_CHOICES:
        raise PatchError(f"{field} must be one of {sorted(NEWLINE_CHOICES)}")
    return norm



def _count_occurrence(text: str, token: str) -> int:
    if token == "":
        return 0
    return text.count(token)



def op_replace(text: str, search: str, replace: str, count: int) -> Tuple[str, Dict[str, int]]:
    hits = _count_occurrence(text, search)
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
    total_hits = _count_occurrence(text, anchor)
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



def _parse_regex_flags(flags: str) -> int:
    mask = 0
    for ch in flags:
        if ch in ("i", "I"):
            mask |= re.IGNORECASE
        elif ch in ("m", "M"):
            mask |= re.MULTILINE
        elif ch in ("s", "S"):
            mask |= re.DOTALL
        elif ch in ("x", "X"):
            mask |= re.VERBOSE
        else:
            raise PatchError(f"unsupported regex flag: {ch}")
    return mask



def op_regex_replace(text: str, pattern: str, replace: str, count: int, flags: str) -> Tuple[str, Dict[str, int]]:
    try:
        compiled = re.compile(pattern, _parse_regex_flags(flags))
    except re.error as exc:
        raise PatchError(f"invalid regex pattern: {pattern!r}: {exc}") from exc

    hits = len(list(compiled.finditer(text)))
    if hits == 0:
        raise PatchError(f"regex_replace not found: {pattern!r}")

    use_count = 0 if count <= 0 else count
    new_text, applied = compiled.subn(replace, text, count=use_count)
    return new_text, {"hits": hits, "applied": applied}



def op_line_replace(
    text: str,
    search: str,
    replace: str,
    count: int,
    line_no: Optional[int],
    line_anchor: Optional[str],
) -> Tuple[str, Dict[str, int]]:
    lines = text.splitlines(keepends=True)
    if not lines:
        raise PatchError("line_replace target text is empty")

    targets: List[int] = []
    if line_no is not None:
        if line_no <= 0:
            raise PatchError("line_replace.line_no must be >= 1")
        idx = line_no - 1
        if idx >= len(lines):
            raise PatchError(f"line_replace.line_no out of range: {line_no}")
        targets.append(idx)
    elif line_anchor is not None:
        for i, line in enumerate(lines):
            if line_anchor in line:
                targets.append(i)
        if not targets:
            raise PatchError(f"line_replace.line_anchor not found: {line_anchor!r}")
    else:
        raise PatchError("line_replace requires line_no or line_anchor")

    remaining = count
    unlimited = count <= 0
    total_hits = 0
    applied = 0

    for i in targets:
        src = lines[i]
        hits = _count_occurrence(src, search)
        total_hits += hits
        if hits == 0:
            continue

        if unlimited:
            lines[i] = src.replace(search, replace)
            applied += hits
            continue

        if remaining <= 0:
            break

        local_count = min(hits, remaining)
        lines[i] = src.replace(search, replace, local_count)
        applied += local_count
        remaining -= local_count

    if total_hits == 0:
        raise PatchError(f"line_replace search not found in selected line scope: {search!r}")

    return "".join(lines), {"hits": total_hits, "applied": applied}



def run_operation(text: str, operation: Dict[str, Any], op_newline: str) -> Tuple[str, Dict[str, Any]]:
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
        replace = normalize_text_newline(replace, op_newline)
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
        anchor = normalize_text_newline(anchor, op_newline)
        content = normalize_text_newline(content, op_newline)
        new_text, stats = op_insert(text, anchor, content, count, after=(op_type == "insert_after"))

    elif op_type == "regex_replace":
        pattern = operation.get("pattern")
        replace = operation.get("replace")
        flags = operation.get("flags", "")
        if not isinstance(pattern, str) or not isinstance(replace, str):
            raise PatchError("regex_replace requires string fields: pattern, replace")
        if not isinstance(flags, str):
            raise PatchError("regex_replace.flags must be string")
        replace = normalize_text_newline(replace, op_newline)
        new_text, stats = op_regex_replace(text, pattern, replace, count, flags)

    elif op_type == "line_replace":
        search = operation.get("search")
        replace = operation.get("replace")
        line_no = operation.get("line_no")
        line_anchor = operation.get("line_anchor")
        if not isinstance(search, str) or not isinstance(replace, str):
            raise PatchError("line_replace requires string fields: search, replace")
        if line_no is not None and not isinstance(line_no, int):
            raise PatchError("line_replace.line_no must be integer")
        if line_anchor is not None and not isinstance(line_anchor, str):
            raise PatchError("line_replace.line_anchor must be string")
        replace = normalize_text_newline(replace, op_newline)
        new_text, stats = op_line_replace(text, search, replace, count, line_no, line_anchor)

    else:
        raise PatchError(f"unsupported operation: {op_type}")

    expected = operation.get("expect")
    if expected is not None:
        if not isinstance(expected, int):
            raise PatchError(f"operation.expect must be integer for op={op_type}")
        if stats["applied"] != expected:
            raise PatchError(
                f"operation applied count mismatch for op={op_type}: "
                f"expected={expected}, actual={stats['applied']}"
            )

    report: Dict[str, Any] = {
        "op": op_type,
        "hits": stats["hits"],
        "applied": stats["applied"],
    }
    if op_type == "regex_replace":
        report["flags"] = operation.get("flags", "")
    if op_type == "line_replace":
        if "line_no" in operation:
            report["line_no"] = operation["line_no"]
        if "line_anchor" in operation:
            report["line_anchor"] = operation["line_anchor"]

    return new_text, report



def _build_diff_preview(
    rel_path: Path,
    before: str,
    after: str,
    context: int,
    max_lines: int,
) -> Dict[str, Any]:
    lines = list(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"a/{rel_path.as_posix()}",
            tofile=f"b/{rel_path.as_posix()}",
            n=context,
            lineterm="",
        )
    )

    truncated = False
    if max_lines > 0 and len(lines) > max_lines:
        remaining = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... [truncated {remaining} lines]"]
        truncated = True

    return {
        "line_count": len(lines),
        "truncated": truncated,
        "lines": lines,
    }



def prepare_patch(
    root: Path,
    item: Dict[str, Any],
    policy: Policy,
) -> PreparedPatch:
    raw_path = item.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise PatchError("item.path must be non-empty string")

    rel_path = normalize_workspace_path(root, raw_path)
    abs_path = root / rel_path

    if not abs_path.exists() or not abs_path.is_file():
        raise PatchError(f"target file not found: {rel_path.as_posix()}")

    spec = resolve_spec(rel_path, policy)

    explicit_encoding = item.get("encoding")
    if explicit_encoding is not None and (not isinstance(explicit_encoding, str) or not explicit_encoding):
        raise PatchError(f"item.encoding invalid: {rel_path.as_posix()}")
    encoding = explicit_encoding if isinstance(explicit_encoding, str) else spec.encoding

    bom = _normalize_bom(item.get("bom", spec.bom), f"item.bom: {rel_path.as_posix()}")
    newline_policy = _normalize_newline(item.get("newline", spec.newline), f"item.newline: {rel_path.as_posix()}")

    original_bytes = abs_path.read_bytes()

    try:
        decoded = decode_text(original_bytes, encoding)
    except UnicodeDecodeError as exc:
        raise PatchError(f"decode failed: path={rel_path.as_posix()} encoding={encoding}: {exc}") from exc

    operations = item.get("operations")
    if not isinstance(operations, list) or not operations:
        raise PatchError(f"item.operations must be non-empty array: {rel_path.as_posix()}")

    detected_newline = detect_newline(decoded.text)
    op_newline = NEWLINE_LF if detected_newline == NEWLINE_NONE else detected_newline

    next_text = decoded.text
    operation_reports: List[Dict[str, Any]] = []

    for idx, op in enumerate(operations):
        if not isinstance(op, dict):
            raise PatchError(f"operation[{idx}] must be object: {rel_path.as_posix()}")
        next_text, report = run_operation(next_text, op, op_newline)
        report["index"] = idx
        operation_reports.append(report)

    next_text = enforce_newline_policy(next_text, newline_policy, fallback=op_newline)

    try:
        body = encode_text(next_text, encoding)
    except UnicodeEncodeError as exc:
        raise PatchError(f"encode failed: path={rel_path.as_posix()} encoding={encoding}: {exc}") from exc

    new_bytes = apply_bom(body, encoding, bom, decoded.had_utf8_bom)

    return PreparedPatch(
        rel_path=rel_path,
        abs_path=abs_path,
        encoding=encoding,
        matched_glob=spec.matched_glob,
        bom=bom,
        newline_policy=newline_policy,
        detected_newline=detected_newline,
        original_had_utf8_bom=decoded.had_utf8_bom,
        original_bytes=original_bytes,
        new_bytes=new_bytes,
        original_text=decoded.text,
        new_text=next_text,
        operation_reports=operation_reports,
    )



def save_report(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")



def write_bytes(path: Path, payload: bytes, atomic_write: bool) -> None:
    if not atomic_write:
        path.write_bytes(payload)
        return

    tmp_path = path.with_name(f"{path.name}.tmp-{os.getpid()}-{now_tag()}")
    tmp_path.write_bytes(payload)
    tmp_path.replace(path)



def _build_run_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", required=True, help="utf-8 json patch config path")
    parser.add_argument("--policy", default=None, help="encoding policy json path")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run", help="execution mode")
    parser.add_argument("--report", default=None, help="json report output path")
    parser.add_argument("--backup-root", default=".encoding_patch_backups", help="backup root for apply mode")

    group_empty = parser.add_mutually_exclusive_group()
    group_empty.add_argument(
        "--fail-on-empty",
        dest="fail_on_empty",
        action="store_true",
        help="fail when zero files changed (default)",
    )
    group_empty.add_argument(
        "--allow-empty",
        dest="fail_on_empty",
        action="store_false",
        help="allow zero changed files",
    )
    parser.set_defaults(fail_on_empty=True)

    parser.add_argument("--diff-context", type=int, default=3, help="dry-run diff context lines")
    parser.add_argument("--diff-max-lines", type=int, default=120, help="max preview lines per file; <=0 means no limit")

    group_atomic = parser.add_mutually_exclusive_group()
    group_atomic.add_argument(
        "--atomic-write",
        dest="atomic_write",
        action="store_true",
        help="write via temp file then replace (default)",
    )
    group_atomic.add_argument(
        "--no-atomic-write",
        dest="atomic_write",
        action="store_false",
        help="write directly without atomic replace",
    )
    parser.set_defaults(atomic_write=True)



def _build_rollback_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--report", required=True, help="apply report path to rollback from")
    parser.add_argument("--output-report", default=None, help="rollback report output path")

    group_atomic = parser.add_mutually_exclusive_group()
    group_atomic.add_argument("--atomic-write", dest="atomic_write", action="store_true", help="atomic restore (default)")
    group_atomic.add_argument("--no-atomic-write", dest="atomic_write", action="store_false", help="direct restore")
    parser.set_defaults(atomic_write=True)



def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    if len(argv) > 1 and argv[1] in {"run", "rollback"}:
        parser = argparse.ArgumentParser(description="Encoding-safe patch tool")
        subs = parser.add_subparsers(dest="command", required=True)

        run_parser = subs.add_parser("run", help="run patch operations")
        _build_run_parser(run_parser)

        rollback_parser = subs.add_parser("rollback", help="rollback files from apply report")
        _build_rollback_parser(rollback_parser)

        return parser.parse_args(argv[1:])

    # legacy mode: no subcommand, treated as run
    parser = argparse.ArgumentParser(description="Encoding-safe patch tool (legacy mode)")
    _build_run_parser(parser)
    ns = parser.parse_args(argv[1:])
    ns.command = "run"
    return ns



def execute_run(args: argparse.Namespace) -> int:
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
        diff_preview = _build_diff_preview(
            patch.rel_path,
            patch.original_text,
            patch.new_text,
            context=max(0, args.diff_context),
            max_lines=args.diff_max_lines,
        )

        if changed:
            changed_count += 1
            if args.mode == "apply":
                backup_path = backup_dir / patch.rel_path
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                backup_path.write_bytes(patch.original_bytes)

                patch.abs_path.parent.mkdir(parents=True, exist_ok=True)
                write_bytes(patch.abs_path, patch.new_bytes, atomic_write=bool(args.atomic_write))

        file_reports.append(
            {
                "path": patch.rel_path.as_posix(),
                "encoding": patch.encoding,
                "matched_glob": patch.matched_glob,
                "bom": patch.bom,
                "newline_policy": patch.newline_policy,
                "detected_newline": patch.detected_newline,
                "had_utf8_bom_before": patch.original_had_utf8_bom,
                "changed": changed,
                "bytes_before": len(patch.original_bytes),
                "bytes_after": len(patch.new_bytes),
                "operations": patch.operation_reports,
                "diff_preview": diff_preview,
            }
        )

    if args.report:
        report_path = (root / args.report).resolve()
    else:
        report_path = (root / f".encoding_patch_reports/{args.mode}-{now_tag()}.json").resolve()

    payload: Dict[str, Any] = {
        "command": "run",
        "mode": args.mode,
        "config": relative_or_str(root, config_path),
        "policy": relative_or_str(root, policy_path),
        "total_files": len(prepared),
        "changed_files": changed_count,
        "fail_on_empty": bool(args.fail_on_empty),
        "atomic_write": bool(args.atomic_write),
        "backup_dir": relative_or_str(root, backup_dir) if args.mode == "apply" else None,
        "files": file_reports,
    }

    save_report(report_path, payload)

    print(
        f"[encoding-safe-patch] mode={args.mode} total={len(prepared)} "
        f"changed={changed_count} fail_on_empty={bool(args.fail_on_empty)}"
    )
    print(f"[encoding-safe-patch] report={relative_or_str(root, report_path)}")
    if args.mode == "apply":
        print(f"[encoding-safe-patch] backup={relative_or_str(root, backup_dir)}")

    if changed_count == 0 and bool(args.fail_on_empty):
        print(
            "[encoding-safe-patch] ERROR: zero files changed while fail-on-empty is enabled",
            file=sys.stderr,
        )
        return 1

    return 0



def execute_rollback(args: argparse.Namespace) -> int:
    root = Path.cwd().resolve()
    report_path = (root / args.report).resolve()
    report_obj = read_json_utf8(report_path)

    if not isinstance(report_obj, dict):
        raise PatchError("rollback report must be object")

    backup_dir_raw = report_obj.get("backup_dir")
    files_obj = report_obj.get("files")
    mode = report_obj.get("mode")

    if not isinstance(backup_dir_raw, str) or not backup_dir_raw:
        raise PatchError("rollback report missing backup_dir")
    if mode != "apply":
        raise PatchError("rollback report mode must be apply")
    if not isinstance(files_obj, list):
        raise PatchError("rollback report missing files array")

    backup_dir = (root / backup_dir_raw).resolve()

    restored = 0
    skipped = 0
    items_report: List[Dict[str, Any]] = []

    for i, item in enumerate(files_obj):
        if not isinstance(item, dict):
            raise PatchError(f"report.files[{i}] must be object")

        path_raw = item.get("path")
        changed = bool(item.get("changed"))

        if not isinstance(path_raw, str) or not path_raw:
            raise PatchError(f"report.files[{i}].path invalid")

        if not changed:
            skipped += 1
            items_report.append({"path": path_raw, "restored": False, "reason": "unchanged"})
            continue

        rel_path = normalize_workspace_path(root, path_raw)
        target_path = root / rel_path
        backup_path = backup_dir / rel_path

        if not backup_path.exists() or not backup_path.is_file():
            raise PatchError(f"backup not found for path={rel_path.as_posix()} under {backup_dir}")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        write_bytes(target_path, backup_path.read_bytes(), atomic_write=bool(args.atomic_write))
        restored += 1
        items_report.append({"path": rel_path.as_posix(), "restored": True})

    if args.output_report:
        out_path = (root / args.output_report).resolve()
    else:
        out_path = (root / f".encoding_patch_reports/rollback-{now_tag()}.json").resolve()

    payload: Dict[str, Any] = {
        "command": "rollback",
        "source_report": relative_or_str(root, report_path),
        "restored_files": restored,
        "skipped_files": skipped,
        "atomic_write": bool(args.atomic_write),
        "files": items_report,
    }
    save_report(out_path, payload)

    print(f"[encoding-safe-patch] rollback restored={restored} skipped={skipped}")
    print(f"[encoding-safe-patch] rollback_report={relative_or_str(root, out_path)}")
    return 0



def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    if args.command == "rollback":
        return execute_rollback(args)
    return execute_run(args)



if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (PatchError, PolicyError) as exc:
        print(f"[encoding-safe-patch] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
