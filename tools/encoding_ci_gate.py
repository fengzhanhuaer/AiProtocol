#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from encoding_policy_core import (
        BOM_NONE,
        BOM_PRESERVE,
        BOM_UTF8_SIG,
        NEWLINE_PRESERVE,
        PolicyError,
        collect_files_from_paths,
        decode_text,
        detect_bom,
        detect_newline,
        is_likely_binary,
        is_utf8_family,
        load_policy,
        read_paths_from_file,
        relative_or_str,
        resolve_spec,
    )
except ModuleNotFoundError:
    from tools.encoding_policy_core import (
        BOM_NONE,
        BOM_PRESERVE,
        BOM_UTF8_SIG,
        NEWLINE_PRESERVE,
        PolicyError,
        collect_files_from_paths,
        decode_text,
        detect_bom,
        detect_newline,
        is_likely_binary,
        is_utf8_family,
        load_policy,
        read_paths_from_file,
        relative_or_str,
        resolve_spec,
    )


class GateError(Exception):
    pass


def _resolve_paths_from_git(root: Path, git_base: str) -> List[str]:
    cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{git_base}...HEAD"]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        raise GateError(f"git diff failed: {' '.join(cmd)} | {stderr}")

    out: List[str] = []
    for line in proc.stdout.splitlines():
        item = line.strip()
        if item:
            out.append(item)
    return out


def _merge_scan_paths(root: Path, args: argparse.Namespace) -> List[str]:
    merged: List[str] = []

    if args.paths:
        merged.extend(args.paths)

    if args.paths_from_file:
        path_file = (root / args.paths_from_file).resolve()
        try:
            merged.extend(read_paths_from_file(path_file))
        except PolicyError as exc:
            raise GateError(str(exc)) from exc

    if args.changed_from_git:
        merged.extend(_resolve_paths_from_git(root, args.git_base))

    if not merged:
        merged = ["."]

    unique = []
    seen = set()
    for item in merged:
        norm = item.replace("\\", "/")
        if norm not in seen:
            seen.add(norm)
            unique.append(item)
    return unique


def _bom_error(expected_bom: str, actual_bom: str, encoding: str) -> Optional[str]:
    if not is_utf8_family(encoding):
        return None

    if expected_bom == BOM_PRESERVE:
        return None

    if expected_bom == BOM_NONE and actual_bom != BOM_NONE:
        return f"bom mismatch: expected={BOM_NONE}, actual={actual_bom}"

    if expected_bom == BOM_UTF8_SIG and actual_bom != BOM_UTF8_SIG:
        return f"bom mismatch: expected={BOM_UTF8_SIG}, actual={actual_bom}"

    return None


def _newline_error(expected: str, actual: str) -> Optional[str]:
    if expected == NEWLINE_PRESERVE:
        return None
    if expected != actual:
        return f"newline mismatch: expected={expected}, actual={actual}"
    return None


def _suggestion(reason: str, rel_path: str) -> str:
    if "decode failed" in reason:
        return (
            f"Check policy encoding mapping and modify file with tools/encoding_safe_patch.py "
            f"instead of direct overwrite: {rel_path}"
        )
    if "bom mismatch" in reason:
        return f"Fix file BOM or update policy bom rule, then rerun gate: {rel_path}"
    if "newline mismatch" in reason:
        return f"Fix newline style or update policy newline rule, then rerun gate: {rel_path}"
    if "binary file" in reason:
        return f"Add file into exclude or use --skip-binary for binary files: {rel_path}"
    return "Check file content and policy settings, then rerun gate"


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="CI encoding gate: verify file bytes by encoding policy with optional BOM/newline checks."
    )
    parser.add_argument("--policy", default="tools/encoding-policy.json", help="encoding policy json path")
    parser.add_argument("--paths", nargs="+", default=[], help="scan paths under workspace")
    parser.add_argument("--paths-from-file", default=None, help="read scan paths from utf-8 file")
    parser.add_argument("--changed-from-git", action="store_true", help="scan changed files from git diff")
    parser.add_argument("--git-base", default="HEAD~1", help="git base revision when --changed-from-git enabled")
    parser.add_argument("--report", default=None, help="optional json report path")
    parser.add_argument("--fail-on-empty", action="store_true", help="fail when zero files scanned")

    # 默认开启 check-bom，允许显式关闭
    group_bom = parser.add_mutually_exclusive_group()
    group_bom.add_argument("--check-bom", dest="check_bom", action="store_true", help="enable BOM check (default)")
    group_bom.add_argument("--no-check-bom", dest="check_bom", action="store_false", help="disable BOM check")
    parser.set_defaults(check_bom=True)

    parser.add_argument("--check-newline", action="store_true", help="enable newline check")

    group_bin = parser.add_mutually_exclusive_group()
    group_bin.add_argument("--skip-binary", action="store_true", help="skip likely binary files")
    group_bin.add_argument("--strict-binary", action="store_true", help="binary files are treated as failures")

    args = parser.parse_args(argv[1:])

    root = Path.cwd().resolve()
    policy_path = (root / args.policy).resolve()

    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        raise GateError(str(exc)) from exc

    try:
        scan_paths = _merge_scan_paths(root, args)
        files = collect_files_from_paths(root, scan_paths, policy)
    except PolicyError as exc:
        raise GateError(str(exc)) from exc

    checked = 0
    failures: List[Dict[str, Any]] = []
    skipped_binary: List[str] = []

    for rel_path in files:
        checked += 1
        abs_path = root / rel_path
        raw = abs_path.read_bytes()

        if is_likely_binary(raw):
            if args.strict_binary:
                reason = "binary file detected and strict-binary is enabled"
                failures.append(
                    {
                        "path": rel_path.as_posix(),
                        "reason": reason,
                        "suggestion": _suggestion(reason, rel_path.as_posix()),
                    }
                )
                continue
            if args.skip_binary:
                skipped_binary.append(rel_path.as_posix())
                continue

        spec = resolve_spec(rel_path, policy)

        try:
            decoded = decode_text(raw, spec.encoding)
        except UnicodeDecodeError as exc:
            reason = f"decode failed with encoding={spec.encoding}: {exc}"
            failures.append(
                {
                    "path": rel_path.as_posix(),
                    "expected_encoding": spec.encoding,
                    "matched_glob": spec.matched_glob,
                    "reason": reason,
                    "suggestion": _suggestion(reason, rel_path.as_posix()),
                }
            )
            continue

        if bool(args.check_bom):
            actual_bom = detect_bom(raw)
            err = _bom_error(spec.bom, actual_bom, spec.encoding)
            if err:
                failures.append(
                    {
                        "path": rel_path.as_posix(),
                        "expected_encoding": spec.encoding,
                        "matched_glob": spec.matched_glob,
                        "expected_bom": spec.bom,
                        "actual_bom": actual_bom,
                        "reason": err,
                        "suggestion": _suggestion(err, rel_path.as_posix()),
                    }
                )
                continue

        if bool(args.check_newline):
            actual_newline = detect_newline(decoded.text)
            err = _newline_error(spec.newline, actual_newline)
            if err:
                failures.append(
                    {
                        "path": rel_path.as_posix(),
                        "expected_encoding": spec.encoding,
                        "matched_glob": spec.matched_glob,
                        "expected_newline": spec.newline,
                        "actual_newline": actual_newline,
                        "reason": err,
                        "suggestion": _suggestion(err, rel_path.as_posix()),
                    }
                )
                continue

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
        "policy": relative_or_str(root, policy_path),
        "paths": scan_paths,
        "checked_files": checked,
        "failed_files": len(failures),
        "skipped_binary_files": len(skipped_binary),
        "skipped_binary_list": skipped_binary,
        "check_bom": bool(args.check_bom),
        "check_newline": bool(args.check_newline),
        "failures": failures,
    }

    if args.report:
        report_path = (root / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(
        f"[encoding-ci-gate] checked={checked} failed={len(failures)} "
        f"skipped_binary={len(skipped_binary)} status={status} check_bom={bool(args.check_bom)}"
    )

    if checked == 0 and args.fail_on_empty:
        print("[encoding-ci-gate] ERROR: no files scanned and --fail-on-empty is enabled", file=sys.stderr)

    if skipped_binary:
        print("[encoding-ci-gate] skipped binary files:", file=sys.stderr)
        for item in skipped_binary:
            print(f"  - {item}", file=sys.stderr)

    if failures:
        print("[encoding-ci-gate] failed files:", file=sys.stderr)
        for item in failures:
            msg = item.get("reason", "unknown")
            sug = item.get("suggestion", "")
            print(f"  - {item['path']} | {msg}", file=sys.stderr)
            if sug:
                print(f"    suggestion: {sug}", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (GateError, PolicyError) as exc:
        print(f"[encoding-ci-gate] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
