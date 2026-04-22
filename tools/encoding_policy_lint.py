#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

try:
    from encoding_policy_core import (
        Policy,
        PolicyError,
        collect_files_from_paths,
        is_excluded,
        load_policy,
        match_glob,
        relative_or_str,
        resolve_spec,
        to_relative,
    )
except ModuleNotFoundError:
    from tools.encoding_policy_core import (
        Policy,
        PolicyError,
        collect_files_from_paths,
        is_excluded,
        load_policy,
        match_glob,
        relative_or_str,
        resolve_spec,
        to_relative,
    )


class LintError(Exception):
    pass


def _scan_all_files(root: Path, scan_paths: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for raw in scan_paths:
        p = Path(raw)
        abs_path = (root / p).resolve() if not p.is_absolute() else p.resolve()
        if not abs_path.exists():
            raise LintError(f"scan path not found: {raw}")

        rel = to_relative(root, abs_path)
        if abs_path.is_file():
            out.append(rel)
            continue

        if abs_path.is_dir():
            for child in abs_path.rglob("*"):
                if child.is_file():
                    out.append(to_relative(root, child))

    unique = {p.as_posix(): p for p in out}
    return [unique[k] for k in sorted(unique.keys())]


def _duplicate_glob_findings(policy: Policy) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    first: Dict[str, int] = {}

    for idx, rule in enumerate(policy.rules):
        if rule.glob in first:
            first_idx = first[rule.glob]
            findings.append(
                {
                    "level": "warning",
                    "type": "duplicate_glob",
                    "glob": rule.glob,
                    "first_index": first_idx,
                    "current_index": idx,
                    "message": f"rule[{idx}] duplicates glob with rule[{first_idx}]",
                }
            )
        else:
            first[rule.glob] = idx

    return findings


def _unreachable_by_order_findings(policy: Policy) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for idx, rule in enumerate(policy.rules):
        if rule.glob in seen:
            findings.append(
                {
                    "level": "warning",
                    "type": "unreachable_rule",
                    "glob": rule.glob,
                    "current_index": idx,
                    "shadowed_by_index": seen[rule.glob],
                    "message": "first-match strategy makes this rule unreachable for same glob",
                }
            )
        else:
            seen[rule.glob] = idx
    return findings


def _redundant_same_mapping_findings(policy: Policy) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    first: Dict[tuple[str, str, str, str], int] = {}

    for idx, r in enumerate(policy.rules):
        key = (r.glob, r.encoding, r.bom, r.newline)
        if key in first:
            findings.append(
                {
                    "level": "info",
                    "type": "redundant_rule",
                    "glob": r.glob,
                    "current_index": idx,
                    "same_as_index": first[key],
                    "message": "rule has identical glob+encoding+bom+newline mapping",
                }
            )
        else:
            first[key] = idx

    return findings


def _unmatched_rule_findings(policy: Policy, all_files: List[Path]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for idx, rule in enumerate(policy.rules):
        hit = False
        for path in all_files:
            rel = path.as_posix()
            if match_glob(rel, rule.glob):
                hit = True
                break
        if not hit:
            findings.append(
                {
                    "level": "info",
                    "type": "unmatched_rule",
                    "rule_index": idx,
                    "glob": rule.glob,
                    "message": "no files matched this rule under current scan paths",
                }
            )
    return findings


def _exclude_rule_conflict_findings(policy: Policy, all_files: List[Path]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in all_files:
        rel = path.as_posix()
        if not is_excluded(path, policy):
            continue

        matched_rules = [r.glob for r in policy.rules if match_glob(rel, r.glob)]
        if matched_rules:
            findings.append(
                {
                    "level": "warning",
                    "type": "exclude_rule_conflict",
                    "path": rel,
                    "rules": matched_rules,
                    "message": "file is both excluded and matched by at least one rule",
                }
            )
    return findings


def _shadow_risk_findings(policy: Policy, files: List[Path]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in files:
        rel = path.as_posix()
        matched = [i for i, r in enumerate(policy.rules) if match_glob(rel, r.glob)]
        if len(matched) <= 1:
            continue
        first_idx = matched[0]
        spec = resolve_spec(path, policy)
        findings.append(
            {
                "level": "warning",
                "type": "order_shadow_risk",
                "path": rel,
                "matched_rule_indexes": matched,
                "effective_rule_index": first_idx,
                "effective_encoding": spec.encoding,
                "message": "multiple rules match same file; first-match order determines behavior",
            }
        )
    return findings


def _save_report(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Lint encoding policy for overlap/unreachable/risk findings")
    parser.add_argument("--policy", default="tools/encoding-policy.json", help="policy path")
    parser.add_argument("--paths", nargs="+", default=["."], help="scan paths")
    parser.add_argument("--report", default=None, help="optional report json")
    parser.add_argument("--strict", action="store_true", help="treat warnings as failure")
    args = parser.parse_args(argv[1:])

    root = Path.cwd().resolve()
    policy_path = (root / args.policy).resolve()

    try:
        policy = load_policy(policy_path)
        all_files = _scan_all_files(root, args.paths)
        included_files = collect_files_from_paths(root, args.paths, policy)
    except (PolicyError, LintError) as exc:
        print(f"[encoding-policy-lint] ERROR: {exc}", file=sys.stderr)
        return 2

    findings: List[Dict[str, Any]] = []
    findings.extend(_duplicate_glob_findings(policy))
    findings.extend(_unreachable_by_order_findings(policy))
    findings.extend(_redundant_same_mapping_findings(policy))
    findings.extend(_unmatched_rule_findings(policy, all_files))
    findings.extend(_exclude_rule_conflict_findings(policy, all_files))
    findings.extend(_shadow_risk_findings(policy, included_files))

    warn_count = sum(1 for item in findings if item.get("level") == "warning")
    info_count = sum(1 for item in findings if item.get("level") == "info")

    status = "ok"
    exit_code = 0
    if args.strict and warn_count > 0:
        status = "failed"
        exit_code = 1

    payload: Dict[str, Any] = {
        "status": status,
        "strict": bool(args.strict),
        "policy": relative_or_str(root, policy_path),
        "paths": args.paths,
        "scanned_files": len(all_files),
        "included_files": len(included_files),
        "warning_count": warn_count,
        "info_count": info_count,
        "findings": findings,
    }

    if args.report:
        report_path = (root / args.report).resolve()
        _save_report(report_path, payload)

    print(
        f"[encoding-policy-lint] status={status} scanned={len(all_files)} "
        f"included={len(included_files)} warning={warn_count} info={info_count}"
    )

    if findings:
        print("[encoding-policy-lint] findings:", file=sys.stderr)
        for item in findings:
            print(
                f"  - [{item.get('level', 'info')}] {item.get('type', 'unknown')} | {item.get('message', '')}",
                file=sys.stderr,
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
