#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


class PolicyError(Exception):
    pass


BOM_PRESERVE = "preserve"
BOM_NONE = "none"
BOM_UTF8_SIG = "utf-8-sig"
BOM_CHOICES = {BOM_PRESERVE, BOM_NONE, BOM_UTF8_SIG}

NEWLINE_PRESERVE = "preserve"
NEWLINE_LF = "lf"
NEWLINE_CRLF = "crlf"
NEWLINE_CR = "cr"
NEWLINE_NONE = "none"
NEWLINE_CHOICES = {NEWLINE_PRESERVE, NEWLINE_LF, NEWLINE_CRLF, NEWLINE_CR}

UTF8_BOM_BYTES = b"\xef\xbb\xbf"


@dataclass
class PolicyRule:
    glob: str
    encoding: str
    bom: str = BOM_PRESERVE
    newline: str = NEWLINE_PRESERVE


@dataclass
class Policy:
    version: int
    default_encoding: str
    default_bom: str
    default_newline: str
    rules: List[PolicyRule]
    exclude: List[str]


@dataclass
class ResolvedSpec:
    encoding: str
    bom: str
    newline: str
    matched_glob: Optional[str]


@dataclass
class DecodedText:
    text: str
    had_utf8_bom: bool


def read_json_utf8(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"json file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyError(f"json file must be utf-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid json: {path}: {exc}") from exc


def _normalize_bom(value: Any, field: str) -> str:
    if value is None:
        return BOM_PRESERVE
    if not isinstance(value, str):
        raise PolicyError(f"{field} must be string")
    norm = value.strip().lower()
    if norm not in BOM_CHOICES:
        raise PolicyError(f"{field} must be one of {sorted(BOM_CHOICES)}")
    return norm


def _normalize_newline(value: Any, field: str) -> str:
    if value is None:
        return NEWLINE_PRESERVE
    if not isinstance(value, str):
        raise PolicyError(f"{field} must be string")
    norm = value.strip().lower()
    if norm not in NEWLINE_CHOICES:
        raise PolicyError(f"{field} must be one of {sorted(NEWLINE_CHOICES)}")
    return norm


def load_policy(path: Path) -> Policy:
    obj = read_json_utf8(path)
    if not isinstance(obj, dict):
        raise PolicyError("policy root must be an object")

    version_obj = obj.get("version", 1)
    if not isinstance(version_obj, int) or version_obj <= 0:
        raise PolicyError("policy.version must be positive integer")

    default_encoding = obj.get("default_encoding", "utf-8")
    if not isinstance(default_encoding, str) or not default_encoding:
        raise PolicyError("policy.default_encoding must be non-empty string")

    default_bom = _normalize_bom(obj.get("default_bom", BOM_PRESERVE), "policy.default_bom")
    default_newline = _normalize_newline(obj.get("default_newline", NEWLINE_PRESERVE), "policy.default_newline")

    rules_obj = obj.get("rules", [])
    exclude_obj = obj.get("exclude", [])

    if not isinstance(rules_obj, list):
        raise PolicyError("policy.rules must be an array")
    if not isinstance(exclude_obj, list):
        raise PolicyError("policy.exclude must be an array")

    rules: List[PolicyRule] = []
    for i, item in enumerate(rules_obj):
        if not isinstance(item, dict):
            raise PolicyError(f"policy.rules[{i}] must be an object")
        glob = item.get("glob")
        encoding = item.get("encoding")
        if not isinstance(glob, str) or not glob:
            raise PolicyError(f"policy.rules[{i}].glob must be non-empty string")
        if not isinstance(encoding, str) or not encoding:
            raise PolicyError(f"policy.rules[{i}].encoding must be non-empty string")
        bom = _normalize_bom(item.get("bom", default_bom), f"policy.rules[{i}].bom")
        newline = _normalize_newline(item.get("newline", default_newline), f"policy.rules[{i}].newline")
        rules.append(PolicyRule(glob=glob, encoding=encoding, bom=bom, newline=newline))

    exclude: List[str] = []
    for i, item in enumerate(exclude_obj):
        if not isinstance(item, str) or not item:
            raise PolicyError(f"policy.exclude[{i}] must be non-empty string")
        exclude.append(item)

    return Policy(
        version=version_obj,
        default_encoding=default_encoding,
        default_bom=default_bom,
        default_newline=default_newline,
        rules=rules,
        exclude=exclude,
    )


def match_glob(rel_posix: str, pattern: str) -> bool:
    name = rel_posix.split("/")[-1]
    return fnmatch(rel_posix, pattern) or fnmatch(name, pattern)


def is_excluded(rel_path: Path, policy: Policy) -> bool:
    rel_posix = rel_path.as_posix()
    return any(match_glob(rel_posix, pat) for pat in policy.exclude)


def resolve_spec(rel_path: Path, policy: Policy) -> ResolvedSpec:
    rel_posix = rel_path.as_posix()
    for rule in policy.rules:
        if match_glob(rel_posix, rule.glob):
            return ResolvedSpec(
                encoding=rule.encoding,
                bom=rule.bom,
                newline=rule.newline,
                matched_glob=rule.glob,
            )
    return ResolvedSpec(
        encoding=policy.default_encoding,
        bom=policy.default_bom,
        newline=policy.default_newline,
        matched_glob=None,
    )


def to_relative(root: Path, path: Path) -> Path:
    abs_path = path.resolve()
    try:
        return abs_path.relative_to(root)
    except ValueError as exc:
        raise PolicyError(f"path escapes workspace: {path}") from exc


def normalize_workspace_path(root: Path, raw_path: str) -> Path:
    p = Path(raw_path)
    if p.is_absolute():
        raise PolicyError(f"path must be workspace-relative: {raw_path}")
    abs_path = (root / p).resolve()
    return to_relative(root, abs_path)


def is_utf8_family(encoding: str) -> bool:
    lower = encoding.strip().lower().replace("_", "-")
    return lower in {"utf-8", "utf8", "utf-8-sig"}


def detect_bom(raw: bytes) -> str:
    if raw.startswith(UTF8_BOM_BYTES):
        return BOM_UTF8_SIG
    return BOM_NONE


def decode_text(raw: bytes, encoding: str) -> DecodedText:
    had_utf8_bom = is_utf8_family(encoding) and raw.startswith(UTF8_BOM_BYTES)
    decode_encoding = "utf-8-sig" if had_utf8_bom else encoding
    text = raw.decode(decode_encoding)
    return DecodedText(text=text, had_utf8_bom=had_utf8_bom)


def encode_text(text: str, encoding: str) -> bytes:
    if encoding.strip().lower().replace("_", "-") == "utf-8-sig":
        return text.encode("utf-8")
    return text.encode(encoding)


def apply_bom(raw: bytes, encoding: str, bom: str, original_had_utf8_bom: bool) -> bytes:
    if not is_utf8_family(encoding):
        return raw

    body = raw[3:] if raw.startswith(UTF8_BOM_BYTES) else raw

    if bom == BOM_UTF8_SIG:
        return UTF8_BOM_BYTES + body
    if bom == BOM_NONE:
        return body
    if bom == BOM_PRESERVE:
        return (UTF8_BOM_BYTES + body) if original_had_utf8_bom else body

    raise PolicyError(f"unsupported bom setting: {bom}")


def detect_newline(text: str) -> str:
    if "\r\n" in text:
        return NEWLINE_CRLF
    if "\n" in text:
        return NEWLINE_LF
    if "\r" in text:
        return NEWLINE_CR
    return NEWLINE_NONE


def newline_chars(label: str) -> str:
    if label == NEWLINE_CRLF:
        return "\r\n"
    if label == NEWLINE_CR:
        return "\r"
    if label == NEWLINE_LF:
        return "\n"
    raise PolicyError(f"unsupported newline label: {label}")


def normalize_text_newline(value: str, newline_label: str) -> str:
    target = newline_chars(newline_label)
    return value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", target)


def enforce_newline_policy(text: str, newline: str, fallback: str) -> str:
    if newline == NEWLINE_PRESERVE:
        return text
    if newline == NEWLINE_NONE:
        return text
    target = newline if newline in {NEWLINE_LF, NEWLINE_CRLF, NEWLINE_CR} else fallback
    return normalize_text_newline(text, target)


def is_likely_binary(raw: bytes, sample_size: int = 4096) -> bool:
    if not raw:
        return False
    if b"\x00" in raw:
        return True

    sample = raw[:sample_size]
    control = 0
    for b in sample:
        if b in (9, 10, 13):
            continue
        if b < 32 or b == 127:
            control += 1
    ratio = control / max(1, len(sample))
    return ratio > 0.30


def collect_files_from_paths(root: Path, scan_paths: Sequence[str], policy: Policy) -> List[Path]:
    out: List[Path] = []
    for raw in scan_paths:
        p = Path(raw)
        abs_path = (root / p).resolve() if not p.is_absolute() else p.resolve()
        if not abs_path.exists():
            raise PolicyError(f"scan path not found: {raw}")

        rel = to_relative(root, abs_path)
        if is_excluded(rel, policy):
            continue

        if abs_path.is_file():
            out.append(rel)
            continue

        if abs_path.is_dir():
            for child in abs_path.rglob("*"):
                if not child.is_file():
                    continue
                rel_child = to_relative(root, child)
                if is_excluded(rel_child, policy):
                    continue
                out.append(rel_child)

    unique = {item.as_posix(): item for item in out}
    return [unique[key] for key in sorted(unique.keys())]


def read_paths_from_file(path: Path) -> List[str]:
    if not path.exists() or not path.is_file():
        raise PolicyError(f"path list file not found: {path}")
    rows: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(line)
    return rows


def relative_or_str(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path)
