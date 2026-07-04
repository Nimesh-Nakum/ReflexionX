#!/usr/bin/env python3
"""
ReflexionX — Shared reflection_contexts.json loader
Single source of truth for reading/writing the canonical reflection
context artifact produced by xss_validator.py and consumed by every
downstream phase.
"""

import json
import os
from typing import Any, Dict, List, Optional, Union


CONTEXT_FILENAME = "reflection_contexts.json"


# ── Path helpers ────────────────────────────────────────────────

def get_contexts_path(output_dir: str) -> str:
    return os.path.join(output_dir, CONTEXT_FILENAME)


def resolve_contexts_path(
    output_dir: Optional[str] = None,
    filepath: Optional[str] = None,
) -> str:
    if filepath:
        return filepath
    if output_dir:
        return get_contexts_path(output_dir)
    raise ValueError("Either output_dir or filepath must be provided")


# ── Schema normalization ────────────────────────────────────────

def normalize_contexts(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    if not isinstance(data, dict):
        return []
    if "urls" in data and isinstance(data["urls"], list):
        return [entry for entry in data["urls"] if isinstance(entry, dict)]
    if "targets" in data and isinstance(data["targets"], list):
        return [entry for entry in data["targets"] if isinstance(entry, dict)]
    normalized = []
    for key, details in data.items():
        if isinstance(details, dict):
            normalized.append({"url": key, **details})
    return normalized


# ── Load / Save ─────────────────────────────────────────────────

def load_contexts(
    output_dir: Optional[str] = None,
    filepath: Optional[str] = None,
) -> List[Dict[str, Any]]:
    path = resolve_contexts_path(output_dir, filepath)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return normalize_contexts(data)


def load_contexts_dict(
    output_dir: Optional[str] = None,
    filepath: Optional[str] = None,
) -> Dict[str, Any]:
    path = resolve_contexts_path(output_dir, filepath)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_contexts(output_dir: str, data: Union[Dict, List]) -> None:
    path = get_contexts_path(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
