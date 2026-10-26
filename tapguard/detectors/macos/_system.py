"""Shared macOS helpers: process resolution and code-signature trust.

Kept dependency-light and defensive - every lookup degrades to ``None`` rather
than raising, so a detector can make a best-effort judgement without crashing.
"""
from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from typing import Optional

try:
    import psutil
except Exception:  # pragma: no cover - psutil missing
    psutil = None  # type: ignore

# Paths Apple ships system executables under.
TRUSTED_PREFIXES = (
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/sbin/",
    "/bin/",
)


def process_name(pid: Optional[int]) -> Optional[str]:
    if not pid or pid <= 0:
        return None
    if psutil is not None:
        try:
            return psutil.Process(pid).name()
        except Exception:
            return None
    try:
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True, text=True, timeout=3,
        )
        name = out.stdout.strip()
        return os.path.basename(name) if name else None
    except Exception:
        return None


def process_exe(pid: Optional[int]) -> Optional[str]:
    if not pid or pid <= 0:
        return None
    if psutil is not None:
        try:
            return psutil.Process(pid).exe()
        except Exception:
            return None
    return None


@lru_cache(maxsize=512)
def signing_leaf(path: Optional[str]) -> Optional[str]:
    """Return the leaf (first) code-signing authority for a binary, or None.

    None means unsigned, ad-hoc, or codesign could not read it.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        res = subprocess.run(
            ["codesign", "-dv", "--verbose=4", path],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return None
    # codesign prints the certificate chain to stderr; the first Authority
    # line is the leaf/signing identity.
    for line in res.stderr.splitlines():
        if line.startswith("Authority="):
            return line.split("=", 1)[1].strip()
    return None


def trust_level(path: Optional[str]) -> str:
    """Classify a binary's signature: apple | developer-id | dev | unsigned | unknown | other."""
    leaf = signing_leaf(path)
    if leaf is None:
        if path and os.path.exists(path):
            return "unsigned"
        return "unknown"
    if leaf == "Software Signing":
        return "apple"
    if leaf.startswith("Developer ID Application"):
        return "developer-id"
    if leaf.startswith(("Apple Development", "Apple Distribution", "Mac Developer")):
        return "dev"
    return "other"


def is_trusted_path(path: Optional[str]) -> bool:
    return bool(path) and path.startswith(TRUSTED_PREFIXES)
