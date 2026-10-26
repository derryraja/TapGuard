"""Audit which apps hold Input Monitoring / Accessibility / PostEvent rights.

These are the TCC permissions a keylogger needs. The detector lists holders so
you can spot anything you didn't grant on purpose. Reading the TCC databases
needs Full Disk Access; when that's missing the detector says so rather than
failing silently.
"""
from __future__ import annotations

import os
import sqlite3
from typing import Optional

from ...models import Finding, Severity

USER_TCC = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
SYSTEM_TCC = "/Library/Application Support/com.apple.TCC/TCC.db"

SERVICES = {
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Synthetic keystroke sending",
}


def _granted(auth_col: str, value: int) -> bool:
    # Newer schema: auth_value (2 = allowed). Older: allowed (1 = allowed).
    return (auth_col == "auth_value" and value == 2) or (auth_col == "allowed" and value == 1)


def _read_db(db_path: str, scope: str) -> tuple[list[Finding], Optional[str]]:
    if not os.path.exists(db_path):
        return [], None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except Exception as exc:
        return [], f"{scope}: cannot open TCC database ({exc})."
    findings: list[Finding] = []
    try:
        cur = con.cursor()
        cols = [row[1] for row in cur.execute("PRAGMA table_info(access)")]
        auth_col = "auth_value" if "auth_value" in cols else ("allowed" if "allowed" in cols else None)
        if auth_col is None:
            return [], f"{scope}: unexpected TCC schema."
        placeholders = ",".join("?" for _ in SERVICES)
        query = f"SELECT service, client, {auth_col} FROM access WHERE service IN ({placeholders})"
        for service, client, value in cur.execute(query, tuple(SERVICES.keys())):
            if not _granted(auth_col, int(value)):
                continue
            label = SERVICES.get(service, service)
            is_apple = str(client).startswith("com.apple.")
            findings.append(
                Finding(
                    title=f"Holds '{label}' permission",
                    severity=Severity.LOW if is_apple else Severity.MEDIUM,
                    detector="Input permissions",
                    description=(
                        f"{scope}: '{client}' is granted {label}. "
                        + ("Apple system component." if is_apple else
                           "Confirm this is an app you installed and trust.")
                    ),
                    process_name=str(client),
                    recommendation=(
                        "Review under System Settings > Privacy & Security > "
                        f"{label}; revoke anything you don't recognise."
                    ),
                    details={"client": str(client), "service": service, "scope": scope},
                )
            )
    except Exception as exc:
        return findings, f"{scope}: TCC query failed ({exc})."
    finally:
        con.close()
    return findings, None


def scan() -> list[Finding]:
    findings: list[Finding] = []
    errors: list[str] = []
    for db_path, scope in ((USER_TCC, "user"), (SYSTEM_TCC, "system")):
        fs, err = _read_db(db_path, scope)
        findings.extend(fs)
        if err:
            errors.append(err)
    if errors:
        findings.append(
            Finding(
                title="Permission audit was limited",
                severity=Severity.INFO,
                detector="Input permissions",
                description=" ".join(errors),
                recommendation=(
                    "Grant Full Disk Access to the app/terminal running this tool "
                    "(System Settings > Privacy & Security > Full Disk Access) for a complete audit."
                ),
            )
        )
    return findings
