"""Scan LaunchAgents / LaunchDaemons / login items for keylogger persistence.

A logger that survives reboot needs a persistence mechanism. This surfaces
user and /Library launchd jobs (System ones are SIP-protected and trusted) plus
classic login items, grading by how the launched binary is signed.
"""
from __future__ import annotations

import os
import plistlib
import subprocess

from ...models import Finding, Severity
from ._system import is_trusted_path, trust_level

LAUNCHD_DIRS = [
    (os.path.expanduser("~/Library/LaunchAgents"), "user LaunchAgent"),
    ("/Library/LaunchAgents", "LaunchAgent"),
    ("/Library/LaunchDaemons", "LaunchDaemon"),
]


def _program(plist: dict) -> str | None:
    if plist.get("Program"):
        return plist["Program"]
    args = plist.get("ProgramArguments")
    if isinstance(args, list) and args:
        return args[0]
    return None


def _scan_launchd() -> list[Finding]:
    findings: list[Finding] = []
    for directory, kind in LAUNCHD_DIRS:
        if not os.path.isdir(directory):
            continue
        for entry in sorted(os.listdir(directory)):
            if not entry.endswith(".plist"):
                continue
            path = os.path.join(directory, entry)
            try:
                with open(path, "rb") as fh:
                    plist = plistlib.load(fh)
            except Exception:
                continue
            program = _program(plist)
            trust = trust_level(program)
            run_at_load = bool(plist.get("RunAtLoad"))
            if trust == "apple" or (program and is_trusted_path(program)):
                continue  # trusted system job
            if trust == "developer-id":
                severity = Severity.LOW
                note = "Signed third-party app - confirm it's expected."
            elif trust == "unknown":
                severity = Severity.MEDIUM
                note = "Launched binary could not be located."
            else:  # unsigned / dev / other
                severity = Severity.HIGH if run_at_load else Severity.MEDIUM
                note = "Unsigned or unrecognised binary set to persist."
            findings.append(
                Finding(
                    title=f"{kind}: {plist.get('Label', entry)}",
                    severity=severity,
                    detector="Persistence",
                    description=(
                        f"{kind} runs '{program or 'unknown'}'"
                        + (" at login/boot. " if run_at_load else ". ")
                        + note
                    ),
                    recommendation="If unexpected, unload with launchctl and delete the plist.",
                    details={
                        "plist": path,
                        "program": program or "unknown",
                        "signature_trust": trust,
                        "run_at_load": run_at_load,
                    },
                )
            )
    return findings


def _scan_login_items() -> list[Finding]:
    try:
        res = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get the name of every login item'],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return []
    if res.returncode != 0 or not res.stdout.strip():
        return []
    items = [x.strip() for x in res.stdout.strip().split(",") if x.strip()]
    return [
        Finding(
            title=f"Login item: {name}",
            severity=Severity.INFO,
            detector="Persistence",
            description=f"'{name}' launches at login. Confirm it's something you added.",
            process_name=name,
            recommendation="Remove under System Settings > General > Login Items if unexpected.",
            details={"login_item": name},
        )
        for name in items
    ]


def scan() -> list[Finding]:
    return _scan_launchd() + _scan_login_items()
