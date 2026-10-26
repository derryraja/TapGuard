"""Detect keyboard interception via Core Graphics event taps.

Core signal: macOS exposes every registered event tap through
``CGGetEventTapList``. A process holding a tap on keyboard events
(``kCGEventKeyDown`` / ``kCGEventKeyUp`` / ``kCGEventFlagsChanged``) is seeing
your keystrokes. Some are legitimate (text expanders, remappers, accessibility
tools); the detector reports them all and grades severity by how well the
responsible process is signed, so a human can judge.
"""
from __future__ import annotations

from ...models import Finding, Severity
from ._system import process_exe, process_name, trust_level

# CGEventType values -> a CGEventMask bit is (1 << type).
_KEY_DOWN = 10
_KEY_UP = 11
_FLAGS_CHANGED = 12
KEYBOARD_MASK = (1 << _KEY_DOWN) | (1 << _KEY_UP) | (1 << _FLAGS_CHANGED)

_OPTION_LISTEN_ONLY = 1  # kCGEventTapOptionListenOnly; 0 = active (can modify)

_TRUST_SEVERITY = {
    "apple": Severity.INFO,
    "developer-id": Severity.MEDIUM,
    "dev": Severity.HIGH,
    "other": Severity.HIGH,
    "unsigned": Severity.HIGH,
    "unknown": Severity.HIGH,
}

_TRUST_NOTE = {
    "apple": "Signed by Apple (a system component).",
    "developer-id": "Signed with a Developer ID - a known third-party app. Confirm you installed it on purpose.",
    "dev": "Development-signed, not notarised. Treat with suspicion unless it's your own build.",
    "other": "Signed by an unrecognised authority.",
    "unsigned": "Unsigned binary - a strong red flag for a keyboard tap.",
    "unknown": "Could not locate or verify the binary.",
}


def scan() -> list[Finding]:
    try:
        import Quartz  # lazy: missing pyobjc becomes a clean finding, not a crash
    except Exception as exc:
        return [
            Finding(
                title="Event-tap scan unavailable",
                severity=Severity.INFO,
                detector="Event taps",
                description=f"Could not import the Quartz framework (pyobjc): {exc}",
                recommendation="Install dependencies: pip install -r requirements.txt",
            )
        ]

    err, taps, _count = Quartz.CGGetEventTapList(1024, None, None)
    if err != 0 or taps is None:
        return [
            Finding(
                title="Event-tap scan returned no data",
                severity=Severity.INFO,
                detector="Event taps",
                description=f"CGGetEventTapList returned error code {err}.",
            )
        ]

    findings: list[Finding] = []
    for tap in taps:
        events = int(getattr(tap, "eventsOfInterest", 0))
        if not (events & KEYBOARD_MASK):
            continue

        pid = int(getattr(tap, "tappingProcess", 0))
        listen_only = int(getattr(tap, "options", 0)) == _OPTION_LISTEN_ONLY
        enabled = bool(getattr(tap, "enabled", False))

        name = process_name(pid) or "unknown"
        exe = process_exe(pid)
        trust = trust_level(exe)
        severity = _TRUST_SEVERITY.get(trust, Severity.HIGH)

        mode = "listen-only" if listen_only else "active (can modify events)"
        findings.append(
            Finding(
                title="Keyboard event tap",
                severity=severity,
                detector="Event taps",
                description=(
                    f"'{name}' holds a {mode} event tap on keyboard events "
                    f"({'enabled' if enabled else 'disabled'}). {_TRUST_NOTE.get(trust, '')}"
                ),
                process_name=name,
                pid=pid or None,
                recommendation=(
                    "If you don't recognise this process, quit it and remove the app; "
                    "then check it isn't set to relaunch (see persistence findings)."
                ),
                details={
                    "executable": exe or "unknown",
                    "signature_trust": trust,
                    "tap_mode": mode,
                    "enabled": enabled,
                    "events_mask": hex(events),
                },
            )
        )

    return findings
