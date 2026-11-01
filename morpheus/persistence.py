import os
from typing import Any


AUTOSTART_KEYS = (
    ("current_user", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("current_user", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("local_machine", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("local_machine", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    (
        "local_machine",
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
)
MAX_AUTOSTART_ENTRIES = 500
MAX_COMMAND_LENGTH = 4096


def inspect_autostart_registry(registry: Any | None = None) -> dict:
    if os.name != "nt" and registry is None:
        return {
            "available": False,
            "entries": [],
            "failures": [],
            "message": "Windows startup registry review is available only on Windows.",
        }

    if registry is None:
        import winreg as registry

    roots = {
        "current_user": registry.HKEY_CURRENT_USER,
        "local_machine": registry.HKEY_LOCAL_MACHINE,
    }
    entries = []
    failures = []
    truncated = False

    for scope, subkey in AUTOSTART_KEYS:
        display_path = f"{scope}\\{subkey}"
        try:
            with registry.OpenKey(roots[scope], subkey) as key:
                value_count = registry.QueryInfoKey(key)[1]
                for index in range(value_count):
                    if len(entries) >= MAX_AUTOSTART_ENTRIES:
                        truncated = True
                        break
                    try:
                        name, command, _value_type = registry.EnumValue(key, index)
                    except OSError as exc:
                        failures.append({
                            "location": display_path,
                            "message": str(exc),
                        })
                        continue
                    entries.append({
                        "scope": scope,
                        "location": display_path,
                        "name": str(name)[:256],
                        "command": str(command)[:MAX_COMMAND_LENGTH],
                        "command_truncated": len(str(command)) > MAX_COMMAND_LENGTH,
                    })
        except FileNotFoundError:
            continue
        except OSError as exc:
            failures.append({
                "location": display_path,
                "message": str(exc),
            })
        if truncated:
            break

    return {
        "available": True,
        "entries": entries,
        "failures": failures,
        "truncated": truncated,
        "message": (
            "Read-only registry inventory. Entries are not malware verdicts; "
            "review names and commands you do not recognize."
        ),
    }
