import argparse
import json
import base64
import hashlib
import hmac
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .engine import DefenseEngine
from .downloads import MAX_MONITORED_FILES, DownloadMonitor
from .code_review import CodeReview
from .local_assistant import OfflineAssistant
from .scanner import ProtectedSystemPathError, StaticScanner, is_protected_system_path
from .sysmon import SysmonStatus
from .timeline import AttackTimeline
from .quarantine import QuarantineManager
from .persistence import inspect_autostart_registry
from .defender_monitor import (
    DefenderHealthMonitor,
    scan_file_with_defender,
    update_defender_signatures,
)
from .clamav import ClamAVScanner
from .filesystem_monitor import SelectedFolderEventMonitor
from .models import (
    CodeReviewRequest,
    AssistantChatRequest,
    AntivirusScanRequest,
    ConfigUpdate,
    QuarantineRequest,
    ScanFileRequest,
    ScanFolderRequest,
    PasskeyCeremonyRequest,
    PasskeyRecoveryRequest,
    PasskeyRegistrationOptionsRequest,
    SettingsPasswordRequest,
)
from .tool_catalog import TOOL_CATALOG
from .expansion import DnsEntropyMonitor, PowerShellLogMonitor
from .network_guard import WindowsFirewallLogMonitor
from .canary import CanaryMonitor
from .risk import explainable_risk, protection_summary
from .auth import (
    AuthFailureLimiter,
    hash_owner_password,
    verify_owner_password,
)
from .passkeys import PasskeyManager

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
DATA_ROOT = Path(os.environ.get("MORPHEUS_DATA_DIR", ROOT / "data"))
CONFIG_PATH = Path(os.environ.get("MORPHEUS_CONFIG_PATH", ROOT / "config.json"))
if not CONFIG_PATH.exists():
    bundled_config = ROOT / "config.json"
    if not bundled_config.is_file():
        raise FileNotFoundError(f"Default configuration is missing: {bundled_config}")
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundled_config, CONFIG_PATH)
engine = DefenseEngine(DATA_ROOT, CONFIG_PATH)
scanner = StaticScanner()
clamav_binary_directory = os.environ.get("MORPHEUS_CLAMAV_DIR") or None
clamav_scanner = ClamAVScanner(
    binary_directory=clamav_binary_directory,
    data_directory=DATA_ROOT / "clamav" if clamav_binary_directory else None,
)
code_reviewer = CodeReview()
offline_helper = OfflineAssistant()
download_monitor = DownloadMonitor(
    scanner,
    engine.quarantine,
    engine.db,
    engine.journal,
    antivirus=clamav_scanner,
)
sysmon = SysmonStatus()
timeline = AttackTimeline(engine.db)
quarantine = engine.quarantine
dns_monitor = DnsEntropyMonitor()
powershell_monitor = PowerShellLogMonitor()
inbound_scan_monitor = WindowsFirewallLogMonitor()
canary_monitor = CanaryMonitor(DATA_ROOT / "canaries")
defender_health_monitor = DefenderHealthMonitor()
filesystem_event_monitor = SelectedFolderEventMonitor()
templates = Jinja2Templates(directory=str(ROOT / "morpheus" / "templates"))
app = FastAPI(title="Morpheus Defense", version="0.2.0")
_MORPHEUS_MUTATION_BUCKETS: dict[str, deque[float]] = {}
_MORPHEUS_MUTATION_RATE = 120
_MORPHEUS_MUTATION_WINDOW = 60.0

@app.middleware("http")
async def morpheus_loopback_guard(request: Request, call_next):
    host = request.headers.get("host", "").split(":", 1)[0].strip("[]").lower()
    if host not in {"localhost", "127.0.0.1", "::1", "testserver"}:
        return JSONResponse(status_code=403, content={"detail": "Morpheus only accepts loopback requests."})

    if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin:
            origin_host = urlsplit(origin).hostname
            if urlsplit(origin).scheme != "http" or origin_host not in {"localhost", "127.0.0.1", "::1"}:
                return JSONResponse(status_code=403, content={"detail": "Cross-origin request blocked."})

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = _MORPHEUS_MUTATION_BUCKETS.setdefault(client, deque())
        while bucket and now - bucket[0] >= _MORPHEUS_MUTATION_WINDOW:
            bucket.popleft()
        if len(bucket) >= _MORPHEUS_MUTATION_RATE:
            return JSONResponse(status_code=429, content={"detail": "Too many Morpheus mutation requests."})
        bucket.append(now)

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
worker_stop = threading.Event()
worker_wakeup = threading.Event()
worker_thread: threading.Thread | None = None
scan_lock = threading.Lock()
scan_cancel_event = threading.Event()
last_scan_at: str | None = None
last_scan_error: str | None = None
LOGGER = logging.getLogger(__name__)
SETTINGS_PASSWORD_PATH = DATA_ROOT / "settings-password.json"
PASSKEYS_PATH = DATA_ROOT / "passkeys.json"
CONFIG_WRITE_LOCK = threading.Lock()
AUTH_FAILURE_LIMITER = AuthFailureLimiter()
WEBAUTHN_ORIGIN = os.environ.get("MORPHEUS_WEBAUTHN_ORIGIN", "http://localhost:8080")
WEBAUTHN_RP_ID = "localhost"

def _write_json_file(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass

def _write_config_file(config: dict) -> None:
    _write_json_file(CONFIG_PATH, config)

passkey_manager = PasskeyManager(PASSKEYS_PATH, _write_json_file)

def _decode_base64url(value: str) -> bytes:
    if not value or len(value) > 8192:
        raise ValueError("Invalid WebAuthn credential data.")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

def _require_webauthn_origin(request: Request) -> None:
    try:
        parsed = urlsplit(WEBAUTHN_ORIGIN)
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="The configured passkey origin is invalid.") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != WEBAUTHN_RP_ID
        or port is None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or request.headers.get("origin") != WEBAUTHN_ORIGIN
        or request.headers.get("host") != parsed.netloc
    ):
        raise HTTPException(status_code=403, detail="This passkey request did not come from the trusted Morpheus origin.")

def _require_passkey_bootstrap(password: str | None, request: Request) -> None:
    _require_webauthn_origin(request)
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    record = read_settings_password()
    if record and not verify_settings_password(password, record):
        AUTH_FAILURE_LIMITER.record_failure(client)
        raise HTTPException(status_code=401, detail="Enter the current owner password to enroll the first passkey.")
    AUTH_FAILURE_LIMITER.record_success(client)
    if record and record.get("algorithm") == "pbkdf2_sha256":
        _migrate_owner_password_record(password, record)

def _migrate_owner_password_record(password: str | None, record: dict) -> None:
    if not password or record.get("algorithm") != "pbkdf2_sha256":
        return
    with CONFIG_WRITE_LOCK:
        latest = read_settings_password()
        if latest and verify_settings_password(password, latest) and latest.get("algorithm") == "pbkdf2_sha256":
            _write_json_file(SETTINGS_PASSWORD_PATH, {
                "algorithm": "argon2id",
                "hash": hash_owner_password(password),
            })

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(
        content='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="background" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#152a3a"/><stop offset="1" stop-color="#09111c"/></linearGradient><linearGradient id="mark" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#79d8f4"/><stop offset="1" stop-color="#f0ad57"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#background)"/><path d="M32 6 52 13v15c0 14-8.6 23.8-20 30C20.6 51.8 12 42 12 28V13L32 6Z" fill="#132332" stroke="#477087" stroke-width="1.5"/><path d="M20 41V21h5l7 10 7-10h5v20h-6V30l-6 8-6-8v11z" fill="url(#mark)"/><circle cx="47" cy="17" r="2" fill="#f0ad57"/></svg>',
        media_type="image/svg+xml",
    )

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    events = engine.db.list_events()
    config = engine.config()
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"events": events, "config": config})

@app.get("/api/events")
def events(limit: int = 200):
    return JSONResponse(engine.db.list_events(limit))

@app.get("/api/status")
def status():
    config = engine.config()
    risk_summary = explainable_risk(engine.db.list_events(200))
    quarantine_status = {
        "folder": str(quarantine.root),
        "categories": ["files", "apps", "folders"],
        "item_count": (
            len(list(quarantine.root.rglob("*.quarantine")))
            + len(list(quarantine.root.rglob("*.folder")))
        ),
        "category_counts": {
            category: sum(
                len(list((quarantine.root / category).rglob(suffix)))
                for suffix in ("*.quarantine", "*.folder")
            )
            for category in ("files", "apps", "folders")
        },
        "containment_failures": engine.containment_failures,
    }
    quarantine_status["total_size_bytes"] = sum(
        path.stat().st_size
        if path.is_file()
        else sum(child.stat().st_size for child in path.rglob("*") if child.is_file())
        for path in (
            list(quarantine.root.rglob("*.quarantine"))
            + list(quarantine.root.rglob("*.folder"))
        )
    )
    quarantine_status["containment_active"] = quarantine_status["item_count"] > 0
    return {
        "running": True,
        "event_count": engine.db.count(),
        "journal": engine.journal.status(),
        "sysmon": sysmon.status(),
        "config": config,
        "tool_watch": {
            "catalog_entries": len(TOOL_CATALOG),
            "categories": sorted({tool["category"] for tool in TOOL_CATALOG}),
            "scope": "running process names, executable paths, and transient command-pattern checks",
        },
        "monitoring": {
            "running": bool(worker_thread and worker_thread.is_alive() and not worker_stop.is_set()),
            "poll_interval_seconds": config["poll_interval_seconds"],
            "last_scan_at": last_scan_at,
            "last_error": last_scan_error,
            "downloads_enabled": config.get("download_monitoring", False),
            "download_directory": config.get("download_directory") or str(Path.home() / "Downloads"),
            "monitored_file_limit": MAX_MONITORED_FILES,
            "scan_max_file_bytes": int(config.get("scan_max_file_bytes", 512 * 1024 * 1024)),
            "scan_max_folder_bytes": int(config.get("scan_max_folder_bytes", 5 * 1024 * 1024 * 1024)),
            "scan_max_folder_files": int(config.get("scan_max_folder_files", 5000)),
            "scan_timeout_seconds": float(config.get("scan_timeout_seconds", 180)),
        },
        "expansion": {
            "dns": dns_monitor.status(bool(config.get("dns_entropy_monitoring", False))),
            "powershell": powershell_monitor.status(bool(config.get("powershell_log_monitoring", False))),
            "process_tree_enabled": bool(config.get("process_tree_monitoring", True)),
            "canary": canary_monitor.status(bool(config.get("canary_monitoring", False))),
            "inbound_scan": inbound_scan_monitor.status(bool(config.get("automatic_inbound_scan_blocking", False))),
        },
        "defender": defender_health_monitor.status(),
        "clamav": clamav_scanner.status(),
        "filesystem_monitor": filesystem_event_monitor.status(
            bool(config.get("download_monitoring", False))
        ),
        "risk": risk_summary,
        "quarantine": quarantine_status,
        "protection": protection_summary(
            config=config,
            defender=defender_health_monitor.status(),
            clamav=clamav_scanner.status(),
            monitoring_running=bool(worker_thread and worker_thread.is_alive() and not worker_stop.is_set()),
            passkey_configured=passkey_manager.status()["configured"],
            risk=risk_summary,
            isolation_item_count=quarantine_status["item_count"],
            containment_failures=engine.containment_failures,
        ),
    }

@app.get("/api/journal/verify")
def verify_journal():
    return engine.journal.verify()

@app.post("/api/scan")
def scan():
    detected = evaluate_processes()
    return {"detected": detected, "processes_checked": engine.last_process_count}

@app.post("/api/scan/cancel")
def cancel_active_scan(
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    scan_cancel_event.set()
    return {"cancelled": True}

@app.get("/api/timeline")
def attack_timeline(limit: int = 200):
    return [timeline.reconstruct(event) for event in engine.db.list_events(limit)]

@app.get("/api/process-tree")
def process_tree():
    return engine.latest_process_tree

@app.get("/api/persistence/startup")
def startup_persistence():
    return inspect_autostart_registry()

@app.get("/api/risk")
def risk_summary():
    return explainable_risk(engine.db.list_events(200))

@app.get("/api/protection")
def protection_status():
    config = engine.config()
    risk = explainable_risk(engine.db.list_events(200))
    item_count = len(list(quarantine.root.rglob("*.quarantine"))) + len(list(quarantine.root.rglob("*.folder")))
    return protection_summary(
        config=config,
        defender=defender_health_monitor.status(),
        clamav=clamav_scanner.status(),
        monitoring_running=bool(worker_thread and worker_thread.is_alive() and not worker_stop.is_set()),
        passkey_configured=passkey_manager.status()["configured"],
        risk=risk,
        isolation_item_count=item_count,
        containment_failures=engine.containment_failures,
    )

@app.get("/api/firewall/worker")
def firewall_worker_status():
    return engine.firewall.worker_status()

@app.post("/api/scan-file")
def scan_file(payload: ScanFileRequest):
    path = payload.path
    if not path:
        return JSONResponse({"error": "path is required"}, status_code=400)
    try:
        scan_cancel_event.clear()
        config = engine.config()
        return scanner.scan_file(
            Path(path),
            max_bytes=int(config.get("scan_max_file_bytes", 512 * 1024 * 1024)),
            timeout_seconds=float(config.get("scan_timeout_seconds", 180)),
            is_cancelled=scan_cancel_event.is_set,
        )
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (FileNotFoundError, OSError, PermissionError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.post("/api/scan-antivirus")
def scan_file_with_antivirus(payload: AntivirusScanRequest):
    try:
        scan_cancel_event.clear()
        config = engine.config()
        result = clamav_scanner.scan_file(
            Path(payload.path),
            max_bytes=int(config.get("scan_max_file_bytes", 512 * 1024 * 1024)),
        )
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if result["verdict"] == "infected":
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": "clamav_detection",
            "severity": "high",
            "source": "ClamAV signature scan",
            "target": Path(payload.path).name,
            "confidence": None,
            "evidence": json.dumps({
                "detections": result["detections"],
                "engine_version": result["engine_version"],
                "database_version": result["database_version"],
            }, sort_keys=True),
            "response": "review_required_manual_approval",
        }
        engine.db.add(event)
        engine.journal.append(event)
    return result

@app.post("/api/antivirus/clamav/update")
def update_clamav_signatures(
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    try:
        return clamav_scanner.update_signatures()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/api/antivirus/defender/scan")
def scan_file_with_windows_defender(payload: AntivirusScanRequest):
    try:
        config = engine.config()
        return scan_file_with_defender(
            Path(payload.path),
            max_bytes=int(config.get("scan_max_file_bytes", 512 * 1024 * 1024)),
        )
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/api/antivirus/defender/update")
def update_windows_defender_signatures(
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    try:
        return update_defender_signatures()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/api/scan-folder")
def scan_folder(payload: ScanFolderRequest):
    try:
        scan_cancel_event.clear()
        config = engine.config()
        return scanner.scan_folder(
            Path(payload.path),
            max_file_bytes=int(config.get("scan_max_file_bytes", 512 * 1024 * 1024)),
            max_folder_bytes=int(config.get("scan_max_folder_bytes", 5 * 1024 * 1024 * 1024)),
            max_files=int(config.get("scan_max_folder_files", 5000)),
            timeout_seconds=float(config.get("scan_timeout_seconds", 180)),
            is_cancelled=scan_cancel_event.is_set,
        )
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (FileNotFoundError, OSError, PermissionError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.post("/api/review-code")
def review_code(payload: CodeReviewRequest):
    try:
        return code_reviewer.review_path(payload.path)
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=404, detail=f"Could not read the selected source path: {exc}") from exc

@app.get("/api/assistant/status")
def assistant_status():
    return offline_helper.status()

@app.post("/api/assistant/chat")
def assistant_chat(payload: AssistantChatRequest):
    answer = offline_helper.chat(payload.message)
    return {"model": "Morpheus offline helper", "answer": answer}

@app.post("/api/scan-upload")
def scan_upload(file: UploadFile = File(...)):
    name = file.filename or "selected file"
    try:
        scan_cancel_event.clear()
        config = engine.config()
        return scanner.scan_stream(
            file.file,
            name,
            max_bytes=int(config.get("scan_max_file_bytes", 512 * 1024 * 1024)),
            timeout_seconds=float(config.get("scan_timeout_seconds", 180)),
            is_cancelled=scan_cancel_event.is_set,
        )
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

@app.get("/api/sysmon")
def sysmon_status():
    return {**sysmon.status(), "install_help": sysmon.install_help()}

@app.get("/api/quarantine")
def list_quarantine():
    items = []
    for path in list(quarantine.root.rglob("*.quarantine")) + list(quarantine.root.rglob("*.folder")):
        category = path.parent.name if path.parent.name in {"files", "apps", "folders"} else "files"
        metadata_path = path.with_suffix(".json")
        original = ""
        if metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                original = metadata.get("original", "")
            except (OSError, json.JSONDecodeError):
                pass
        items.append({
            "name": path.name,
            "size": path.stat().st_size if path.is_file() else sum(p.stat().st_size for p in path.rglob("*") if p.is_file()),
            "modified": path.stat().st_mtime,
            "category": category,
            "token": path.stem,
            "original": original,
            "kind": "folder" if path.suffix == ".folder" else "file",
        })
    return items

@app.get("/api/quarantine/status")
def quarantine_status():
    category_counts = {}
    for category in ("files", "apps", "folders"):
        suffixes = ("*.quarantine", "*.folder") if category == "folders" else ("*.quarantine",)
        category_counts[category] = sum(
            len(list((quarantine.root / category).rglob(suffix)))
            for suffix in suffixes
        )
    items = list(quarantine.root.rglob("*.quarantine")) + list(quarantine.root.rglob("*.folder"))
    total_size = 0
    for path in items:
        try:
            total_size += (
                path.stat().st_size
                if path.is_file()
                else sum(child.stat().st_size for child in path.rglob("*") if child.is_file())
            )
        except OSError:
            continue
    return {
        "folder": str(quarantine.root),
        "categories": ["files", "apps", "folders"],
        "item_count": len(list(quarantine.root.rglob("*.quarantine"))) + len(list(quarantine.root.rglob("*.folder"))),
        "category_counts": category_counts,
        "total_size_bytes": total_size,
        "containment_active": bool(items),
        "containment_failures": engine.containment_failures,
    }

@app.post("/api/quarantine")
def quarantine_file(
    payload: QuarantineRequest,
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    path = payload.path
    if not path:
        return JSONResponse({"error": "path is required"}, status_code=400)
    try:
        resolved = Path(path)
        resolved = resolved.resolve()
        if resolved == Path(resolved.anchor) or is_protected_system_path(resolved, resolve=False):
            return JSONResponse({"error": "Drive roots and protected Windows folders cannot be isolated."}, status_code=403)
        if quarantine.root in resolved.parents or resolved == quarantine.root:
            return JSONResponse({"error": "Morpheus isolated storage cannot be isolated."}, status_code=403)
        if resolved.is_dir():
            return quarantine.quarantine_folder(resolved)
        category = "apps" if resolved.suffix.casefold() in {".exe", ".dll", ".sys", ".com"} else "files"
        return quarantine.quarantine(resolved, category=category)
    except (FileNotFoundError, OSError, PermissionError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.post("/api/quarantine/{token}/restore")
def restore_quarantine(
    token: str,
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    try:
        return quarantine.restore(token)
    except (FileNotFoundError, OSError, PermissionError, json.JSONDecodeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.post("/api/quarantine/{token}/delete")
def delete_quarantine(
    token: str,
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    return quarantine.delete(token)

@app.post("/api/config")
def set_config(
    payload: ConfigUpdate,
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    require_sensitive_authorization(x_morpheus_authorization, request)
    with CONFIG_WRITE_LOCK:
        config = engine.config()
        config.update(payload.model_dump(exclude_none=True))
        _write_config_file(config)
    return config

def read_settings_password():
    if not SETTINGS_PASSWORD_PATH.exists():
        return None
    return json.loads(SETTINGS_PASSWORD_PATH.read_text(encoding="utf-8"))

def verify_settings_password(password: str | None, record: dict) -> bool:
    if not password:
        return False
    if record.get("algorithm") == "argon2id":
        encoded_hash = record.get("hash")
        return isinstance(encoded_hash, str) and verify_owner_password(password, encoded_hash)
    if record.get("algorithm") != "pbkdf2_sha256":
        return False
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["hash"], validate=True)
        iterations = int(record["iterations"])
        if not 100_000 <= iterations <= 1_200_000 or len(expected) != 32:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)

def _client_auth_key(request: Request) -> str:
    if request.client is None or not request.client.host:
        return "unknown"
    return request.client.host

def _check_auth_throttle(client: str) -> None:
    retry_after = AUTH_FAILURE_LIMITER.seconds_until_allowed(client)
    if retry_after > 0:
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts. Try again later.",
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )

def require_sensitive_authorization(token: str | None, request: Request):
    client = _client_auth_key(request)
    if not passkey_manager.status()["configured"]:
        raise HTTPException(status_code=403, detail="Enroll a passkey before making sensitive changes.")
    if not passkey_manager.consume_grant(token, client):
        raise HTTPException(status_code=401, detail="A valid, unused passkey approval is required.")

@app.get("/api/passkeys/status")
def passkey_status():
    return passkey_manager.status()

@app.post("/api/passkeys/registration/options")
def passkey_registration_options(
    payload: PasskeyRegistrationOptionsRequest,
    request: Request,
    x_morpheus_authorization: str | None = Header(default=None),
):
    _require_webauthn_origin(request)
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    current_status = passkey_manager.status()
    if current_status["configured"]:
        if not passkey_manager.consume_grant(x_morpheus_authorization, client):
            raise HTTPException(status_code=401, detail="A passkey approval is required to add another passkey.")
    else:
        _require_passkey_bootstrap(payload.bootstrap_password, request)

    try:
        options = generate_registration_options(
            rp_id=WEBAUTHN_RP_ID,
            rp_name="Morpheus Defense",
            user_id=hashlib.sha256(b"morpheus-local-owner").digest(),
            user_name="owner@localhost",
            user_display_name="Morpheus owner",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=f"Could not start passkey enrollment: {exc}") from exc
    ceremony_id = passkey_manager.create_challenge("registration", options.challenge, client)
    return {"ceremony_id": ceremony_id, "public_key": json.loads(options_to_json(options))}

@app.post("/api/passkeys/registration/verify")
def verify_passkey_registration(payload: PasskeyCeremonyRequest, request: Request):
    _require_webauthn_origin(request)
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    challenge = passkey_manager.consume_challenge(payload.ceremony_id, "registration", client)
    if challenge is None:
        raise HTTPException(status_code=400, detail="The passkey enrollment challenge expired or was already used.")
    try:
        verified = verify_registration_response(
            credential=payload.credential,
            expected_challenge=challenge,
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError) as exc:
        client = _client_auth_key(request)
        AUTH_FAILURE_LIMITER.record_failure(client)
        raise HTTPException(status_code=400, detail="Passkey registration could not be verified.") from exc
    if not verified.user_verified:
        raise HTTPException(status_code=400, detail="The authenticator did not verify the owner.")
    credential = {
        "credential_id": _encode_base64url(verified.credential_id),
        "public_key": _encode_base64url(verified.credential_public_key),
        "sign_count": verified.sign_count,
    }
    try:
        recovery_codes = passkey_manager.add_credential(credential)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    AUTH_FAILURE_LIMITER.record_success(client)
    return {"configured": True, "recovery_codes": recovery_codes}

@app.post("/api/passkeys/authentication/options")
def passkey_authentication_options(request: Request):
    _require_webauthn_origin(request)
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    credentials = passkey_manager.credentials()
    if not credentials:
        raise HTTPException(status_code=403, detail="Enroll a passkey before requesting approval.")
    options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=_decode_base64url(item["credential_id"]))
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    ceremony_id = passkey_manager.create_challenge("authentication", options.challenge, client)
    return {"ceremony_id": ceremony_id, "public_key": json.loads(options_to_json(options))}

@app.post("/api/passkeys/authentication/verify")
def verify_passkey_authentication(payload: PasskeyCeremonyRequest, request: Request):
    _require_webauthn_origin(request)
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    challenge = passkey_manager.consume_challenge(payload.ceremony_id, "authentication", client)
    if challenge is None:
        AUTH_FAILURE_LIMITER.record_failure(client)
        raise HTTPException(status_code=400, detail="The passkey approval challenge expired or was already used.")
    try:
        credential_id = _encode_base64url(_decode_base64url(payload.credential["rawId"]))
        credential = passkey_manager.get_credential(credential_id)
        if credential is None:
            raise ValueError("The passkey is not registered.")
        verified = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=challenge,
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=_decode_base64url(credential["public_key"]),
            credential_current_sign_count=int(credential.get("sign_count", 0)),
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError) as exc:
        AUTH_FAILURE_LIMITER.record_failure(client)
        raise HTTPException(status_code=401, detail="Passkey approval could not be verified.") from exc
    if not verified.user_verified or not passkey_manager.update_sign_count(
        credential_id,
        verified.new_sign_count,
    ):
        AUTH_FAILURE_LIMITER.record_failure(client)
        raise HTTPException(status_code=401, detail="Passkey verification failed; use a different registered authenticator.")
    AUTH_FAILURE_LIMITER.record_success(client)
    return {"authorization": passkey_manager.issue_grant(client), "expires_in_seconds": 60}

@app.post("/api/passkeys/recovery")
def recover_passkey_access(payload: PasskeyRecoveryRequest, request: Request):
    _require_webauthn_origin(request)
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    if not passkey_manager.consume_recovery_code(payload.code):
        AUTH_FAILURE_LIMITER.record_failure(client)
        raise HTTPException(status_code=401, detail="The recovery code is invalid or has already been used.")
    AUTH_FAILURE_LIMITER.record_success(client)
    return {"authorization": passkey_manager.issue_grant(client), "expires_in_seconds": 60}

@app.get("/api/settings-password/status")
def settings_password_status():
    return {"configured": read_settings_password() is not None}

@app.post("/api/settings-password")
def set_settings_password(payload: SettingsPasswordRequest, request: Request):
    client = _client_auth_key(request)
    _check_auth_throttle(client)
    with CONFIG_WRITE_LOCK:
        current = read_settings_password()
        if passkey_manager.status()["configured"]:
            require_sensitive_authorization(
                request.headers.get("x-morpheus-authorization"),
                request,
            )
        if current and not verify_settings_password(payload.current_password, current):
            AUTH_FAILURE_LIMITER.record_failure(client)
            raise HTTPException(status_code=401, detail="The current owner settings password is incorrect.")
        AUTH_FAILURE_LIMITER.record_success(client)
        _write_json_file(SETTINGS_PASSWORD_PATH, {
            "algorithm": "argon2id",
            "hash": hash_owner_password(payload.password),
        })
    return {"configured": True}

def evaluate_processes():
    global last_scan_at, last_scan_error
    with scan_lock:
        try:
            detections = engine.evaluate_once()
            config = engine.config()
            if config.get("dns_entropy_monitoring", False):
                try:
                    detections.extend(dns_monitor.poll(engine.db, engine.journal))
                except Exception:
                    LOGGER.exception("DNS cache monitoring failed")
            else:
                dns_monitor.suspend()
            if config.get("powershell_log_monitoring", False):
                try:
                    detections.extend(powershell_monitor.poll(engine.db, engine.journal))
                except Exception:
                    LOGGER.exception("PowerShell event-log monitoring failed")
            else:
                powershell_monitor.suspend()
            if config.get("canary_monitoring", False):
                try:
                    detections.extend(canary_monitor.poll(engine.db, engine.journal))
                except Exception:
                    LOGGER.exception("Canary file monitoring failed")
            try:
                detections.extend(inbound_scan_monitor.poll(
                    config,
                    engine.firewall,
                    engine.db,
                    engine.journal,
                ))
            except Exception:
                LOGGER.exception("Inbound firewall log monitoring failed")
        except Exception as exc:
            last_scan_error = str(exc)
            raise
        last_scan_at = datetime.now(timezone.utc).isoformat()
        last_scan_error = None
        return detections

def worker():
    last_process_scan: float | None = None
    last_download_scan: float | None = None
    last_download_root: str | None = None
    while not worker_stop.is_set():
        try:
            config = engine.config()
            interval = config["poll_interval_seconds"]
            now = time.monotonic()
            process_scan_due = (
                last_process_scan is None
                or now - last_process_scan >= interval
            )
            if process_scan_due:
                evaluate_processes()
                last_process_scan = now

            configured_download_root = str(
                Path(config.get("download_directory") or Path.home() / "Downloads").expanduser()
            )
            if not config.get("download_monitoring", False):
                last_download_scan = None
                last_download_root = None
            periodic_download_scan_due = (
                config.get("download_monitoring", False)
                and (
                    last_download_scan is None
                    or configured_download_root != last_download_root
                    or now - last_download_scan >= interval
                )
            )
            if periodic_download_scan_due:
                download_monitor.scan_new_downloads(config)
                last_download_scan = now
                last_download_root = configured_download_root

            filesystem_scan_due = filesystem_event_monitor.poll(config, worker_wakeup)
            if filesystem_scan_due and not periodic_download_scan_due:
                download_monitor.scan_new_downloads(config)

            defender_health_monitor.poll(engine.db, engine.journal)
        except Exception:
            LOGGER.exception("Background security monitoring failed")
        try:
            interval = engine.config()["poll_interval_seconds"]
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            LOGGER.exception("Unable to read the background scan interval")
            interval = 5
        watcher_delay = filesystem_event_monitor.seconds_until_scan()
        if watcher_delay is not None:
            interval = min(interval, max(watcher_delay, 0.1))
        worker_wakeup.wait(interval)
        worker_wakeup.clear()

@app.on_event("startup")
def start_worker():
    global worker_thread
    worker_stop.clear()
    worker_wakeup.clear()
    if worker_thread and worker_thread.is_alive():
        return
    worker_thread = threading.Thread(target=worker, name="morpheus-collector", daemon=True)
    worker_thread.start()

@app.on_event("shutdown")
def stop_worker():
    worker_stop.set()
    worker_wakeup.set()
    filesystem_event_monitor.stop()
    if worker_thread:
        worker_thread.join(timeout=2)

def cli():
    parser = argparse.ArgumentParser(prog="morpheus")
    parser.add_argument("--serve", action="store_true", help="Run API and dashboard")
    parser.add_argument("--scan", action="store_true", help="Run one scan")
    args = parser.parse_args()

    if args.scan:
        print(json.dumps(engine.evaluate_once(), indent=2))
    elif args.serve:
        uvicorn.run(app, host="127.0.0.1", port=8080)
    else:
        parser.print_help()
