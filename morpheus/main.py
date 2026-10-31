import argparse
import json
import base64
import hashlib
import hmac
import logging
import os
import secrets
import shutil
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from .engine import DefenseEngine
from .downloads import DownloadMonitor
from .code_review import CodeReview
from .local_assistant import LocalAssistant, LocalAssistantError
from .scanner import MAX_SCAN_FILE_SIZE, ProtectedSystemPathError, StaticScanner
from .sysmon import SysmonStatus
from .timeline import AttackTimeline
from .quarantine import QuarantineManager
from .models import (
    CodeReviewRequest,
    AssistantChatRequest,
    ConfigUpdate,
    FirewallRuleRequest,
    QuarantineRequest,
    ScanFileRequest,
    ScanFolderRequest,
    SettingsPasswordRequest,
)
from .firewall import FirewallWorkerError
from .firewall_worker import parse_public_ip
from .tool_catalog import TOOL_CATALOG
from .expansion import DnsEntropyMonitor, PowerShellLogMonitor
from .canary import CanaryMonitor
from .risk import explainable_risk

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
code_reviewer = CodeReview()
local_assistant = LocalAssistant()
download_monitor = DownloadMonitor(scanner, engine.quarantine, engine.db, engine.journal)
sysmon = SysmonStatus()
timeline = AttackTimeline(engine.db)
quarantine = QuarantineManager(DATA_ROOT / "quarantine")
dns_monitor = DnsEntropyMonitor()
powershell_monitor = PowerShellLogMonitor()
canary_monitor = CanaryMonitor(DATA_ROOT / "canaries")
templates = Jinja2Templates(directory=str(ROOT / "morpheus" / "templates"))
app = FastAPI(title="Morpheus Defense", version="0.1.0")
worker_stop = threading.Event()
worker_thread: threading.Thread | None = None
scan_lock = threading.Lock()
last_scan_at: str | None = None
last_scan_error: str | None = None
MAX_UPLOAD_SIZE = MAX_SCAN_FILE_SIZE
LOGGER = logging.getLogger(__name__)
SETTINGS_PASSWORD_PATH = DATA_ROOT / "settings-password.json"
PASSWORD_HASH_ITERATIONS = 600_000

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(
        content='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#07111f"/><path d="M12 48V16h8l12 15 12-15h8v32h-9V30L32 42 21 30v18z" fill="#66e3ff"/><circle cx="52" cy="12" r="5" fill="#7cf2bd"/></svg>',
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
        },
        "expansion": {
            "dns": dns_monitor.status(bool(config.get("dns_entropy_monitoring", False))),
            "powershell": powershell_monitor.status(bool(config.get("powershell_log_monitoring", False))),
            "process_tree_enabled": bool(config.get("process_tree_monitoring", True)),
            "canary": canary_monitor.status(bool(config.get("canary_monitoring", False))),
        },
        "risk": explainable_risk(engine.db.list_events(200)),
    }

@app.get("/api/journal/verify")
def verify_journal():
    return engine.journal.verify()

@app.post("/api/scan")
def scan():
    return {"detected": evaluate_processes()}

@app.get("/api/timeline")
def attack_timeline(limit: int = 200):
    return [timeline.reconstruct(event) for event in engine.db.list_events(limit)]

@app.get("/api/process-tree")
def process_tree():
    return engine.latest_process_tree

@app.get("/api/risk")
def risk_summary():
    return explainable_risk(engine.db.list_events(200))

@app.post("/api/scan-file")
def scan_file(payload: ScanFileRequest):
    path = payload.path
    if not path:
        return JSONResponse({"error": "path is required"}, status_code=400)
    try:
        return scanner.scan_file(Path(path))
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (FileNotFoundError, OSError, PermissionError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.post("/api/scan-folder")
def scan_folder(payload: ScanFolderRequest):
    try:
        return scanner.scan_folder(Path(payload.path))
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
    return local_assistant.status()

@app.post("/api/assistant/chat")
def assistant_chat(payload: AssistantChatRequest):
    try:
        answer = local_assistant.chat(
            payload.model,
            payload.message,
            [message.model_dump() for message in payload.history],
        )
        return {"model": payload.model, "answer": answer}
    except LocalAssistantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

@app.post("/api/scan-upload")
def scan_upload(file: UploadFile = File(...)):
    limit_mb = max(1, (MAX_UPLOAD_SIZE + 1024 * 1024 - 1) // (1024 * 1024))
    if file.size is not None and file.size > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds the {limit_mb} MB per-file scan limit.")
    content = file.file.read(MAX_UPLOAD_SIZE + 1)
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds the {limit_mb} MB per-file scan limit.")
    name = file.filename or "selected file"
    try:
        return scanner.scan_bytes(content, name)
    except ProtectedSystemPathError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

@app.get("/api/sysmon")
def sysmon_status():
    return {**sysmon.status(), "install_help": sysmon.install_help()}

@app.get("/api/quarantine")
def list_quarantine():
    items = []
    for path in quarantine.root.glob("*.quarantine"):
        items.append({"name": path.name, "size": path.stat().st_size, "modified": path.stat().st_mtime})
    return items

@app.post("/api/quarantine")
def quarantine_file(payload: QuarantineRequest):
    path = payload.path
    if not path:
        return JSONResponse({"error": "path is required"}, status_code=400)
    try:
        return quarantine.quarantine(Path(path))
    except (FileNotFoundError, OSError, PermissionError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.get("/api/firewall")
def firewall_rules():
    try:
        return engine.firewall.list_morpheus_rules()
    except FirewallWorkerError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/api/firewall/worker")
def firewall_worker_status():
    return engine.firewall.worker_status()

@app.post("/api/firewall")
def add_firewall_rule(
    payload: FirewallRuleRequest,
    x_morpheus_settings_password: str | None = Header(default=None),
):
    require_settings_password(x_morpheus_settings_password)
    address = parse_public_ip(payload.remote_ip)
    if address is None:
        raise HTTPException(status_code=422, detail="Only globally routable IPv4 or IPv6 addresses can be blocked.")
    try:
        added = engine.firewall.block_remote(str(address))
    except FirewallWorkerError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not added:
        raise HTTPException(status_code=503, detail="The firewall worker could not add the requested rule.")
    return {"added": True}

@app.delete("/api/firewall/{name}")
def remove_firewall_rule(
    name: str,
    x_morpheus_settings_password: str | None = Header(default=None),
):
    require_settings_password(x_morpheus_settings_password)
    try:
        removed = engine.firewall.remove_rule_by_name(name)
    except FirewallWorkerError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(status_code=404, detail="The Morpheus firewall rule was not found or could not be removed.")
    return {"removed": True}

@app.post("/api/quarantine/{token}/restore")
def restore_quarantine(token: str):
    try:
        return quarantine.restore(token)
    except (FileNotFoundError, OSError, PermissionError, json.JSONDecodeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

@app.post("/api/quarantine/{token}/delete")
def delete_quarantine(token: str):
    return quarantine.delete(token)

@app.post("/api/config")
def set_config(payload: ConfigUpdate, x_morpheus_settings_password: str | None = Header(default=None)):
    require_settings_password(x_morpheus_settings_password)
    config = engine.config()
    for key, value in payload.model_dump(exclude_none=True).items():
        config[key] = value
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config

def read_settings_password():
    if not SETTINGS_PASSWORD_PATH.exists():
        return None
    return json.loads(SETTINGS_PASSWORD_PATH.read_text(encoding="utf-8"))

def verify_settings_password(password: str | None, record: dict) -> bool:
    if not password or record.get("algorithm") != "pbkdf2_sha256":
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

def require_settings_password(password: str | None):
    record = read_settings_password()
    if record and not verify_settings_password(password, record):
        raise HTTPException(status_code=401, detail="A valid owner settings password is required.")

@app.get("/api/settings-password/status")
def settings_password_status():
    return {"configured": read_settings_password() is not None}

@app.post("/api/settings-password")
def set_settings_password(payload: SettingsPasswordRequest):
    current = read_settings_password()
    if current and not verify_settings_password(payload.current_password, current):
        raise HTTPException(status_code=401, detail="The current owner settings password is incorrect.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", payload.password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    SETTINGS_PASSWORD_PATH.write_text(json.dumps({
        "algorithm": "pbkdf2_sha256",
        "iterations": PASSWORD_HASH_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }), encoding="utf-8")
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
        except Exception as exc:
            last_scan_error = str(exc)
            raise
        last_scan_at = datetime.now(timezone.utc).isoformat()
        last_scan_error = None
        return detections

def worker():
    while not worker_stop.is_set():
        try:
            evaluate_processes()
            download_monitor.scan_new_downloads(engine.config())
        except Exception:
            LOGGER.exception("Background security monitoring failed")
        try:
            interval = engine.config()["poll_interval_seconds"]
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            LOGGER.exception("Unable to read the background scan interval")
            interval = 5
        worker_stop.wait(interval)

@app.on_event("startup")
def start_worker():
    global worker_thread
    if worker_thread and worker_thread.is_alive():
        return
    worker_stop.clear()
    worker_thread = threading.Thread(target=worker, name="morpheus-collector", daemon=True)
    worker_thread.start()

@app.on_event("shutdown")
def stop_worker():
    worker_stop.set()
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
