import json
import subprocess
import uuid
import os
from .firewall_worker import RULE_NAME_PATTERN, WORKER_PIPE, parse_public_ipv4


class FirewallWorkerError(RuntimeError):
    pass


class FirewallController:
    def __init__(self, use_worker: bool | None = None):
        self.use_worker = os.name == "nt" if use_worker is None else use_worker

    def block_remote(self, remote_ip: str) -> bool:
        address = parse_public_ipv4(remote_ip)
        if address is None:
            return False
        if self.use_worker:
            return self._request_worker({"operation": "add", "remote_ip": str(address)})
        rule = f"Morpheus-Block-{uuid.uuid4().hex[:12]}"
        result = subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=out", "action=block", f"remoteip={remote_ip}/32",
        ], capture_output=True, text=True)
        return result.returncode == 0

    def list_morpheus_rules(self):
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose"],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except subprocess.TimeoutExpired as exc:
            raise FirewallWorkerError("Windows Firewall did not respond within 3 seconds.") from exc
        if result.returncode:
            detail = result.stderr.strip() or "Windows Firewall rule listing failed."
            raise FirewallWorkerError(detail)
        rules = []
        current = None
        for line in result.stdout.splitlines():
            if line.startswith("Rule Name:"):
                current = line.split(":", 1)[1].strip()
            elif current and current.startswith("Morpheus-Block-") and line.strip().startswith("RemoteIP:"):
                rules.append({"name": current, "remote_ip": line.split(":", 1)[1].strip()})
                current = None
        return rules

    def remove_rule_by_name(self, name: str):
        if not isinstance(name, str) or not RULE_NAME_PATTERN.fullmatch(name):
            return False
        if self.use_worker:
            return self._request_worker({"operation": "remove", "name": name})
        result = subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], capture_output=True, text=True)
        return result.returncode == 0

    def worker_available(self) -> bool:
        if not self.use_worker:
            return False
        try:
            import pywintypes
            import win32pipe
            win32pipe.WaitNamedPipe(WORKER_PIPE, 200)
            return True
        except ImportError:
            return False
        except pywintypes.error:
            return False

    def worker_status(self) -> dict:
        if os.name != "nt":
            return {
                "available": False,
                "installed": False,
                "running": False,
                "message": "The privileged firewall service is available only in the Windows desktop app.",
            }
        try:
            import pywintypes
            import win32service
        except ImportError:
            return {
                "available": False,
                "installed": False,
                "running": False,
                "message": "Windows firewall service support is missing from this build.",
            }

        manager = None
        service = None
        try:
            manager = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CONNECT
            )
            service = win32service.OpenService(
                manager,
                "MorpheusFirewallWorker",
                win32service.SERVICE_QUERY_STATUS,
            )
            state = win32service.QueryServiceStatus(service)[1]
            running = state == win32service.SERVICE_RUNNING
            available = running and self.worker_available()
            return {
                "available": available,
                "installed": True,
                "running": running,
                "message": (
                    "The firewall service is ready."
                    if available
                    else "The firewall service is installed but stopped. Start it with administrator approval."
                    if not running
                    else "The service is running, but its local connection is unavailable. Restart Morpheus or the service."
                ),
            }
        except pywintypes.error as exc:
            if getattr(exc, "winerror", None) == 1060:
                message = "The firewall service is not installed. Reinstall the machine-wide Morpheus app."
                installed = False
            else:
                message = f"Could not check the firewall service (Windows error {getattr(exc, 'winerror', 'unknown')})."
                installed = True
            return {
                "available": False,
                "installed": installed,
                "running": False,
                "message": message,
            }
        finally:
            if service:
                win32service.CloseServiceHandle(service)
            if manager:
                win32service.CloseServiceHandle(manager)

    @staticmethod
    def _request_worker(request: dict) -> bool:
        try:
            import pywintypes
            import win32con
            import win32file
            import win32pipe
        except ImportError as exc:
            raise FirewallWorkerError("The Morpheus Windows firewall worker is not available in this build.") from exc
        try:
            win32pipe.WaitNamedPipe(WORKER_PIPE, 1500)
            pipe = win32file.CreateFile(
                WORKER_PIPE,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0,
                None,
                win32con.OPEN_EXISTING,
                0,
                None,
            )
        except pywintypes.error as exc:
            raise FirewallWorkerError(
                "The Morpheus firewall worker is not running. Reinstall Morpheus or start its Windows service."
            ) from exc

        try:
            win32pipe.SetNamedPipeHandleState(
                pipe, win32pipe.PIPE_READMODE_MESSAGE, None, None
            )
            win32file.WriteFile(pipe, json.dumps(request).encode("utf-8"))
            error, raw = win32file.ReadFile(pipe, 4096)
            if error or len(raw) >= 4096:
                raise FirewallWorkerError("The firewall worker returned an invalid response.")
            response = json.loads(raw.decode("utf-8"))
        except (OSError, pywintypes.error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FirewallWorkerError(f"Unable to communicate with the firewall worker: {exc}") from exc
        finally:
            win32file.CloseHandle(pipe)

        if not response.get("ok"):
            message = response.get("error", "The firewall worker rejected the request.")
            raise FirewallWorkerError(message)
        return bool(response.get("ok"))
