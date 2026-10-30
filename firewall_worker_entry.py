import json
import sys
import winreg

import win32api
import pywintypes
import win32con
import win32event
import win32file
import win32pipe
import win32security
import win32service
import win32serviceutil
import winerror
import servicemanager

from morpheus.firewall import FirewallController
from morpheus.firewall_worker import (
    WORKER_PIPE,
    handle_worker_request,
    run_service_mode_if_needed,
)


class MorpheusFirewallWorker(win32serviceutil.ServiceFramework):
    _svc_name_ = "MorpheusFirewallWorker"
    _svc_display_name_ = "Morpheus Firewall Worker"
    _svc_description_ = "Applies allowlisted Morpheus firewall rules."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        firewall = FirewallController(use_worker=False)
        while win32event.WaitForSingleObject(self.stop_event, 0) == win32event.WAIT_TIMEOUT:
            pipe = self._create_pipe()
            try:
                while True:
                    try:
                        win32pipe.ConnectNamedPipe(pipe, None)
                        break
                    except pywintypes.error as exc:
                        if exc.winerror == winerror.ERROR_PIPE_CONNECTED:
                            break
                        if exc.winerror != winerror.ERROR_PIPE_LISTENING:
                            raise
                        if win32event.WaitForSingleObject(self.stop_event, 100) == win32event.WAIT_OBJECT_0:
                            return
                self._serve_request(pipe, firewall)
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(pipe)
                except pywintypes.error:
                    pass
                win32file.CloseHandle(pipe)

    @staticmethod
    def _create_pipe():
        descriptor = win32security.SECURITY_DESCRIPTOR()
        descriptor.Initialize()
        acl = win32security.ACL()
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\MorpheusFirewallWorker\Parameters",
            ) as key:
                owner_sid_text = winreg.QueryValueEx(key, "OwnerSid")[0]
            allowed_sids = [
                win32security.ConvertStringSidToSid(owner_sid_text),
                win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None),
            ]
        except (OSError, ValueError) as exc:
            raise RuntimeError("The firewall worker owner SID is not configured.") from exc
        for sid in allowed_sids:
            acl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                sid,
            )
        descriptor.SetSecurityDescriptorDacl(1, acl, 0)
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = descriptor
        attributes.bInheritHandle = False
        return win32pipe.CreateNamedPipe(
            WORKER_PIPE,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_NOWAIT,
            1,
            8192,
            8192,
            0,
            attributes,
        )

    @staticmethod
    def _serve_request(pipe, firewall):
        win32pipe.SetNamedPipeHandleState(
            pipe, win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT, None, None
        )
        error, raw = win32file.ReadFile(pipe, 4096)
        if error or len(raw) >= 4096:
            response = {"ok": False, "error": "Request is invalid or too large."}
        else:
            try:
                request = json.loads(raw.decode("utf-8"))
                response = handle_worker_request(request, firewall)
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = {"ok": False, "error": "Request is not valid JSON."}
        win32file.WriteFile(pipe, json.dumps(response).encode("utf-8"))
        win32file.FlushFileBuffers(pipe)


if __name__ == "__main__":
    if not run_service_mode_if_needed(sys.argv, servicemanager, MorpheusFirewallWorker):
        def save_owner_sid(*_):
            key_path = r"SYSTEM\CurrentControlSet\Services\MorpheusFirewallWorker\Parameters"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    winreg.QueryValueEx(key, "OwnerSid")
                    return
            except FileNotFoundError:
                pass
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                owner_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
                owner_sid_text = win32security.ConvertSidToStringSid(owner_sid)
            finally:
                win32api.CloseHandle(token)
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "OwnerSid", 0, winreg.REG_SZ, owner_sid_text)

        win32serviceutil.HandleCommandLine(
            MorpheusFirewallWorker,
            customOptionHandler=save_owner_sid,
        )
