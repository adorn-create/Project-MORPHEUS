import ipaddress
import re


WORKER_PIPE = r"\\.\pipe\MorpheusFirewallWorker"
RULE_NAME_PATTERN = re.compile(r"^Morpheus-Block-[0-9a-f]{12}$")


def parse_public_ipv4(value: str):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_unspecified or address.is_multicast or address.is_reserved
    ):
        return None
    return address


def handle_worker_request(request: dict, firewall) -> dict:
    if not isinstance(request, dict):
        return {"ok": False, "error": "Request must be a JSON object."}

    operation = request.get("operation")
    if operation == "add":
        address = parse_public_ipv4(request.get("remote_ip", ""))
        if address is None:
            return {"ok": False, "error": "Only public IPv4 addresses can be blocked."}
        try:
            return {"ok": bool(firewall.block_remote(str(address)))}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    if operation == "remove":
        name = request.get("name", "")
        if not isinstance(name, str) or not RULE_NAME_PATTERN.fullmatch(name):
            return {"ok": False, "error": "Only Morpheus-owned firewall rules can be removed."}
        try:
            return {"ok": bool(firewall.remove_rule_by_name(name))}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    return {"ok": False, "error": "Unsupported firewall worker operation."}


def run_service_mode_if_needed(argv: list[str], service_manager, service_class) -> bool:
    if len(argv) != 1:
        return False
    service_manager.Initialize()
    service_manager.PrepareToHostSingle(service_class)
    service_manager.StartServiceCtrlDispatcher()
    return True
