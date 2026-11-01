import hashlib
import ipaddress
import re


WORKER_PIPE = r"\\.\pipe\MorpheusFirewallWorker"
RULE_NAME_PATTERN = re.compile(r"^Morpheus-(?:Block|Scan-Block)-[0-9a-f]{12}$")


def parse_public_ip(value: str):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global or (
        isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
    ):
        return None
    return address


def parse_public_ipv4(value: str):
    address = parse_public_ip(value)
    if address is None or address.version != 4:
        return None
    return address


def scan_block_rule_name(remote_ip: str) -> str:
    address = parse_public_ip(remote_ip)
    if address is None:
        raise ValueError("Only globally routable IPv4 or IPv6 addresses can be blocked.")
    suffix = hashlib.sha256(str(address).encode("ascii")).hexdigest()[:12]
    return f"Morpheus-Scan-Block-{suffix}"


def handle_worker_request(request: dict, firewall) -> dict:
    if not isinstance(request, dict):
        return {"ok": False, "error": "Request must be a JSON object."}

    operation = request.get("operation")
    if operation == "add":
        address = parse_public_ip(request.get("remote_ip", ""))
        if address is None:
            return {"ok": False, "error": "Only globally routable IPv4 or IPv6 addresses can be blocked."}
        try:
            return {"ok": bool(firewall.block_remote(str(address)))}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    if operation == "add_inbound":
        address = parse_public_ip(request.get("remote_ip", ""))
        if address is None:
            return {"ok": False, "error": "Only globally routable IPv4 or IPv6 addresses can be blocked."}
        try:
            return {"ok": bool(firewall.block_inbound_remote(str(address)))}
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
