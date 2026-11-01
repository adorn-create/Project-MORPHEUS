from types import SimpleNamespace

from morpheus.firewall import FirewallController
from morpheus.firewall_worker import (
    handle_worker_request,
    parse_public_ip,
    parse_public_ipv4,
    run_service_mode_if_needed,
)


class FirewallStub:
    def __init__(self):
        self.added = []
        self.removed = []

    def block_remote(self, remote_ip):
        self.added.append(remote_ip)
        return True

    def block_inbound_remote(self, remote_ip):
        self.added.append(f"inbound:{remote_ip}")
        return True

    def remove_rule_by_name(self, name):
        self.removed.append(name)
        return True


def test_worker_only_accepts_public_ipv4_and_morpheus_rule_names():
    firewall = FirewallStub()

    added = handle_worker_request({"operation": "add", "remote_ip": "1.1.1.1"}, firewall)
    added_ipv6 = handle_worker_request(
        {"operation": "add", "remote_ip": "2001:4860:4860::8888"}, firewall
    )
    inbound_added = handle_worker_request(
        {"operation": "add_inbound", "remote_ip": "1.1.1.1"}, firewall
    )
    blocked_private = handle_worker_request({"operation": "add", "remote_ip": "127.0.0.1"}, firewall)
    removed = handle_worker_request(
        {"operation": "remove", "name": "Morpheus-Block-012345abcdef"}, firewall
    )
    rejected_remove = handle_worker_request(
        {"operation": "remove", "name": "Windows-Firewall-Rule"}, firewall
    )
    rejected_command = handle_worker_request({"operation": "execute", "command": "whoami"}, firewall)
    rejected_inbound_private = handle_worker_request(
        {"operation": "add_inbound", "remote_ip": "192.168.1.10"}, firewall
    )

    assert added == {"ok": True}
    assert added_ipv6 == {"ok": True}
    assert inbound_added == {"ok": True}
    assert blocked_private["ok"] is False
    assert removed == {"ok": True}
    assert rejected_remove["ok"] is False
    assert rejected_command["ok"] is False
    assert rejected_inbound_private["ok"] is False
    assert firewall.added == ["1.1.1.1", "2001:4860:4860::8888", "inbound:1.1.1.1"]
    assert firewall.removed == ["Morpheus-Block-012345abcdef"]


def test_public_ipv4_validation_rejects_reserved_and_ipv6():
    assert parse_public_ipv4("8.8.8.8") is not None
    assert parse_public_ipv4("192.168.1.1") is None
    assert parse_public_ipv4("203.0.113.1") is None
    assert parse_public_ipv4("2001:4860:4860::8888") is None


def test_public_ip_validation_accepts_public_ipv6_and_rejects_non_global_addresses():
    assert parse_public_ip("2001:4860:4860::8888") is not None
    assert parse_public_ip("fd00::1") is None
    assert parse_public_ip("fe80::1") is None
    assert parse_public_ip("::1") is None
    assert parse_public_ip("::ffff:8.8.8.8") is None


def test_firewall_controller_creates_explicit_dual_stack_outbound_rules(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("morpheus.firewall.subprocess.run", run)
    controller = FirewallController(use_worker=False)

    assert controller.block_remote("2001:4860:4860::8888") is True
    assert any("dir=out" == argument for argument in commands[0])
    assert "action=block" in commands[0]
    assert "enable=yes" in commands[0]
    assert "profile=any" in commands[0]
    assert "protocol=any" in commands[0]
    assert "remoteip=2001:4860:4860::8888/128" in commands[0]


def test_firewall_controller_creates_inbound_block_for_public_source(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("morpheus.firewall.subprocess.run", run)
    controller = FirewallController(use_worker=False)

    assert controller.block_inbound_remote("1.2.3.4") is True
    assert any("dir=in" == argument for argument in commands[0])
    assert "action=block" in commands[0]
    assert "protocol=any" in commands[0]
    assert "remoteip=1.2.3.4/32" in commands[0]
    assert any(argument.startswith("name=Morpheus-Scan-Block-") for argument in commands[0])


def test_worker_uses_service_dispatcher_when_started_by_windows():
    calls = []

    class ServiceManagerStub:
        def Initialize(self):
            calls.append("initialize")

        def PrepareToHostSingle(self, service_class):
            calls.append(("prepare", service_class))

        def StartServiceCtrlDispatcher(self):
            calls.append("dispatch")

    service_class = object()

    handled = run_service_mode_if_needed(
        ["morpheus-firewall-worker.exe"],
        ServiceManagerStub(),
        service_class,
    )

    assert handled is True
    assert calls == ["initialize", ("prepare", service_class), "dispatch"]


def test_worker_cli_commands_keep_command_line_handler():
    class ServiceManagerStub:
        def Initialize(self):
            raise AssertionError("CLI invocations must not start service dispatch")

    assert run_service_mode_if_needed(
        ["morpheus-firewall-worker.exe", "debug"],
        ServiceManagerStub(),
        object(),
    ) is False
