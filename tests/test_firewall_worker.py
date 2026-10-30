from morpheus.firewall_worker import (
    handle_worker_request,
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

    def remove_rule_by_name(self, name):
        self.removed.append(name)
        return True


def test_worker_only_accepts_public_ipv4_and_morpheus_rule_names():
    firewall = FirewallStub()

    added = handle_worker_request({"operation": "add", "remote_ip": "1.1.1.1"}, firewall)
    blocked_private = handle_worker_request({"operation": "add", "remote_ip": "127.0.0.1"}, firewall)
    removed = handle_worker_request(
        {"operation": "remove", "name": "Morpheus-Block-012345abcdef"}, firewall
    )
    rejected_remove = handle_worker_request(
        {"operation": "remove", "name": "Windows-Firewall-Rule"}, firewall
    )
    rejected_command = handle_worker_request({"operation": "execute", "command": "whoami"}, firewall)

    assert added == {"ok": True}
    assert blocked_private["ok"] is False
    assert removed == {"ok": True}
    assert rejected_remove["ok"] is False
    assert rejected_command["ok"] is False
    assert firewall.added == ["1.1.1.1"]
    assert firewall.removed == ["Morpheus-Block-012345abcdef"]


def test_public_ipv4_validation_rejects_reserved_and_ipv6():
    assert parse_public_ipv4("8.8.8.8") is not None
    assert parse_public_ipv4("192.168.1.1") is None
    assert parse_public_ipv4("203.0.113.1") is None
    assert parse_public_ipv4("2001:4860:4860::8888") is None


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
