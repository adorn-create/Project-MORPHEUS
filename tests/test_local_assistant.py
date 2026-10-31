import json
from urllib.error import URLError

import pytest

from morpheus.local_assistant import LocalAssistant, LocalAssistantError


class FakeResponse:
    def __init__(self, value):
        self.content = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.content


def test_local_chat_uses_loopback_and_never_uses_tools(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        if request.full_url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": "local-model:latest"}]})
        return FakeResponse({"message": {"content": "Review the alert cautiously."}})

    monkeypatch.setattr("morpheus.local_assistant.urlopen", fake_urlopen)
    assistant = LocalAssistant()

    result = assistant.chat(
        "local-model:latest",
        "What does this review alert mean?",
        [{"role": "user", "content": "Help me understand the dashboard"}],
    )

    assert result == "Review the alert cautiously."
    assert len(requests) == 2
    assert all(request.full_url.startswith("http://127.0.0.1:11434/") for request, _ in requests)
    chat_body = json.loads(requests[1][0].data)
    assert chat_body["stream"] is False
    assert "tools" not in chat_body
    assert chat_body["messages"][0]["role"] == "system"
    assert chat_body["messages"][-1] == {
        "role": "user",
        "content": "What does this review alert mean?",
    }


def test_status_explains_when_ollama_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "morpheus.local_assistant.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("connection refused")),
    )

    result = LocalAssistant().status()

    assert result["available"] is False
    assert result["models"] == []
    assert "127.0.0.1:11434" in result["message"]


def test_chat_rejects_model_not_installed_locally(monkeypatch):
    monkeypatch.setattr(
        "morpheus.local_assistant.urlopen",
        lambda *_args, **_kwargs: FakeResponse({"models": [{"name": "known-model"}]}),
    )

    with pytest.raises(LocalAssistantError, match="installed in the local Ollama service") as exc:
        LocalAssistant().chat("unlisted-model", "Question", [])

    assert exc.value.status_code == 400
