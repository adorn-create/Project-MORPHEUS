from morpheus.local_assistant import OfflineAssistant


def test_offline_assistant_is_ready_without_external_model():
    status = OfflineAssistant().status()

    assert status["available"] is True
    assert status["ready"] is True
    assert status["mode"] == "built-in offline helper"
    assert "No Ollama" in status["message"]


def test_offline_assistant_explains_file_checks_and_antivirus_limits():
    answer = OfflineAssistant().chat(
        "Does this scan prove that my file has no virus?",
    )

    assert "not a full antivirus scan" in answer
    assert "Microsoft Defender" in answer


def test_offline_assistant_explains_common_topics_and_unknown_questions():
    assistant = OfflineAssistant()

    assert "does not control another computer" in assistant.chat(
        "What does the firewall do?"
    )
    assert "not a general-purpose AI" in assistant.chat(
        "Can you write a poem about space?"
    )


def test_offline_assistant_explains_inbound_scan_protection():
    answer = OfflineAssistant().chat("How does inbound scan blocking work?")

    assert "dropped-packet logging" in answer
    assert "10 or more distinct local ports" in answer
    assert "Allow this IP" in answer
