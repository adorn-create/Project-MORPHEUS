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


def test_offline_assistant_explains_read_only_defender_health_check():
    answer = OfflineAssistant().chat("Does Morpheus change my Defender settings?")

    assert "read Microsoft Defender's protection status" in answer
    assert "does not change Defender settings" in answer


def test_offline_assistant_explains_optional_clamav_engine_and_database():
    answer = OfflineAssistant().chat("Can ClamAV update its signature database?")

    assert "FreshClam" in answer
    assert "does not bundle ClamAV" in answer
    assert "does not automatically quarantine" in answer

def test_offline_assistant_explains_common_malware_entry_paths():
    answer = OfflineAssistant().chat(
        "can you explain how a malware can get in to my pc"
    )

    assert "phishing links or attachments" in answer
    assert "unsafe downloads" in answer
    assert "Keep Microsoft Defender" in answer
