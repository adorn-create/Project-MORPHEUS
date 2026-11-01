from morpheus.detector import OwnBehaviorModel, executable_signals
from morpheus.threat_matrix import THREAT_MATRIX


def test_behavior_model_is_fast_deterministic_and_explainable():
    model = OwnBehaviorModel()

    assert model.score({}) == (0.0, [])
    score, reasons = model.score({
        "temporary_program_location": True,
        "high_cpu": True,
        "unrecognized_signal": True,
    })
    assert round(score, 2) == 0.5
    assert reasons == ["temporary_program_location", "high_cpu"]
    score, reasons = model.score(dict.fromkeys(THREAT_MATRIX.process_weights, True))
    assert round(score, 2) == 0.95
    assert reasons == list(THREAT_MATRIX.process_weights)


def test_process_lineage_adds_configured_correlation_weight():
    model = OwnBehaviorModel()

    score, reasons = model.score({
        "temporary_program_location": True,
        "suspicious_process_lineage": True,
    })

    assert round(score, 2) == 0.49
    assert reasons == ["temporary_program_location", "suspicious_process_lineage"]


def test_temporary_program_signal_uses_path_boundaries(tmp_path, monkeypatch):
    temp_root = tmp_path / "Temp"
    temp_root.mkdir()
    monkeypatch.setenv("TEMP", str(temp_root))
    monkeypatch.setenv("TMP", str(temp_root))

    class Process:
        def __init__(self, path):
            self.path = path

        def exe(self):
            return str(self.path)

        def cpu_percent(self, interval=None):
            return 0

    inside, _ = executable_signals(Process(temp_root / "app.exe"))
    sibling, _ = executable_signals(Process(tmp_path / "TempOther" / "app.exe"))

    assert inside["temporary_program_location"] is True
    assert sibling["temporary_program_location"] is False
