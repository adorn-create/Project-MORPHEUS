from morpheus.detector import OwnBehaviorModel


def test_behavior_model_is_fast_deterministic_and_explainable():
    model = OwnBehaviorModel()

    assert model.score({}) == (0.0, [])
    assert model.score({
        "unsigned_temp_executable": True,
        "high_cpu": True,
        "unrecognized_signal": True,
    }) == (0.5, ["unsigned_temp_executable", "high_cpu"])
    score, reasons = model.score({
        name: True
        for name, _weight in model.weights
    })
    assert round(score, 2) == 0.95
    assert reasons == [name for name, _weight in model.weights]
