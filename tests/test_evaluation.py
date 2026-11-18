import csv

import pytest

from morpheus.evaluation import evaluate_process_tree_dataset


def _write_dataset(path, rows):
    fields = ("group_id", "process_name", "parent_process_name", "label")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_process_tree_evaluation_holds_out_whole_groups_and_reports_metrics(tmp_path):
    dataset = tmp_path / "events.csv"
    _write_dataset(dataset, [
        {"group_id": "b1", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "benign"},
        {"group_id": "b2", "process_name": "powershell.exe", "parent_process_name": "winword.exe", "label": "benign"},
        {"group_id": "s1", "process_name": "cmd.exe", "parent_process_name": "excel.exe", "label": "suspicious"},
        {"group_id": "s2", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "suspicious"},
        {"group_id": "s2", "process_name": "powershell.exe", "parent_process_name": "services.exe", "label": "suspicious"},
    ])

    report = evaluate_process_tree_dataset(dataset, test_fraction=0.5, seed=7)

    assert report["scope"] == "process_tree_review_rule_only"
    assert report["groups"]["train_by_label"] == {"benign": 1, "suspicious": 1}
    assert report["groups"]["test_by_label"] == {"benign": 1, "suspicious": 1}
    assert report["groups"]["test_group_ids"] == sorted(
        report["groups"]["test_group_ids"]
    )
    assert not (
        set(report["groups"]["train_group_ids"])
        & set(report["groups"]["test_group_ids"])
    )
    assert report["test_records"] >= 2
    assert sum(report["confusion_matrix"].values()) == 2
    assert report["metrics"]["accuracy"] in {0.0, 0.5, 1.0}


def test_process_tree_evaluation_rejects_conflicting_labels_within_group(tmp_path):
    dataset = tmp_path / "events.csv"
    _write_dataset(dataset, [
        {"group_id": "same", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "benign"},
        {"group_id": "same", "process_name": "cmd.exe", "parent_process_name": "excel.exe", "label": "suspicious"},
        {"group_id": "b2", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "benign"},
        {"group_id": "s2", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "suspicious"},
    ])

    with pytest.raises(ValueError, match="conflicting labels"):
        evaluate_process_tree_dataset(dataset)


def test_process_tree_evaluation_requires_independent_groups_per_class(tmp_path):
    dataset = tmp_path / "events.csv"
    _write_dataset(dataset, [
        {"group_id": "b1", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "benign"},
        {"group_id": "b2", "process_name": "notepad.exe", "parent_process_name": "explorer.exe", "label": "benign"},
        {"group_id": "s1", "process_name": "cmd.exe", "parent_process_name": "excel.exe", "label": "suspicious"},
    ])

    with pytest.raises(ValueError, match="at least two independent groups"):
        evaluate_process_tree_dataset(dataset)
