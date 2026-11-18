from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

from .collector import is_suspicious_process_tree_edge


REQUIRED_COLUMNS = {
    "group_id",
    "process_name",
    "parent_process_name",
    "label",
}
LABELS = {"benign", "suspicious"}


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate_process_tree_dataset(
    dataset_path: Path,
    *,
    test_fraction: float = 0.2,
    seed: int = 42,
) -> dict[str, Any]:
    if not math.isfinite(test_fraction) or not 0 < test_fraction < 1:
        raise ValueError("test_fraction must be between 0 and 1.")

    grouped_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    group_labels: dict[str, str] = {}
    with dataset_path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if (
            reader.fieldnames is None
            or not REQUIRED_COLUMNS.issubset(reader.fieldnames)
        ):
            missing = sorted(REQUIRED_COLUMNS - set(reader.fieldnames or ()))
            raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")
        for line_number, row in enumerate(reader, start=2):
            group_id = (row.get("group_id") or "").strip()
            label = (row.get("label") or "").strip().casefold()
            if not group_id:
                raise ValueError(f"Dataset row {line_number} has no group_id.")
            if label not in LABELS:
                raise ValueError(
                    f"Dataset row {line_number} has unsupported label {label!r}; "
                    "only reviewed benign/suspicious labels are accepted."
                )
            previous_label = group_labels.setdefault(group_id, label)
            if previous_label != label:
                raise ValueError(
                    f"Dataset group {group_id!r} contains conflicting labels."
                )
            grouped_rows[group_id].append(row)

    if not grouped_rows:
        raise ValueError("Dataset contains no labeled rows.")

    groups_by_label: dict[str, list[str]] = defaultdict(list)
    for group_id, label in group_labels.items():
        groups_by_label[label].append(group_id)
    insufficient = [
        f"{label}={len(groups_by_label[label])}"
        for label in sorted(LABELS)
        if len(groups_by_label[label]) < 2
    ]
    if insufficient:
        raise ValueError(
            "A group holdout needs at least two independent groups per class; "
            + ", ".join(insufficient)
        )

    rng = random.Random(seed)
    test_groups: set[str] = set()
    for label in sorted(LABELS):
        groups = sorted(groups_by_label[label])
        rng.shuffle(groups)
        test_count = min(
            len(groups) - 1,
            max(1, math.ceil(len(groups) * test_fraction)),
        )
        test_groups.update(groups[:test_count])

    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
    }
    test_records = 0
    for group_id in test_groups:
        test_records += len(grouped_rows[group_id])
        predicted_suspicious = any(
            is_suspicious_process_tree_edge(
                row.get("parent_process_name"),
                row.get("process_name"),
            )
            for row in grouped_rows[group_id]
        )
        actual_suspicious = group_labels[group_id] == "suspicious"
        if actual_suspicious and predicted_suspicious:
            counts["true_positive"] += 1
        elif actual_suspicious:
            counts["false_negative"] += 1
        elif predicted_suspicious:
            counts["false_positive"] += 1
        else:
            counts["true_negative"] += 1

    tp, fp, tn, fn = (
        counts["true_positive"],
        counts["false_positive"],
        counts["true_negative"],
        counts["false_negative"],
    )
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    train_groups = set(group_labels) - test_groups
    return {
        "schema_version": 1,
        "scope": "process_tree_review_rule_only",
        "seed": seed,
        "test_fraction": test_fraction,
        "labeling_caveat": (
            "Metrics inherit dataset labels. If labels are based on capture "
            "provenance, they are weak labels, not independently verified "
            "ground truth."
        ),
        "aggregation": (
            "One prediction per capture group: suspicious if any row in that "
            "group matches the existing document-app-to-script-host review rule."
        ),
        "groups": {
            "total": len(group_labels),
            "train": len(train_groups),
            "test": len(test_groups),
            "train_by_label": {
                label: sum(group_labels[group] == label for group in train_groups)
                for label in sorted(LABELS)
            },
            "test_by_label": {
                label: sum(group_labels[group] == label for group in test_groups)
                for label in sorted(LABELS)
            },
            "train_group_ids": sorted(train_groups),
            "test_group_ids": sorted(test_groups),
        },
        "test_records": test_records,
        "confusion_matrix": counts,
        "metrics": {
            "precision": precision,
            "recall": recall,
            "specificity": specificity,
            "false_positive_rate": (
                1 - specificity if specificity is not None else None
            ),
            "f1": f1,
            "accuracy": _ratio(tp + tn, tp + fp + tn + fn),
        },
        "interpretation": (
            "This is an exploratory evaluation of one review-only process-tree "
            "rule, not a measure of overall Morpheus detection accuracy or "
            "blocking effectiveness."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Morpheus's process-tree review rule on grouped labeled telemetry."
    )
    parser.add_argument("dataset", type=Path, help="Normalized CSV dataset")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-fraction", type=float, default=0.2)
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    report = evaluate_process_tree_dataset(
        args.dataset,
        test_fraction=args.test_fraction,
        seed=args.seed,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
