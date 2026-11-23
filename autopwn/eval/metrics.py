"""Detection metrics against ground truth: TP/FP/FN, precision, recall, F1."""
from __future__ import annotations

from dataclasses import dataclass


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


@dataclass(frozen=True)
class Metrics:
    tp: frozenset[str]
    fp: frozenset[str]
    fn: frozenset[str]

    @property
    def precision(self) -> float:
        return _safe_div(len(self.tp), len(self.tp) + len(self.fp))

    @property
    def recall(self) -> float:
        """Also called the detection rate."""
        return _safe_div(len(self.tp), len(self.tp) + len(self.fn))

    # explicit alias — the project speaks of "detection rate"
    detection_rate = recall

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return _safe_div(2 * p * r, p + r)

    def to_dict(self) -> dict:
        return {
            "tp": sorted(self.tp), "fp": sorted(self.fp), "fn": sorted(self.fn),
            "true_positives": len(self.tp),
            "false_positives": len(self.fp),
            "false_negatives": len(self.fn),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "detection_rate": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def evaluate(detected: set[str] | frozenset[str],
             ground_truth: set[str] | frozenset[str]) -> Metrics:
    """Compare a detected class set against ground truth."""
    detected, ground_truth = set(detected), set(ground_truth)
    return Metrics(
        tp=frozenset(detected & ground_truth),
        fp=frozenset(detected - ground_truth),
        fn=frozenset(ground_truth - detected),
    )


def aggregate(metrics_list: list[Metrics]) -> dict:
    """Macro- and micro-averaged summary over several targets."""
    if not metrics_list:
        return {"targets": 0, "macro_precision": 0.0, "macro_recall": 0.0,
                "macro_f1": 0.0, "micro_precision": 0.0, "micro_recall": 0.0,
                "total_false_positives": 0, "total_false_negatives": 0}
    n = len(metrics_list)
    macro_p = sum(m.precision for m in metrics_list) / n
    macro_r = sum(m.recall for m in metrics_list) / n
    macro_f = sum(m.f1 for m in metrics_list) / n
    tp = sum(len(m.tp) for m in metrics_list)
    fp = sum(len(m.fp) for m in metrics_list)
    fn = sum(len(m.fn) for m in metrics_list)
    return {
        "targets": n,
        "macro_precision": round(macro_p, 4),
        "macro_recall": round(macro_r, 4),
        "macro_detection_rate": round(macro_r, 4),
        "macro_f1": round(macro_f, 4),
        "micro_precision": round(_safe_div(tp, tp + fp), 4),
        "micro_recall": round(_safe_div(tp, tp + fn), 4),
        "total_true_positives": tp,
        "total_false_positives": fp,
        "total_false_negatives": fn,
    }
