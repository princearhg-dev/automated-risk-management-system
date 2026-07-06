# anomaly_detector.py - statistical anomaly detection using Z-scores
#
# this is the second half of the hybrid detection approach
# the rule engine catches known patterns, but this module catches unusual
# behaviour that doesn't match any specific rule
#
# how it works: keeps a rolling window of recent event counts per event type
# and uses Z-scores to measure how far the current count deviates from the baseline
# if the Z-score exceeds the threshold, it gets flagged as an anomaly
#
# Z-score chosen over a machine learning model because it's simpler to explain,
# doesn't need training data, and is statistically sound for this scale of prototype

import numpy as np
from collections import defaultdict, deque
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Z_SCORE_THRESHOLD, BASELINE_WINDOW_SIZE


class AnomalyDetector:
    # maintains a rolling baseline of event counts and checks new batches against it

    def __init__(self, window_size=BASELINE_WINDOW_SIZE, z_threshold=Z_SCORE_THRESHOLD):
        self.window_size = window_size
        self.z_threshold = z_threshold

        # one rolling window per event type - deque automatically drops old entries
        self._windows = defaultdict(lambda: deque(maxlen=window_size))

        # minimum batches required before flagging anything
        # otherwise the baseline is too thin and everything looks anomalous
        self._batches_processed = 0
        self._min_batches_for_detection = 5

    def _update_baseline(self, event_type_counts):
        # adds the current batch's counts to the rolling windows
        # done after the anomaly check so the current batch doesn't
        # inflate its own Z-score
        for event_type, count in event_type_counts.items():
            self._windows[event_type].append(count)

    def _compute_zscore(self, value, window):
        # standard Z-score formula: (value - mean) / std
        # returns 0 if there isn't enough data or if std is zero
        if len(window) < 3:
            return 0.0

        arr = np.array(list(window))
        mean = np.mean(arr)
        std = np.std(arr)

        if std == 0:
            # can't divide by zero - if everything in the window is identical
            # then there's no variance to detect against
            return 0.0

        return float((value - mean) / std)

    def analyse(self, events):
        # main entry point - takes a list of processed events and returns any anomalies found
        if not events:
            return []

        # count how many events of each type are in this batch
        current_counts = defaultdict(int)
        for e in events:
            current_counts[e.get("event_type", "unknown")] += 1

        anomalies = []

        if self._batches_processed >= self._min_batches_for_detection:
            for event_type, count in current_counts.items():
                window = self._windows[event_type]
                z = self._compute_zscore(count, window)

                if abs(z) >= self.z_threshold:
                    mean_val = np.mean(list(window)) if len(window) > 0 else 0
                    anomalies.append(self._make_anomaly_detection(
                        event_type, count, z, mean_val, events
                    ))

        # update baseline after checking
        self._update_baseline(current_counts)
        self._batches_processed += 1

        return anomalies

    def _make_anomaly_detection(self, event_type, count, z_score, baseline_mean, events):
        # builds the detection dict - severity is based on how extreme the Z-score is
        abs_z = abs(z_score)
        if abs_z >= 5.0:
            severity = "Critical"
        elif abs_z >= 4.0:
            severity = "High"
        elif abs_z >= 3.0:
            severity = "Medium"
        else:
            severity = "Low"

        # try to pull out the most common IP and asset from the flagged events
        related = [e for e in events if e.get("event_type") == event_type]
        top_ip = None
        top_asset = None
        if related:
            ip_counts = defaultdict(int)
            for e in related:
                if e.get("source_ip"):
                    ip_counts[e["source_ip"]] += 1
            if ip_counts:
                top_ip = max(ip_counts, key=ip_counts.get)
            top_asset = related[0].get("asset")

        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "alert_type": f"Anomaly: {event_type.replace('_', ' ').title()}",
            "severity": severity,
            "source_ip": top_ip,
            "user_id": None,
            "asset": top_asset,
            "description": (
                f"Statistical anomaly detected for event type '{event_type}'. "
                f"Current count: {count}, baseline mean: {baseline_mean:.1f}, "
                f"Z-score: {z_score:.2f} (threshold: {self.z_threshold})."
            ),
            "event_ids": "",
            "triggered_rule": "anomaly_zscore",
            "z_score": z_score,
        }

    def get_baseline_summary(self):
        # returns the current baseline stats for each event type
        # exposed through the API so it can be shown on the dashboard
        summary = {}
        for event_type, window in self._windows.items():
            if len(window) > 0:
                arr = np.array(list(window))
                summary[event_type] = {
                    "mean": float(np.mean(arr)),
                    "std": float(np.std(arr)),
                    "min": float(np.min(arr)),
                    "max": float(np.max(arr)),
                    "samples": len(window),
                }
        return summary

    def reset(self):
        # clears all baseline data - mainly used in tests
        self._windows = defaultdict(lambda: deque(maxlen=self.window_size))
        self._batches_processed = 0


# single shared instance used by the monitor loop
# module-level singleton so the baseline persists across cycles
_detector = AnomalyDetector()


def get_detector():
    return _detector


def analyse_events(events):
    return _detector.analyse(events)


def get_baseline():
    return _detector.get_baseline_summary()
