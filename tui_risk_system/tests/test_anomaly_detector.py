# test_anomaly_detector.py
# tests for the Z-score anomaly detection module
# the detector is stateful so a fresh instance is created in each test

import sys
import os
import pytest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.anomaly_detector import AnomalyDetector


def _make_events(event_type, count, source_ip="10.0.0.1"):
    # just creates count events of a given type, timestamps don't matter much here
    ts = datetime.now().isoformat(timespec="seconds")
    return [
        {
            "timestamp": ts,
            "event_type": event_type,
            "source_ip": source_ip,
            "user_id": "jsmith",
            "asset": "Booking Platform",
        }
        for _ in range(count)
    ]


# ---- Warm-up period ----

class TestWarmUpPeriod:
    # the detector needs a few batches before it starts flagging anything
    # otherwise everything looks anomalous on the first run

    def test_no_detections_before_min_batches(self):
        detector = AnomalyDetector(window_size=50, z_threshold=2.5)
        # push 4 batches of unusual data - should be silent during warm-up
        for _ in range(4):
            result = detector.analyse(_make_events("failed_login", 50))
        assert result == []

    def test_detections_start_after_min_batches(self):
        detector = AnomalyDetector(window_size=50, z_threshold=2.5)

        # feed 5 baseline batches with some variance so std > 0
        # if all counts are identical then std=0 and Z will always be 0
        for count in [2, 1, 3, 2, 1]:
            detector.analyse(_make_events("failed_login", count))

        # now a massive spike - should be clearly anomalous against a baseline of ~1-3
        result = detector.analyse(_make_events("failed_login", 1000))
        assert len(result) > 0

    def test_batches_processed_counter_increments(self):
        detector = AnomalyDetector()
        assert detector._batches_processed == 0
        detector.analyse(_make_events("failed_login", 3))
        assert detector._batches_processed == 1
        detector.analyse(_make_events("failed_login", 3))
        assert detector._batches_processed == 2


# ---- Z-score calculation ----

class TestZScoreCalculation:

    def test_returns_zero_with_insufficient_data(self):
        detector = AnomalyDetector()
        # only 2 items in window - not enough to compute a meaningful Z
        from collections import deque
        window = deque([1, 2], maxlen=100)
        z = detector._compute_zscore(5, window)
        assert z == 0.0

    def test_returns_zero_when_std_is_zero(self):
        detector = AnomalyDetector()
        from collections import deque
        # all the same value means std = 0, can't divide by zero
        window = deque([5, 5, 5, 5, 5], maxlen=100)
        z = detector._compute_zscore(5, window)
        assert z == 0.0

    def test_positive_zscore_for_high_value(self):
        detector = AnomalyDetector()
        from collections import deque
        window = deque([1, 1, 1, 1, 2, 1, 1], maxlen=100)
        z = detector._compute_zscore(10, window)
        assert z > 0

    def test_negative_zscore_for_low_value(self):
        detector = AnomalyDetector()
        from collections import deque
        # window needs variance so std > 0 for Z to be non-zero
        window = deque([10, 9, 11, 10, 12, 8, 10], maxlen=100)
        z = detector._compute_zscore(1, window)
        assert z < 0


# ---- Severity banding ----

class TestSeverityBanding:
    # Z bands: |Z| >= 5 = Critical, >= 4 = High, >= 3 = Medium, else Low
    # testing via _make_anomaly_detection since it's easier than forcing exact Z values

    def setup_method(self):
        self.detector = AnomalyDetector()

    def test_critical_severity_at_z5(self):
        result = self.detector._make_anomaly_detection("failed_login", 100, 5.1, 10.0, [])
        assert result["severity"] == "Critical"

    def test_high_severity_at_z4(self):
        result = self.detector._make_anomaly_detection("failed_login", 100, 4.2, 10.0, [])
        assert result["severity"] == "High"

    def test_medium_severity_at_z3(self):
        result = self.detector._make_anomaly_detection("failed_login", 100, 3.1, 10.0, [])
        assert result["severity"] == "Medium"

    def test_low_severity_below_z3(self):
        result = self.detector._make_anomaly_detection("failed_login", 100, 2.6, 10.0, [])
        assert result["severity"] == "Low"

    def test_negative_z_uses_abs_for_severity(self):
        # -5.1 should still come out as Critical since we use the absolute value
        result = self.detector._make_anomaly_detection("failed_login", 0, -5.1, 10.0, [])
        assert result["severity"] == "Critical"


# ---- Detection content ----

class TestDetectionContent:

    def test_detection_has_required_keys(self):
        detector = AnomalyDetector()
        det = detector._make_anomaly_detection("failed_login", 50, 3.5, 5.0, [])
        required = {"timestamp", "alert_type", "severity", "source_ip", "user_id",
                    "asset", "description", "event_ids", "triggered_rule", "z_score"}
        assert required.issubset(det.keys())

    def test_alert_type_formatted_correctly(self):
        detector = AnomalyDetector()
        det = detector._make_anomaly_detection("sql_injection_attempt", 10, 3.0, 2.0, [])
        assert det["alert_type"] == "Anomaly: Sql Injection Attempt"

    def test_description_contains_count_and_zscore(self):
        detector = AnomalyDetector()
        det = detector._make_anomaly_detection("failed_login", 42, 3.7, 5.0, [])
        assert "42" in det["description"]
        assert "3.70" in det["description"]

    def test_top_ip_extracted_from_events(self):
        detector = AnomalyDetector()
        events = _make_events("failed_login", 5, source_ip="1.2.3.4")
        det = detector._make_anomaly_detection("failed_login", 5, 3.5, 1.0, events)
        assert det["source_ip"] == "1.2.3.4"


# ---- Baseline update and reset ----

class TestBaselineAndReset:

    def test_baseline_updates_after_each_batch(self):
        detector = AnomalyDetector()
        detector.analyse(_make_events("dns_lookup", 5))
        summary = detector.get_baseline_summary()
        assert "dns_lookup" in summary

    def test_reset_clears_baseline(self):
        detector = AnomalyDetector()
        detector.analyse(_make_events("dns_lookup", 5))
        detector.reset()
        summary = detector.get_baseline_summary()
        assert summary == {}

    def test_reset_clears_batch_counter(self):
        detector = AnomalyDetector()
        for _ in range(5):
            detector.analyse(_make_events("dns_lookup", 3))
        detector.reset()
        assert detector._batches_processed == 0

    def test_empty_batch_returns_empty_list(self):
        detector = AnomalyDetector()
        result = detector.analyse([])
        assert result == []

    def test_baseline_summary_has_stats(self):
        detector = AnomalyDetector()
        for _ in range(5):
            detector.analyse(_make_events("failed_login", 5))
        summary = detector.get_baseline_summary()
        assert "mean" in summary["failed_login"]
        assert "std" in summary["failed_login"]
        assert "samples" in summary["failed_login"]
