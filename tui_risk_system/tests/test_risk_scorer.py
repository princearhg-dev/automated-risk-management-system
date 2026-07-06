# test_risk_scorer.py
# tests for the NIST SP 800-30 risk scoring module
# checking that each threat type maps to the right likelihood/impact values
# and that the final score and level come out correctly

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.risk_scorer import (
    score_alert,
    score_all_alerts,
    get_overall_risk_level,
    risk_level_to_colour,
    get_risk_summary_stats,
    _get_risk_level,
)


def _make_alert(alert_type, severity="High", asset="Booking Platform"):
    return {"alert_type": alert_type, "severity": severity, "asset": asset}


# ---- _get_risk_level ----

class TestGetRiskLevel:
    # just checking the threshold boundaries are correct
    # Low: 1-5, Medium: 6-10, High: 11-15, Very High: 16-20, Critical: 21-25

    def test_score_1_is_low(self):
        assert _get_risk_level(1) == "Low"

    def test_score_5_is_low(self):
        assert _get_risk_level(5) == "Low"

    def test_score_6_is_medium(self):
        assert _get_risk_level(6) == "Medium"

    def test_score_10_is_medium(self):
        assert _get_risk_level(10) == "Medium"

    def test_score_11_is_high(self):
        assert _get_risk_level(11) == "High"

    def test_score_15_is_high(self):
        assert _get_risk_level(15) == "High"

    def test_score_16_is_very_high(self):
        assert _get_risk_level(16) == "Very High"

    def test_score_20_is_very_high(self):
        assert _get_risk_level(20) == "Very High"

    def test_score_21_is_critical(self):
        assert _get_risk_level(21) == "Critical"

    def test_score_25_is_critical(self):
        assert _get_risk_level(25) == "Critical"


# ---- score_alert: known threat types ----

class TestScoreAlertKnownThreats:
    # checking the exact NIST values for each threat type against what's defined
    # in the THREAT_RISK_MAP in risk_scorer.py

    def test_brute_force_score(self):
        # High (4) x High (4) = 16 -> Very High
        result = score_alert(_make_alert("Brute Force Attack"))
        assert result["likelihood_val"] == 4
        assert result["impact_val"] == 4
        assert result["risk_score"] == 16
        assert result["risk_level"] == "Very High"

    def test_port_scan_score(self):
        # High (4) x Moderate (3) = 12 -> High
        result = score_alert(_make_alert("Port Scan"))
        assert result["likelihood_val"] == 4
        assert result["impact_val"] == 3
        assert result["risk_score"] == 12
        assert result["risk_level"] == "High"

    def test_sql_injection_score(self):
        # Moderate (3) x Very High (5) = 15 -> High
        result = score_alert(_make_alert("SQL Injection Attempt"))
        assert result["likelihood_val"] == 3
        assert result["impact_val"] == 5
        assert result["risk_score"] == 15
        assert result["risk_level"] == "High"

    def test_privilege_escalation_score(self):
        # Moderate (3) x Very High (5) = 15 -> High
        result = score_alert(_make_alert("Privilege Escalation Attempt"))
        assert result["risk_score"] == 15
        assert result["risk_level"] == "High"

    def test_off_hours_access_score(self):
        # High (4) x Low (2) = 8 -> Medium
        result = score_alert(_make_alert("Off-Hours Access"))
        assert result["likelihood_val"] == 4
        assert result["impact_val"] == 2
        assert result["risk_score"] == 8
        assert result["risk_level"] == "Medium"

    def test_suspicious_data_transfer_score(self):
        # Low (2) x Very High (5) = 10 -> Medium
        result = score_alert(_make_alert("Suspicious Data Transfer"))
        assert result["likelihood_val"] == 2
        assert result["impact_val"] == 5
        assert result["risk_score"] == 10
        assert result["risk_level"] == "Medium"

    def test_security_config_change_score(self):
        # Moderate (3) x High (4) = 12 -> High
        result = score_alert(_make_alert("Security Configuration Change"))
        assert result["risk_score"] == 12
        assert result["risk_level"] == "High"


# ---- score_alert: anomaly detections ----

class TestScoreAlertAnomalies:
    # anomaly alerts use the severity field to derive likelihood/impact
    # since they don't have a fixed threat type like the rule-based ones

    def test_critical_anomaly_score(self):
        # Very High (5) x Very High (5) = 25 -> Critical
        result = score_alert({"alert_type": "Anomaly: Failed Login", "severity": "Critical"})
        assert result["likelihood_val"] == 5
        assert result["impact_val"] == 5
        assert result["risk_score"] == 25
        assert result["risk_level"] == "Critical"

    def test_high_anomaly_score(self):
        # High (4) x High (4) = 16 -> Very High
        result = score_alert({"alert_type": "Anomaly: Failed Login", "severity": "High"})
        assert result["risk_score"] == 16
        assert result["risk_level"] == "Very High"

    def test_medium_anomaly_score(self):
        # Moderate (3) x Moderate (3) = 9 -> Medium
        result = score_alert({"alert_type": "Anomaly: Failed Login", "severity": "Medium"})
        assert result["risk_score"] == 9
        assert result["risk_level"] == "Medium"

    def test_low_anomaly_score(self):
        # Low (2) x Low (2) = 4 -> Low
        result = score_alert({"alert_type": "Anomaly: Failed Login", "severity": "Low"})
        assert result["risk_score"] == 4
        assert result["risk_level"] == "Low"


# ---- score_alert: unknown type ----

class TestScoreAlertUnknown:

    def test_unknown_type_defaults_to_moderate_moderate(self):
        # if a new threat type comes in that isn't in the map, default to 3x3=9
        result = score_alert({"alert_type": "Some New Threat", "severity": "High"})
        assert result["likelihood_val"] == 3
        assert result["impact_val"] == 3
        assert result["risk_score"] == 9

    def test_result_has_required_keys(self):
        result = score_alert(_make_alert("Brute Force Attack"))
        for key in ("threat_type", "asset", "likelihood", "likelihood_val",
                    "impact", "impact_val", "risk_score", "risk_level"):
            assert key in result


# ---- score_all_alerts ----

class TestScoreAllAlerts:

    def test_returns_same_count_as_input(self):
        alerts = [_make_alert("Brute Force Attack"), _make_alert("Port Scan")]
        results = score_all_alerts(alerts)
        assert len(results) == 2

    def test_empty_input_returns_empty(self):
        assert score_all_alerts([]) == []


# ---- get_overall_risk_level ----

class TestGetOverallRiskLevel:

    def test_returns_highest_level(self):
        scores = [
            {"risk_score": 5},   # Low
            {"risk_score": 16},  # Very High
            {"risk_score": 11},  # High
        ]
        assert get_overall_risk_level(scores) == "Very High"

    def test_empty_list_returns_low(self):
        assert get_overall_risk_level([]) == "Low"

    def test_single_critical_score(self):
        assert get_overall_risk_level([{"risk_score": 25}]) == "Critical"


# ---- risk_level_to_colour ----

class TestRiskLevelToColour:

    def test_known_levels_return_expected_colour(self):
        assert risk_level_to_colour("Low") == "success"
        assert risk_level_to_colour("Medium") == "warning"
        assert risk_level_to_colour("High") == "orange"
        assert risk_level_to_colour("Very High") == "danger"
        assert risk_level_to_colour("Critical") == "dark"

    def test_unknown_level_returns_secondary(self):
        assert risk_level_to_colour("Whatever") == "secondary"


# ---- get_risk_summary_stats ----

class TestGetRiskSummaryStats:

    def test_counts_by_level(self):
        scores = [
            {"risk_level": "Low"},
            {"risk_level": "Low"},
            {"risk_level": "High"},
            {"risk_level": "Critical"},
        ]
        stats = get_risk_summary_stats(scores)
        assert stats["Low"] == 2
        assert stats["High"] == 1
        assert stats["Critical"] == 1
        assert stats["Medium"] == 0

    def test_empty_list_returns_all_zeros(self):
        stats = get_risk_summary_stats([])
        assert all(v == 0 for v in stats.values())
