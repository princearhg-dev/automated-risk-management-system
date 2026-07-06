# test_rule_engine.py
# unit tests for the rule-based detection engine
# each rule is tested separately so it's easy to see exactly what triggers it

import sys
import os
import pytest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.rule_engine import (
    rule_brute_force,
    rule_port_scan,
    rule_sql_injection,
    rule_privilege_escalation,
    rule_off_hours_access,
    rule_large_data_transfer,
    rule_config_change,
    run_all_rules,
    get_rule_names,
    ALL_RULES,
)


# ---- Brute Force ----

class TestRuleBruteForce:

    def _make_failed_logins(self, ip, count, within_seconds=30):
        # builds a list of failed login events from the same IP within a time window
        now = datetime.now()
        events = []
        for i in range(count):
            ts = (now - timedelta(seconds=i * (within_seconds / count))).isoformat()
            events.append({
                "timestamp": ts,
                "event_type": "failed_login",
                "source_ip": ip,
                "user_id": "jsmith",
                "asset": "Booking Platform",
            })
        return events

    def test_fires_on_five_or_more_in_window(self):
        events = self._make_failed_logins("1.2.3.4", count=6)
        detections = rule_brute_force(events)
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "Brute Force Attack"
        assert detections[0]["source_ip"] == "1.2.3.4"
        assert detections[0]["severity"] == "High"

    def test_does_not_fire_below_threshold(self):
        events = self._make_failed_logins("1.2.3.4", count=3)
        detections = rule_brute_force(events)
        assert len(detections) == 0

    def test_does_not_fire_on_successful_logins(self):
        # successful logins shouldn't trigger brute force even with lots of them
        now = datetime.now()
        events = [
            {"timestamp": (now - timedelta(seconds=i)).isoformat(),
             "event_type": "successful_login",
             "source_ip": "1.2.3.4",
             "user_id": "jsmith",
             "asset": "Booking Platform"}
            for i in range(8)
        ]
        detections = rule_brute_force(events)
        assert len(detections) == 0

    def test_separate_ips_not_grouped(self):
        # 3 from each IP - neither should trigger on its own
        e1 = self._make_failed_logins("1.2.3.4", count=3)
        e2 = self._make_failed_logins("5.6.7.8", count=3)
        detections = rule_brute_force(e1 + e2)
        assert len(detections) == 0

    def test_both_ips_trigger_independently(self):
        e1 = self._make_failed_logins("1.2.3.4", count=6)
        e2 = self._make_failed_logins("5.6.7.8", count=6)
        detections = rule_brute_force(e1 + e2)
        ips = {d["source_ip"] for d in detections}
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_empty_events_returns_empty(self):
        assert rule_brute_force([]) == []


# ---- Port Scan ----

class TestRulePortScan:

    def _make_scan_events(self, ip, num_ports):
        # connection attempts to num_ports distinct ports from the same IP
        now = datetime.now()
        events = []
        for port in range(1000, 1000 + num_ports):
            events.append({
                "timestamp": now.isoformat(),
                "event_type": "connection_attempt",
                "source_ip": ip,
                "user_id": None,
                "asset": "Corporate Network",
                "details": {"destination_port": port},
            })
        return events

    def test_fires_at_threshold(self):
        events = self._make_scan_events("9.9.9.9", 15)
        detections = rule_port_scan(events)
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "Port Scan"
        assert detections[0]["severity"] == "Medium"

    def test_does_not_fire_below_threshold(self):
        events = self._make_scan_events("9.9.9.9", 10)
        detections = rule_port_scan(events)
        assert len(detections) == 0

    def test_events_without_port_in_details_ignored(self):
        # if there's no destination_port in details the event shouldn't count
        now = datetime.now()
        events = [
            {"timestamp": now.isoformat(), "event_type": "connection_attempt",
             "source_ip": "9.9.9.9", "details": {}}
            for _ in range(20)
        ]
        detections = rule_port_scan(events)
        assert len(detections) == 0

    def test_empty_events_returns_empty(self):
        assert rule_port_scan([]) == []


# ---- SQL Injection ----

class TestRuleSqlInjection:

    def _make_sqli_event(self, ip="5.5.5.5", asset="Booking Platform"):
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": "sql_injection_attempt",
            "source_ip": ip,
            "user_id": None,
            "asset": asset,
            "details": {"payload": "' OR '1'='1"},
        }

    def test_fires_on_sqli_event(self):
        detections = rule_sql_injection([self._make_sqli_event()])
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "SQL Injection Attempt"
        assert detections[0]["severity"] == "High"

    def test_fires_multiple_for_multiple_events(self):
        events = [self._make_sqli_event(ip=f"1.2.3.{i}") for i in range(3)]
        detections = rule_sql_injection(events)
        assert len(detections) == 3

    def test_ignores_other_event_types(self):
        event = {"timestamp": datetime.now().isoformat(), "event_type": "failed_login",
                 "source_ip": "1.2.3.4", "details": {}}
        assert rule_sql_injection([event]) == []

    def test_empty_events_returns_empty(self):
        assert rule_sql_injection([]) == []


# ---- Privilege Escalation ----

class TestRulePrivilegeEscalation:

    def _make_priv_esc(self, user="jsmith"):
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": "privilege_escalation_attempt",
            "source_ip": "10.0.0.5",
            "user_id": user,
            "asset": "Crew Management System",
            "details": {"attempted_action": "sudo su"},
        }

    def test_fires_on_privilege_escalation(self):
        detections = rule_privilege_escalation([self._make_priv_esc()])
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "Privilege Escalation Attempt"
        assert detections[0]["severity"] == "High"

    def test_detection_includes_user_id(self):
        detections = rule_privilege_escalation([self._make_priv_esc(user="admin")])
        assert detections[0]["user_id"] == "admin"

    def test_ignores_other_event_types(self):
        event = {"timestamp": datetime.now().isoformat(), "event_type": "failed_login",
                 "source_ip": "10.0.0.1", "user_id": "jsmith", "details": {}}
        assert rule_privilege_escalation([event]) == []


# ---- Off-Hours Access ----

class TestRuleOffHoursAccess:

    def _make_off_hours_login(self, hour=2, event_type="off_hours_login"):
        return {
            "timestamp": f"2024-06-01T{hour:02d}:15:00",
            "event_type": event_type,
            "source_ip": "10.0.0.10",
            "user_id": "kwilson",
            "asset": "Booking Platform",
            "hour": hour,
            "day_of_week": "Saturday",
            "is_off_hours": True,
        }

    def test_fires_on_off_hours_login_event_type(self):
        detections = rule_off_hours_access([self._make_off_hours_login(hour=2)])
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "Off-Hours Access"
        assert detections[0]["severity"] == "Low"

    def test_fires_on_successful_login_with_off_hours_flag(self):
        # a successful login at 11pm should still flag if is_off_hours is true
        event = self._make_off_hours_login(hour=23, event_type="successful_login")
        detections = rule_off_hours_access([event])
        assert len(detections) == 1

    def test_does_not_fire_when_is_off_hours_false(self):
        event = self._make_off_hours_login(hour=10)
        event["is_off_hours"] = False
        assert rule_off_hours_access([event]) == []

    def test_does_not_fire_on_failed_login(self):
        # failed logins are handled by the brute force rule, not this one
        event = {"timestamp": "2024-06-01T02:00:00", "event_type": "failed_login",
                 "source_ip": "10.0.0.1", "user_id": "jsmith", "is_off_hours": True}
        assert rule_off_hours_access([event]) == []


# ---- Large Data Transfer ----

class TestRuleLargeDataTransfer:

    def _make_transfer_event(self, bytes_val):
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": "large_data_transfer",
            "source_ip": "10.0.0.20",
            "user_id": "svc_payment",
            "asset": "Customer Database",
            "details": {"bytes_transferred": bytes_val},
        }

    def test_fires_at_100mb(self):
        # threshold is exactly 100MB
        threshold = 100 * 1024 * 1024
        detections = rule_large_data_transfer([self._make_transfer_event(threshold)])
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "Suspicious Data Transfer"
        assert detections[0]["severity"] == "Medium"

    def test_fires_above_threshold(self):
        detections = rule_large_data_transfer([self._make_transfer_event(500_000_000)])
        assert len(detections) == 1

    def test_does_not_fire_below_threshold(self):
        detections = rule_large_data_transfer([self._make_transfer_event(50 * 1024 * 1024)])
        assert len(detections) == 0

    def test_zero_bytes_does_not_fire(self):
        assert rule_large_data_transfer([self._make_transfer_event(0)]) == []


# ---- Config Change ----

class TestRuleConfigChange:

    def _make_config_event(self, change_type="modified"):
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": "config_change",
            "source_ip": "10.0.0.3",
            "user_id": "admin",
            "asset": "Cloud Infrastructure",
            "details": {"component": "firewall_rule", "change_type": change_type},
        }

    def test_fires_on_any_config_change(self):
        detections = rule_config_change([self._make_config_event("modified")])
        assert len(detections) == 1
        assert detections[0]["alert_type"] == "Security Configuration Change"

    def test_deleted_gets_high_severity(self):
        # deleting a config is more serious than modifying it
        detections = rule_config_change([self._make_config_event("deleted")])
        assert detections[0]["severity"] == "High"

    def test_modified_gets_low_severity(self):
        detections = rule_config_change([self._make_config_event("modified")])
        assert detections[0]["severity"] == "Low"

    def test_created_gets_low_severity(self):
        detections = rule_config_change([self._make_config_event("created")])
        assert detections[0]["severity"] == "Low"

    def test_empty_events_returns_empty(self):
        assert rule_config_change([]) == []


# ---- run_all_rules ----

class TestRunAllRules:

    def test_returns_list(self):
        result = run_all_rules([])
        assert isinstance(result, list)

    def test_all_detections_have_timestamp(self):
        events = [
            {"timestamp": datetime.now().isoformat(), "event_type": "sql_injection_attempt",
             "source_ip": "5.5.5.5", "asset": "Booking Platform", "details": {}}
        ]
        result = run_all_rules(events)
        for det in result:
            assert "timestamp" in det

    def test_get_rule_names_returns_correct_count(self):
        names = get_rule_names()
        assert len(names) == len(ALL_RULES)

    def test_run_all_rules_catches_exceptions(self):
        # even with badly formed events it shouldn't crash the whole thing
        broken_events = [{"event_type": "failed_login"}]  # missing timestamp/ip
        try:
            run_all_rules(broken_events)
        except Exception:
            pytest.fail("run_all_rules should not raise exceptions")
