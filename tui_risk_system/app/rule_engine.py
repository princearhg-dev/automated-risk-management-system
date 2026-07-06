# rule_engine.py - rule-based threat detection
#
# this implements the rule-based half of the hybrid detection engine
# each rule looks for a specific known attack pattern in the event stream
# seven rules chosen to cover the most common threats
# relevant to a travel company like TUI based on the literature review

from datetime import datetime, timedelta
from collections import defaultdict

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS, PORT_SCAN_THRESHOLD
)


def _now_str():
    return datetime.now().isoformat(timespec="seconds")


# ---- individual detection rules ----

def rule_brute_force(events):
    # fires when the same IP generates more than BRUTE_FORCE_THRESHOLD failed logins
    # within BRUTE_FORCE_WINDOW_SECONDS seconds
    # brute force is one of the most common automated attacks against internet-facing
    # login pages, which TUI's booking portal definitely is
    detections = []

    # group failed logins by source IP first
    failed_by_ip = defaultdict(list)
    for e in events:
        if e.get("event_type") == "failed_login" and e.get("source_ip"):
            failed_by_ip[e["source_ip"]].append(e)

    window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)

    for ip, login_events in failed_by_ip.items():
        sorted_events = sorted(login_events, key=lambda x: x["timestamp"])

        # sliding window - each event is checked as a potential start of a burst
        for i, start_event in enumerate(sorted_events):
            try:
                start_time = datetime.fromisoformat(start_event["timestamp"])
            except ValueError:
                continue

            in_window = [
                e for e in sorted_events[i:]
                if abs(datetime.fromisoformat(e["timestamp"]) - start_time) <= window
            ]

            if len(in_window) >= BRUTE_FORCE_THRESHOLD:
                event_ids = [e.get("id") for e in in_window if e.get("id")]

                detections.append({
                    "alert_type": "Brute Force Attack",
                    "severity": "High",
                    "source_ip": ip,
                    "user_id": start_event.get("user_id"),
                    "asset": start_event.get("asset", "Unknown"),
                    "description": (
                        f"Brute force attack detected: {len(in_window)} failed login "
                        f"attempts from {ip} within {BRUTE_FORCE_WINDOW_SECONDS} seconds."
                    ),
                    "event_ids": ",".join(str(i) for i in event_ids),
                    "triggered_rule": "brute_force",
                })
                # break to avoid reporting the same IP multiple times
                break

    return detections


def rule_port_scan(events):
    # fires when one IP hits more than PORT_SCAN_THRESHOLD distinct ports
    # port scanning is usually reconnaissance before a more targeted attack
    # tracking distinct ports per IP across the event batch
    detections = []

    ports_by_ip = defaultdict(set)
    ip_to_event = {}

    for e in events:
        if e.get("event_type") == "connection_attempt" and e.get("source_ip"):
            ip = e["source_ip"]
            port = e.get("details", {}).get("destination_port")
            if port:
                ports_by_ip[ip].add(port)
                ip_to_event[ip] = e

    for ip, ports in ports_by_ip.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            e = ip_to_event[ip]
            detections.append({
                "alert_type": "Port Scan",
                "severity": "Medium",
                "source_ip": ip,
                "user_id": None,
                "asset": e.get("asset", "Corporate Network"),
                "description": (
                    f"Port scan detected: {ip} attempted connections to "
                    f"{len(ports)} distinct ports."
                ),
                "event_ids": "",
                "triggered_rule": "port_scan",
            })

    return detections


def rule_sql_injection(events):
    # any event already flagged as sql_injection_attempt gets an alert
    # the application log labels these when it spots suspicious payload patterns
    detections = []

    for e in events:
        if e.get("event_type") == "sql_injection_attempt":
            detections.append({
                "alert_type": "SQL Injection Attempt",
                "severity": "High",
                "source_ip": e.get("source_ip"),
                "user_id": None,
                "asset": e.get("asset", "Unknown"),
                "description": (
                    f"SQL injection attempt detected against {e.get('asset')} "
                    f"from {e.get('source_ip')}."
                ),
                "event_ids": str(e.get("id", "")),
                "triggered_rule": "sql_injection",
            })

    return detections


def rule_privilege_escalation(events):
    # fires on any privilege_escalation_attempt event
    # insider threats trying to escalate privileges are particularly concerning
    # for TUI because of the sensitive systems they could reach (crew, payments)
    detections = []

    for e in events:
        if e.get("event_type") == "privilege_escalation_attempt":
            detections.append({
                "alert_type": "Privilege Escalation Attempt",
                "severity": "High",
                "source_ip": e.get("source_ip"),
                "user_id": e.get("user_id"),
                "asset": e.get("asset", "Unknown"),
                "description": (
                    f"Privilege escalation attempt by user {e.get('user_id')} "
                    f"on {e.get('asset')}."
                ),
                "event_ids": str(e.get("id", "")),
                "triggered_rule": "privilege_escalation",
            })

    return detections


def rule_off_hours_access(events):
    # flags logins outside business hours (before 6am or after 10pm)
    # not everything outside hours is malicious - shift workers exist -
    # but it's worth flagging for review, hence Low severity
    # relies on the is_off_hours field set by the processor rather than
    # recalculating the hour here
    detections = []

    for e in events:
        if e.get("event_type") in ("off_hours_login", "successful_login"):
            if e.get("is_off_hours"):
                detections.append({
                    "alert_type": "Off-Hours Access",
                    "severity": "Low",
                    "source_ip": e.get("source_ip"),
                    "user_id": e.get("user_id"),
                    "asset": e.get("asset", "Unknown"),
                    "description": (
                        f"Access outside business hours by {e.get('user_id')} "
                        f"at {e.get('hour', '?')}:00 on {e.get('day_of_week', '?')}."
                    ),
                    "event_ids": str(e.get("id", "")),
                    "triggered_rule": "off_hours_access",
                })

    return detections


def rule_large_data_transfer(events):
    # flags any outbound transfer over 100MB
    # could be a backup job or could be data exfiltration - either way it needs a look
    # TUI holds a lot of customer PII so data exfiltration is a high-impact scenario
    detections = []
    THRESHOLD_BYTES = 100 * 1024 * 1024  # 100 MB

    for e in events:
        if e.get("event_type") == "large_data_transfer":
            bytes_val = e.get("details", {}).get("bytes_transferred", 0)
            if bytes_val >= THRESHOLD_BYTES:
                mb = bytes_val // (1024 * 1024)
                detections.append({
                    "alert_type": "Suspicious Data Transfer",
                    "severity": "Medium",
                    "source_ip": e.get("source_ip"),
                    "user_id": e.get("user_id"),
                    "asset": e.get("asset", "Unknown"),
                    "description": (
                        f"Large outbound data transfer of {mb}MB detected "
                        f"from {e.get('source_ip')} to external destination."
                    ),
                    "event_ids": str(e.get("id", "")),
                    "triggered_rule": "large_data_transfer",
                })

    return detections


def rule_config_change(events):
    # any security config change gets flagged - deletions are High severity
    # because deleting a firewall rule or IAM policy could expose the whole system
    # modifications and creations are Low since they might be routine maintenance
    detections = []

    for e in events:
        if e.get("event_type") == "config_change":
            change_type = e.get("details", {}).get("change_type", "")
            severity = "High" if change_type == "deleted" else "Low"
            component = e.get("details", {}).get("component", "unknown")

            detections.append({
                "alert_type": "Security Configuration Change",
                "severity": severity,
                "source_ip": e.get("source_ip"),
                "user_id": e.get("user_id"),
                "asset": e.get("asset", "Unknown"),
                "description": (
                    f"Security config change: {component} was {change_type} "
                    f"by {e.get('user_id')} on {e.get('asset')}."
                ),
                "event_ids": str(e.get("id", "")),
                "triggered_rule": "config_change",
            })

    return detections


# ---- rule runner ----

ALL_RULES = [
    rule_brute_force,
    rule_port_scan,
    rule_sql_injection,
    rule_privilege_escalation,
    rule_off_hours_access,
    rule_large_data_transfer,
    rule_config_change,
]


def run_all_rules(events):
    # runs every rule against the event list and collects all the detections
    # catching exceptions per rule so one broken rule doesn't kill the whole pipeline
    all_detections = []
    timestamp = _now_str()

    for rule_fn in ALL_RULES:
        try:
            results = rule_fn(events)
            for det in results:
                det["timestamp"] = timestamp
            all_detections.extend(results)
        except Exception as ex:
            print(f"[RuleEngine] Rule {rule_fn.__name__} failed: {ex}")

    return all_detections


def get_rule_names():
    return [r.__name__ for r in ALL_RULES]
