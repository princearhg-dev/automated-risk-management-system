# data_generator.py - generates synthetic security events to feed the pipeline
#
# since this is a prototype there's no connection to real TUI systems, so
# this simulates the kinds of events that would come from a travel company's
# network - auth logs, firewall logs, application logs etc.
# the events are designed to match the threat types discussed in the lit review

import random
import string
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ASSET_TYPES, EVENT_SOURCES


# pool of fake IPs - mix of internal (10.x) and external addresses
INTERNAL_IPS = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(20)]
EXTERNAL_IPS = [
    f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for _ in range(30)
]
ALL_IPS = INTERNAL_IPS + EXTERNAL_IPS

# fake employee usernames that look realistic for a travel company
USERS = [
    "jsmith", "awhite", "mthompson", "lpatel", "kwilson",
    "cjohnson", "rmoore", "sgarcia", "tbrown", "nbaker",
    "admin", "svc_booking", "svc_crew", "svc_payment", "guest_api",
]

# ports commonly seen in enterprise environments
COMMON_PORTS = [22, 80, 443, 3389, 8080, 8443, 5432, 3306, 1433, 21]


# ---- individual event generators ----

def _make_failed_login(timestamp, attacker_ip=None):
    # if attacker_ip is given, use it - needed for brute force sequences
    # where all the events need to come from the same IP
    ip = attacker_ip or random.choice(EXTERNAL_IPS)
    return {
        "timestamp": timestamp,
        "source": "auth_log",
        "event_type": "failed_login",
        "source_ip": ip,
        "user_id": random.choice(USERS),
        "asset": random.choice(["Booking Platform", "Customer Database", "Flight Operations System"]),
        "details": {
            "reason": random.choice(["bad_password", "account_locked", "invalid_user"]),
            "port": 22 if random.random() < 0.5 else 443,
        }
    }


def _make_successful_login(timestamp):
    return {
        "timestamp": timestamp,
        "source": "auth_log",
        "event_type": "successful_login",
        "source_ip": random.choice(ALL_IPS),
        "user_id": random.choice(USERS),
        "asset": random.choice(ASSET_TYPES),
        "details": {
            "session_duration_s": random.randint(60, 7200),
            "mfa_used": random.choice([True, False]),
        }
    }


def _make_port_scan(timestamp, attacker_ip=None):
    # port scans generate one event per port, all from the same IP
    # the rule engine detects them by spotting many connection attempts from one source
    ip = attacker_ip or random.choice(EXTERNAL_IPS)
    ports_scanned = random.sample(range(1, 65535), random.randint(10, 30))
    events = []
    t = datetime.fromisoformat(timestamp)
    for i, port in enumerate(ports_scanned):
        events.append({
            "timestamp": (t + timedelta(seconds=i * 0.5)).isoformat(),
            "source": "firewall_log",
            "event_type": "connection_attempt",
            "source_ip": ip,
            "user_id": None,
            "asset": "Corporate Network",
            "details": {
                "destination_port": port,
                "protocol": "TCP",
                "action": "blocked",
            }
        })
    return events


def _make_data_exfiltration_attempt(timestamp):
    # large outbound transfer - could be legit backup or could be exfiltration
    # anything over 100MB gets flagged in the rule engine
    return {
        "timestamp": timestamp,
        "source": "network_log",
        "event_type": "large_data_transfer",
        "source_ip": random.choice(INTERNAL_IPS),
        "user_id": random.choice(USERS),
        "asset": random.choice(["Customer Database", "Payment Gateway"]),
        "details": {
            "bytes_transferred": random.randint(500_000_000, 5_000_000_000),
            "destination_ip": random.choice(EXTERNAL_IPS),
            "protocol": random.choice(["HTTP", "HTTPS", "FTP", "SFTP"]),
        }
    }


def _make_sql_injection_attempt(timestamp):
    # simulates a web app receiving a SQL injection payload in a request
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE customers;--",
        "1; SELECT * FROM users",
        "' UNION SELECT username,password FROM users--",
    ]
    return {
        "timestamp": timestamp,
        "source": "application_log",
        "event_type": "sql_injection_attempt",
        "source_ip": random.choice(EXTERNAL_IPS),
        "user_id": None,
        "asset": random.choice(["Booking Platform", "Hotel Reservation System"]),
        "details": {
            "url_path": random.choice(["/search", "/login", "/api/bookings"]),
            "payload_snippet": random.choice(payloads),
            "http_status": 400,
        }
    }


def _make_privilege_escalation(timestamp):
    # someone trying to access resources they shouldn't have
    return {
        "timestamp": timestamp,
        "source": "system_log",
        "event_type": "privilege_escalation_attempt",
        "source_ip": random.choice(INTERNAL_IPS),
        "user_id": random.choice(USERS),
        "asset": random.choice(["Crew Management System", "Payment Gateway", "Customer Database"]),
        "details": {
            "attempted_action": random.choice(["sudo su", "chmod 777 /etc/passwd", "grant dba"]),
            "result": "denied",
        }
    }


def _make_unusual_hours_login(timestamp):
    # forces the timestamp to be outside business hours (before 6am or after 10pm)
    t = datetime.fromisoformat(timestamp)
    off_hour = random.choice([23, 0, 1, 2, 3, 4])
    t = t.replace(hour=off_hour, minute=random.randint(0, 59))
    return {
        "timestamp": t.isoformat(),
        "source": "auth_log",
        "event_type": "off_hours_login",
        "source_ip": random.choice(ALL_IPS),
        "user_id": random.choice(USERS),
        "asset": random.choice(ASSET_TYPES),
        "details": {
            "hour": off_hour,
            "day_of_week": t.strftime("%A"),
        }
    }


def _make_config_change(timestamp):
    # someone changed a firewall rule or IAM policy - could be routine or malicious
    return {
        "timestamp": timestamp,
        "source": "system_log",
        "event_type": "config_change",
        "source_ip": random.choice(INTERNAL_IPS),
        "user_id": random.choice(USERS),
        "asset": random.choice(["Cloud Infrastructure", "Corporate Network"]),
        "details": {
            "component": random.choice(["firewall_rule", "iam_policy", "s3_bucket_policy", "security_group"]),
            "change_type": random.choice(["modified", "deleted", "created"]),
        }
    }


def _make_normal_event(timestamp):
    # routine system activity with no threat attached
    return {
        "timestamp": timestamp,
        "source": random.choice(EVENT_SOURCES),
        "event_type": random.choice(["dns_lookup", "api_call", "file_access", "service_start"]),
        "source_ip": random.choice(INTERNAL_IPS),
        "user_id": random.choice(USERS),
        "asset": random.choice(ASSET_TYPES),
        "details": {
            "bytes": random.randint(100, 50000),
            "duration_ms": random.randint(10, 2000),
        }
    }


# ---- main public functions ----

def generate_events(n=10, inject_threats=True):
    # generates n events - if inject_threats is True then some will be attack events
    # weighted random selection so normal events are more common than threats
    # which makes it feel more realistic
    events = []
    now = datetime.now()

    for i in range(n):
        # spread events over the last few minutes
        ts = (now - timedelta(seconds=random.randint(0, 300))).isoformat()

        if not inject_threats:
            events.append(_make_normal_event(ts))
            continue

        r = random.random()

        if r < 0.45:
            events.append(_make_normal_event(ts))
        elif r < 0.60:
            events.append(_make_failed_login(ts))
        elif r < 0.70:
            events.append(_make_successful_login(ts))
        elif r < 0.76:
            events.append(_make_sql_injection_attempt(ts))
        elif r < 0.82:
            events.append(_make_data_exfiltration_attempt(ts))
        elif r < 0.87:
            events.append(_make_privilege_escalation(ts))
        elif r < 0.91:
            events.append(_make_unusual_hours_login(ts))
        elif r < 0.95:
            events.append(_make_config_change(ts))
        else:
            events.append(_make_normal_event(ts))

    return events


def generate_brute_force_sequence(attacker_ip=None, count=8):
    # generates a burst of failed logins from the same IP to trigger the brute force rule
    ip = attacker_ip or random.choice(EXTERNAL_IPS)
    now = datetime.now()
    events = []

    for i in range(count):
        # all within 45 seconds so they fall inside the detection window
        ts = (now - timedelta(seconds=random.randint(0, 45))).isoformat()
        events.append(_make_failed_login(ts, attacker_ip=ip))

    return events


def generate_port_scan_sequence(attacker_ip=None):
    ip = attacker_ip or random.choice(EXTERNAL_IPS)
    now = datetime.now()
    return _make_port_scan(now.isoformat(), attacker_ip=ip)


def generate_historical_data(hours=24, events_per_hour=20):
    # generates a larger batch of past events to populate the DB at startup
    # so the dashboard has something to show straight away instead of being empty
    all_events = []
    now = datetime.now()

    for h in range(hours):
        for _ in range(events_per_hour):
            ts = (now - timedelta(hours=h, minutes=random.randint(0, 59))).isoformat()
            # occasionally inject a brute force burst to make the data more interesting
            if random.random() < 0.05:
                burst_ip = random.choice(EXTERNAL_IPS)
                for _ in range(random.randint(5, 10)):
                    t2 = (now - timedelta(hours=h, seconds=random.randint(0, 50))).isoformat()
                    all_events.append(_make_failed_login(t2, attacker_ip=burst_ip))
            else:
                all_events.append(generate_events(1)[0])

    return all_events
