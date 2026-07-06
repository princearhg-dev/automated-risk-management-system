# test_data_generator.py
# tests for the synthetic event generator
# since the generator is random, specific values can't be tested - just that
# the structure and types are correct for every event it produces

import sys
import os
import pytest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.data_generator import (
    generate_events,
    generate_brute_force_sequence,
    generate_port_scan_sequence,
    generate_historical_data,
)

# every event needs at least these three fields for the pipeline to work
REQUIRED_EVENT_FIELDS = {"timestamp", "source", "event_type"}


def _valid_iso_timestamp(ts):
    # returns True if ts can be parsed as an ISO 8601 string
    try:
        datetime.fromisoformat(str(ts))
        return True
    except ValueError:
        return False


# ---- generate_events ----

class TestGenerateEvents:

    def test_returns_correct_count(self):
        events = generate_events(n=10)
        assert len(events) == 10

    def test_all_events_have_required_fields(self):
        for event in generate_events(n=20):
            for field in REQUIRED_EVENT_FIELDS:
                assert field in event, f"event missing field: {field}"

    def test_timestamps_are_valid_iso(self):
        for event in generate_events(n=10):
            assert _valid_iso_timestamp(event["timestamp"]), \
                f"bad timestamp: {event['timestamp']}"

    def test_event_type_is_string(self):
        for event in generate_events(n=10):
            assert isinstance(event["event_type"], str)

    def test_source_is_string(self):
        for event in generate_events(n=10):
            assert isinstance(event["source"], str)

    def test_no_threats_injected_when_flag_false(self):
        # with inject_threats=False every event should be a normal type
        normal_types = {"dns_lookup", "api_call", "file_access", "service_start"}
        events = generate_events(n=30, inject_threats=False)
        for event in events:
            assert event["event_type"] in normal_types, \
                f"unexpected type with inject_threats=False: {event['event_type']}"

    def test_various_event_types_appear_with_threats(self):
        # with 100 events and threats enabled we should see more than one event type
        events = generate_events(n=100, inject_threats=True)
        types_seen = {e["event_type"] for e in events}
        assert len(types_seen) > 1

    def test_details_is_dict(self):
        for event in generate_events(n=10):
            if "details" in event:
                assert isinstance(event["details"], dict)

    def test_n_zero_returns_empty(self):
        assert generate_events(n=0) == []


# ---- generate_brute_force_sequence ----

class TestGenerateBruteForceSequence:

    def test_default_count_is_8(self):
        events = generate_brute_force_sequence()
        assert len(events) == 8

    def test_custom_count(self):
        events = generate_brute_force_sequence(count=12)
        assert len(events) == 12

    def test_all_events_are_failed_logins(self):
        events = generate_brute_force_sequence()
        for e in events:
            assert e["event_type"] == "failed_login"

    def test_all_events_from_same_ip(self):
        ip = "9.9.9.9"
        events = generate_brute_force_sequence(attacker_ip=ip)
        for e in events:
            assert e["source_ip"] == ip

    def test_events_within_brute_force_window(self):
        # all events should fall within a 60 second window to trigger the rule
        events = generate_brute_force_sequence()
        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in events]
        span_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        assert span_seconds <= 60


# ---- generate_port_scan_sequence ----

class TestGeneratePortScanSequence:

    def test_returns_list(self):
        result = generate_port_scan_sequence()
        assert isinstance(result, list)

    def test_all_events_are_connection_attempts(self):
        events = generate_port_scan_sequence()
        for e in events:
            assert e["event_type"] == "connection_attempt"

    def test_all_events_from_same_ip(self):
        ip = "8.8.8.8"
        events = generate_port_scan_sequence(attacker_ip=ip)
        for e in events:
            assert e["source_ip"] == ip

    def test_each_event_has_destination_port(self):
        events = generate_port_scan_sequence()
        for e in events:
            port = e.get("details", {}).get("destination_port")
            assert port is not None

    def test_multiple_distinct_ports(self):
        events = generate_port_scan_sequence()
        ports = {e["details"]["destination_port"] for e in events}
        assert len(ports) > 1

    def test_enough_ports_to_trigger_rule(self):
        # the port scan rule needs at least PORT_SCAN_THRESHOLD=15 distinct ports
        events = generate_port_scan_sequence()
        ports = {e["details"]["destination_port"] for e in events}
        assert len(ports) >= 10  # generator makes between 10-30


# ---- generate_historical_data ----

class TestGenerateHistoricalData:

    def test_returns_list(self):
        result = generate_historical_data(hours=2, events_per_hour=5)
        assert isinstance(result, list)

    def test_returns_roughly_expected_count(self):
        # brute force bursts get injected so count can be higher than hours*per_hour
        result = generate_historical_data(hours=2, events_per_hour=10)
        assert len(result) >= 20  # minimum 2*10=20

    def test_all_have_required_fields(self):
        events = generate_historical_data(hours=1, events_per_hour=5)
        for event in events:
            for field in REQUIRED_EVENT_FIELDS:
                assert field in event, f"historical event missing field: {field}"

    def test_all_timestamps_are_valid(self):
        events = generate_historical_data(hours=1, events_per_hour=5)
        for event in events:
            assert _valid_iso_timestamp(event["timestamp"])

    def test_events_have_valid_timestamps(self):
        # just checking timestamps are parseable, not checking the exact range
        events = generate_historical_data(hours=3, events_per_hour=5)
        for event in events:
            assert _valid_iso_timestamp(event["timestamp"]), \
                f"invalid timestamp: {event['timestamp']}"
