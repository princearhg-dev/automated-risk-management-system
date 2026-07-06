# test_processor.py
# tests for the data processing layer - validation, normalisation, dedup and enrichment
# process_batch is also tested since it ties all of these together

import sys
import os
import pytest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.processor import (
    validate_event,
    normalise_event,
    is_duplicate,
    enrich_event,
    process_batch,
    reset_dedup_store,
)


# -- Helpers --

def _make_event(**overrides):
    # minimal valid event, any field can be overridden by tests
    base = {
        "timestamp": "2024-06-01T10:00:00",
        "source": "auth_log",
        "event_type": "failed_login",
        "source_ip": "10.0.0.1",
        "user_id": "jsmith",
        "asset": "Booking Platform",
        "details": {},
    }
    base.update(overrides)
    return base


# ---- validate_event ----

class TestValidateEvent:

    def test_valid_event_returns_true(self):
        ok, reason = validate_event(_make_event())
        assert ok is True
        assert reason is None

    def test_missing_timestamp_fails(self):
        e = _make_event()
        del e["timestamp"]
        ok, reason = validate_event(e)
        assert ok is False
        assert "timestamp" in reason

    def test_missing_source_fails(self):
        e = _make_event()
        del e["source"]
        ok, reason = validate_event(e)
        assert ok is False
        assert "source" in reason

    def test_missing_event_type_fails(self):
        e = _make_event()
        del e["event_type"]
        ok, reason = validate_event(e)
        assert ok is False
        assert "event_type" in reason

    def test_none_timestamp_fails(self):
        ok, reason = validate_event(_make_event(timestamp=None))
        assert ok is False

    def test_bad_timestamp_format_fails(self):
        ok, reason = validate_event(_make_event(timestamp="not-a-date"))
        assert ok is False
        assert "invalid timestamp" in reason

    def test_datetime_object_as_timestamp_is_valid(self):
        # validate_event handles datetime objects via fromisoformat(str(...))
        ok, reason = validate_event(_make_event(timestamp=datetime(2024, 6, 1, 10, 0, 0)))
        assert ok is True


# ---- normalise_event ----

class TestNormaliseEvent:

    def test_source_lowercased(self):
        result = normalise_event(_make_event(source="AUTH_LOG"))
        assert result["source"] == "auth_log"

    def test_event_type_lowercased(self):
        result = normalise_event(_make_event(event_type="FAILED_LOGIN"))
        assert result["event_type"] == "failed_login"

    def test_timestamp_truncated_to_seconds(self):
        result = normalise_event(_make_event(timestamp="2024-06-01T10:00:00.123456"))
        # fractions of a second get stripped
        assert "." not in result["timestamp"]
        assert result["timestamp"] == "2024-06-01T10:00:00"

    def test_datetime_object_timestamp_converted(self):
        dt = datetime(2024, 6, 1, 10, 0, 0)
        result = normalise_event(_make_event(timestamp=dt))
        assert result["timestamp"] == "2024-06-01T10:00:00"

    def test_details_string_parsed_to_dict(self):
        result = normalise_event(_make_event(details='{"key": "value"}'))
        assert isinstance(result["details"], dict)
        assert result["details"]["key"] == "value"

    def test_details_invalid_json_wrapped_in_raw(self):
        result = normalise_event(_make_event(details="not json"))
        assert isinstance(result["details"], dict)
        assert "raw" in result["details"]

    def test_details_none_becomes_empty_dict(self):
        result = normalise_event(_make_event(details=None))
        assert result["details"] == {}

    def test_missing_optional_fields_default_to_none(self):
        e = {"timestamp": "2024-06-01T10:00:00", "source": "auth_log", "event_type": "failed_login"}
        result = normalise_event(e)
        assert result["source_ip"] is None
        assert result["user_id"] is None
        assert result["asset"] is None


# ---- is_duplicate ----

class TestIsDuplicate:

    def setup_method(self):
        # always start with a clean dedup store between tests
        reset_dedup_store()

    def test_first_occurrence_not_duplicate(self):
        assert is_duplicate(_make_event()) is False

    def test_second_same_event_is_duplicate(self):
        e = _make_event()
        is_duplicate(e)  # first call registers it
        assert is_duplicate(e) is True

    def test_different_ip_not_duplicate(self):
        e1 = _make_event(source_ip="10.0.0.1")
        e2 = _make_event(source_ip="10.0.0.2")
        is_duplicate(e1)
        assert is_duplicate(e2) is False

    def test_different_event_type_not_duplicate(self):
        e1 = _make_event(event_type="failed_login")
        e2 = _make_event(event_type="successful_login")
        is_duplicate(e1)
        assert is_duplicate(e2) is False

    def test_reset_clears_duplicates(self):
        e = _make_event()
        is_duplicate(e)
        reset_dedup_store()
        # after reset the same event should not be flagged
        assert is_duplicate(e) is False


# ---- enrich_event ----

class TestEnrichEvent:

    def test_hour_extracted(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T14:30:00"))
        assert result["hour"] == 14

    def test_day_of_week_extracted(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T14:30:00"))
        # 2024-06-01 is a Saturday
        assert result["day_of_week"] == "Saturday"

    def test_off_hours_early_morning(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T03:00:00"))
        assert result["is_off_hours"] is True

    def test_off_hours_late_night(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T23:00:00"))
        assert result["is_off_hours"] is True

    def test_not_off_hours_during_day(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T09:00:00"))
        assert result["is_off_hours"] is False

    def test_boundary_06_not_off_hours(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T06:00:00"))
        assert result["is_off_hours"] is False

    def test_boundary_22_is_off_hours(self):
        result = enrich_event(_make_event(timestamp="2024-06-01T22:00:00"))
        assert result["is_off_hours"] is True

    def test_internal_ip_flagged(self):
        result = enrich_event(_make_event(source_ip="10.0.1.5"))
        assert result["is_internal_ip"] is True

    def test_external_ip_not_internal(self):
        result = enrich_event(_make_event(source_ip="8.8.8.8"))
        assert result["is_internal_ip"] is False

    def test_192_168_is_internal(self):
        result = enrich_event(_make_event(source_ip="192.168.1.1"))
        assert result["is_internal_ip"] is True

    def test_missing_ip_gives_none(self):
        e = _make_event()
        del e["source_ip"]
        result = enrich_event(e)
        assert result["is_internal_ip"] is None


# ---- process_batch ----

class TestProcessBatch:

    def setup_method(self):
        reset_dedup_store()

    def test_valid_events_returned(self):
        events = [_make_event(source_ip=f"10.0.0.{i}", timestamp=f"2024-06-01T10:00:{i:02d}") for i in range(5)]
        valid, dropped = process_batch(events)
        assert len(valid) == 5
        assert dropped == 0

    def test_invalid_events_counted_in_dropped(self):
        bad = {"source": "auth_log", "event_type": "failed_login"}  # no timestamp
        events = [bad, _make_event()]
        valid, dropped = process_batch(events)
        assert dropped >= 1
        assert len(valid) == 1

    def test_duplicates_counted_in_dropped(self):
        e = _make_event()
        valid, dropped = process_batch([e, e])
        assert len(valid) == 1
        assert dropped == 1

    def test_output_events_are_enriched(self):
        events = [_make_event()]
        valid, _ = process_batch(events)
        # enrichment fields should all be present after processing
        assert "hour" in valid[0]
        assert "is_off_hours" in valid[0]
        assert "is_internal_ip" in valid[0]

    def test_empty_batch_returns_empty(self):
        valid, dropped = process_batch([])
        assert valid == []
        assert dropped == 0
