# processor.py - data processing and filtering layer
#
# this sits between the event collection and the detection engine
# its job is to clean up events, normalise the fields, remove duplicates
# and drop anything obviously broken so the detection engine gets consistent input
# it maps to the "Data Processing and Filtering Layer" in the design chapter

import json
import hashlib
from datetime import datetime


# minimum fields every event must have to be considered valid
REQUIRED_FIELDS = {"timestamp", "source", "event_type"}

# in-memory store of event hashes we've already processed this session
# in a production system this would be Redis or something persistent,
# but for a prototype keeping it in memory is fine
_seen_hashes = set()


def _event_hash(event):
    # hashing timestamp + IP + event type to spot duplicates
    # two events with all three the same are almost certainly the same event arriving twice
    key = f"{event.get('timestamp')}|{event.get('source_ip')}|{event.get('event_type')}"
    return hashlib.md5(key.encode()).hexdigest()


def validate_event(event):
    # checks the required fields exist and the timestamp is a valid ISO string
    # returns (True, None) if valid, (False, reason) if not
    for field in REQUIRED_FIELDS:
        if field not in event or event[field] is None:
            return False, f"missing required field: {field}"

    try:
        datetime.fromisoformat(str(event["timestamp"]))
    except ValueError:
        return False, f"invalid timestamp format: {event['timestamp']}"

    return True, None


def normalise_event(event):
    # standardises the event so everything downstream gets consistent types and formats
    # some events come in with uppercase sources or microsecond timestamps which caused
    # inconsistencies - stripping those here
    normalised = {}

    ts = event["timestamp"]
    if isinstance(ts, datetime):
        normalised["timestamp"] = ts.isoformat(timespec="seconds")
    else:
        try:
            dt = datetime.fromisoformat(str(ts))
            normalised["timestamp"] = dt.isoformat(timespec="seconds")
        except ValueError:
            normalised["timestamp"] = str(ts)

    normalised["source"] = str(event["source"]).lower().strip()
    normalised["event_type"] = str(event["event_type"]).lower().strip()

    # optional fields default to None if missing
    normalised["source_ip"] = event.get("source_ip")
    normalised["user_id"] = event.get("user_id")
    normalised["asset"] = event.get("asset")

    # details can come in as a dict or a JSON string depending on the source
    # normalised to always be a dict
    raw_details = event.get("details")
    if isinstance(raw_details, str):
        try:
            normalised["details"] = json.loads(raw_details)
        except json.JSONDecodeError:
            normalised["details"] = {"raw": raw_details}
    elif isinstance(raw_details, dict):
        normalised["details"] = raw_details
    else:
        normalised["details"] = {}

    return normalised


def is_duplicate(event):
    # returns True if this event has already been processed in the current session
    h = _event_hash(event)
    if h in _seen_hashes:
        return True
    _seen_hashes.add(h)
    return False


def enrich_event(event):
    # adds some derived fields that the detection rules find useful
    # mainly extracting the hour and checking if it's outside business hours
    enriched = dict(event)  # copy so the original event isn't mutated

    try:
        dt = datetime.fromisoformat(event["timestamp"])
        enriched["hour"] = dt.hour
        enriched["day_of_week"] = dt.strftime("%A")
        # off hours = before 6am or 10pm onwards
        enriched["is_off_hours"] = dt.hour < 6 or dt.hour >= 22
    except (ValueError, KeyError):
        enriched["hour"] = None
        enriched["day_of_week"] = None
        enriched["is_off_hours"] = False

    # flag whether the source IP is internal or external
    ip = event.get("source_ip", "")
    if ip:
        enriched["is_internal_ip"] = (
            ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")
        )
    else:
        enriched["is_internal_ip"] = None

    return enriched


def process_batch(raw_events):
    # main entry point - takes raw events, runs them through the full processing chain
    # and returns (valid_events, dropped_count)
    # called by the monitor loop before passing events to the detection engine
    valid_events = []
    dropped = 0
    duplicate_count = 0

    for event in raw_events:
        # validate first
        ok, reason = validate_event(event)
        if not ok:
            dropped += 1
            continue

        # check for duplicates
        if is_duplicate(event):
            duplicate_count += 1
            continue

        # normalise then enrich
        norm = normalise_event(event)
        enriched = enrich_event(norm)

        valid_events.append(enriched)

    return valid_events, dropped + duplicate_count


def reset_dedup_store():
    # clears the in-memory hash store - mainly used in tests to avoid
    # state leaking between test cases
    global _seen_hashes
    _seen_hashes = set()
