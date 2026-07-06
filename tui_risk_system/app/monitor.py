# monitor.py - the background monitoring loop
#
# this ties all the pipeline layers together and runs continuously in the background
# every MONITOR_INTERVAL seconds it generates new events, processes them,
# runs detection, scores any findings, and saves everything to the database
#
# the data flow follows what's described in the design chapter:
# Collection -> Processing -> Analytics -> Storage -> Visualisation

import threading
import time
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MONITOR_INTERVAL, EVENTS_PER_CYCLE
from app.data_generator import generate_events
from app.processor import process_batch
from app.rule_engine import run_all_rules
from app.anomaly_detector import analyse_events
from app.risk_scorer import score_alert
from app import database as db


def run_pipeline_cycle():
    # runs one full cycle of the pipeline and returns a summary dict
    # broken out into its own function so it's easy to test in isolation

    # step 1: generate new synthetic events
    raw_events = generate_events(n=EVENTS_PER_CYCLE, inject_threats=True)

    # step 2: process and filter them
    clean_events, dropped = process_batch(raw_events)

    if not clean_events:
        return {"generated": len(raw_events), "stored": 0, "alerts": 0}

    # step 3: store the valid events
    db.insert_events_bulk(clean_events)

    # fetch back recent events with their DB IDs so the rule engine can reference them
    recent = db.get_recent_events(limit=EVENTS_PER_CYCLE * 2)

    # step 4a: rule-based detection on recent events
    rule_detections = run_all_rules(recent)

    # step 4b: statistical anomaly detection on the current batch
    anomaly_detections = analyse_events(clean_events)

    all_detections = rule_detections + anomaly_detections

    # step 5: score each detection and save both the alert and risk score
    alert_count = 0
    now_str = datetime.now().isoformat(timespec="seconds")

    for detection in all_detections:
        risk_assessment = score_alert(detection)

        alert_id = db.insert_alert(
            timestamp=detection.get("timestamp", now_str),
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            source_ip=detection.get("source_ip"),
            user_id=detection.get("user_id"),
            asset=detection.get("asset"),
            description=detection.get("description"),
            event_ids=detection.get("event_ids", ""),
            risk_score=risk_assessment["risk_score"],
        )

        db.insert_risk_score(
            timestamp=now_str,
            alert_id=alert_id,
            threat_type=risk_assessment["threat_type"],
            asset=risk_assessment["asset"],
            likelihood=risk_assessment["likelihood"],
            likelihood_val=risk_assessment["likelihood_val"],
            impact=risk_assessment["impact"],
            impact_val=risk_assessment["impact_val"],
            risk_score=risk_assessment["risk_score"],
            risk_level=risk_assessment["risk_level"],
        )

        alert_count += 1

    return {
        "generated": len(raw_events),
        "stored": len(clean_events),
        "dropped": dropped,
        "alerts": alert_count,
    }


# ---- background thread management ----

_monitor_thread = None
_running = False


def start_monitor():
    # starts the monitoring loop in a daemon thread
    # daemon=True means the thread dies automatically when Flask stops
    # so there's no need to handle clean shutdown manually
    global _monitor_thread, _running

    if _running:
        print("[Monitor] Already running")
        return

    _running = True

    def loop():
        print(f"[Monitor] Starting continuous monitoring (interval: {MONITOR_INTERVAL}s)")
        while _running:
            try:
                result = run_pipeline_cycle()
                print(f"[Monitor] Cycle done: {result}")
            except Exception as ex:
                print(f"[Monitor] Cycle error: {ex}")
            time.sleep(MONITOR_INTERVAL)
        print("[Monitor] Stopped")

    _monitor_thread = threading.Thread(target=loop, daemon=True)
    _monitor_thread.start()


def stop_monitor():
    global _running
    _running = False
