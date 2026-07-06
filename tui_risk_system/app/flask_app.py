# flask_app.py - creates and configures the Flask application
#
# app factory pattern so the app can be created cleanly
# and the monitor thread only starts once rather than on every test import

from flask import Flask
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SECRET_KEY
from app import database as db
from app.routes import dashboard


def create_app(start_monitor=True):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = SECRET_KEY

    # set up the database tables if they don't exist yet
    db.initialise_db()

    # seed with historical data so the dashboard isn't empty on first load
    _seed_if_empty(app)

    # register the blueprint that contains all the routes
    app.register_blueprint(dashboard)

    if start_monitor:
        from app.monitor import start_monitor as start_mon
        start_mon()

    return app


def _seed_if_empty(app):
    # checks if the events table is empty and if so generates 12 hours of
    # historical data so there's something to show on the dashboard straight away
    conn = db.get_connection()
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()

    if count == 0:
        print("[App] Seeding database with historical data...")
        from app.data_generator import generate_historical_data
        from app.processor import process_batch
        from app.rule_engine import run_all_rules
        from app.anomaly_detector import analyse_events
        from app.risk_scorer import score_alert
        from datetime import datetime

        historical = generate_historical_data(hours=12, events_per_hour=15)
        clean_events, _ = process_batch(historical)
        db.insert_events_bulk(clean_events)

        # run detection on the seeded data so we have alerts to show too
        rule_detections = run_all_rules(clean_events[:200])
        anomaly_detections = analyse_events(clean_events[:200])
        all_detections = rule_detections + anomaly_detections

        now_str = datetime.now().isoformat(timespec="seconds")
        for det in all_detections:
            risk = score_alert(det)
            alert_id = db.insert_alert(
                timestamp=det.get("timestamp", now_str),
                alert_type=det["alert_type"],
                severity=det["severity"],
                source_ip=det.get("source_ip"),
                user_id=det.get("user_id"),
                asset=det.get("asset"),
                description=det.get("description"),
                event_ids=det.get("event_ids", ""),
                risk_score=risk["risk_score"],
            )
            db.insert_risk_score(
                timestamp=now_str,
                alert_id=alert_id,
                threat_type=risk["threat_type"],
                asset=risk["asset"],
                likelihood=risk["likelihood"],
                likelihood_val=risk["likelihood_val"],
                impact=risk["impact"],
                impact_val=risk["impact_val"],
                risk_score=risk["risk_score"],
                risk_level=risk["risk_level"],
            )

        print(f"[App] Seeded {len(clean_events)} events, {len(all_detections)} alerts")
