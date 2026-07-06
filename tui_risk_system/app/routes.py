# routes.py - all the Flask URL routes for the dashboard
#
# all endpoints in one place using a Blueprint
# the page routes render the HTML templates and the /api routes return JSON
# for the Chart.js charts and live table updates

import json
from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, jsonify, request, abort, session, redirect, url_for, flash

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import database as db
from app.anomaly_detector import get_baseline
from app.risk_scorer import risk_level_to_colour
from config import LOGIN_USERNAME, LOGIN_PASSWORD

# using a Blueprint so the routes are separate from the app factory
dashboard = Blueprint("dashboard", __name__)


def login_required(f):
    # decorator that redirects unauthenticated users to the login page
    # wrapping all the page routes with this so the dashboard is protected
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("dashboard.login"))
        return f(*args, **kwargs)
    return decorated


# ---- authentication ----

@dashboard.route("/login", methods=["GET", "POST"])
def login():
    # if already logged in just go straight to the dashboard
    if session.get("logged_in"):
        return redirect(url_for("dashboard.index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == LOGIN_USERNAME and password == LOGIN_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard.index"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@dashboard.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("dashboard.login"))


# ---- main pages ----

@dashboard.route("/")
@login_required
def index():
    summary = db.get_dashboard_summary()
    return render_template("index.html", summary=summary)


@dashboard.route("/alerts")
@login_required
def alerts_page():
    severity_filter = request.args.get("severity", "all")

    if severity_filter == "all":
        alerts = db.get_recent_alerts(limit=100)
    else:
        alerts = db.get_alerts_by_severity(severity_filter)

    return render_template("alerts.html", alerts=alerts, severity_filter=severity_filter)


@dashboard.route("/events")
@login_required
def events_page():
    # the analyst can filter by event type and asset to narrow down what they're looking at
    event_type_filter = request.args.get("event_type", "all")
    asset_filter = request.args.get("asset", "all")

    events = db.get_events_filtered(
        event_type=event_type_filter,
        asset=asset_filter,
        limit=200,
    )

    # fetch distinct values to populate the filter dropdowns
    event_types = db.get_distinct_event_types()
    assets = db.get_distinct_assets()

    return render_template(
        "events.html",
        events=events,
        event_types=event_types,
        assets=assets,
        event_type_filter=event_type_filter,
        asset_filter=asset_filter,
    )


@dashboard.route("/risk")
@login_required
def risk_page():
    risk_scores = db.get_recent_risk_scores(limit=100)
    distribution = db.get_risk_level_distribution()
    return render_template(
        "risk.html",
        risk_scores=risk_scores,
        distribution=distribution,
        colour_fn=risk_level_to_colour,
    )


# ---- JSON API endpoints for the charts and live updates ----

@dashboard.route("/api/summary")
def api_summary():
    summary = db.get_dashboard_summary()
    return jsonify(summary)


@dashboard.route("/api/alerts/recent")
def api_recent_alerts():
    limit = request.args.get("limit", 20, type=int)
    alerts = db.get_recent_alerts(limit=limit)
    return jsonify(alerts)


@dashboard.route("/api/alerts/over-time")
def api_alerts_over_time():
    hours = request.args.get("hours", 24, type=int)
    data = db.get_alerts_over_time(hours=hours)
    return jsonify(data)


@dashboard.route("/api/alerts/by-severity")
def api_alerts_by_severity():
    counts = db.get_alert_counts_by_severity()
    return jsonify(counts)


@dashboard.route("/api/risk/distribution")
def api_risk_distribution():
    distribution = db.get_risk_level_distribution()
    return jsonify(distribution)


@dashboard.route("/api/events/types")
def api_event_types():
    counts = db.get_events_count_last_n(n=100)
    return jsonify(counts)


@dashboard.route("/api/baseline")
def api_baseline():
    # exposes the anomaly detector's baseline so it can be shown on the dashboard
    baseline = get_baseline()
    return jsonify(baseline)


@dashboard.route("/api/alerts/acknowledge/<int:alert_id>", methods=["POST"])
def api_acknowledge_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok", "alert_id": alert_id})


@dashboard.route("/api/events/recent")
def api_recent_events():
    limit = request.args.get("limit", 20, type=int)
    events = db.get_recent_events(limit=limit)
    return jsonify(events)
