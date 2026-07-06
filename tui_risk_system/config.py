# config.py - all the settings in one place so they're easy to find and update

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# database file lives in the project root folder
DATABASE_PATH = os.path.join(BASE_DIR, "risk_data.db")

# Flask needs a secret key for sessions - in a real deployment this would
# be pulled from an environment variable, not hardcoded like this
SECRET_KEY = "tui-fyp-dev-key-2024"

# dashboard login - single admin account for the prototype
# a real system would have a proper user table with hashed passwords
LOGIN_USERNAME = "admin"
LOGIN_PASSWORD = "tui-risk-2024"

# how often the background monitor runs (in seconds)
# 5 seconds feels like a good balance between responsiveness and performance
MONITOR_INTERVAL = 5

# how many events to generate per monitor cycle
EVENTS_PER_CYCLE = 10

# NIST SP 800-30 likelihood scale - 1 (Very Low) to 5 (Very High)
# these numeric values are used to calculate the risk score
LIKELIHOOD_SCALE = {
    "Very Low":  1,
    "Low":       2,
    "Moderate":  3,
    "High":      4,
    "Very High": 5,
}

# same scale for impact - matches the NIST methodology
IMPACT_SCALE = {
    "Very Low":  1,
    "Low":       2,
    "Moderate":  3,
    "High":      4,
    "Very High": 5,
}

# risk level thresholds for the 1-25 score range
# taken from the NIST SP 800-30 risk matrix in the design chapter
RISK_THRESHOLDS = {
    "Low":       (1, 5),
    "Medium":    (6, 10),
    "High":      (11, 15),
    "Very High": (16, 20),
    "Critical":  (21, 25),
}

# Z-score threshold for the anomaly detector - anything above this gets flagged
# tested a few values and 2.5 gave the fewest false positives while still
# catching real spikes
Z_SCORE_THRESHOLD = 2.5

# brute force rule settings
BRUTE_FORCE_THRESHOLD = 5       # number of failed logins that triggers it
BRUTE_FORCE_WINDOW_SECONDS = 60  # time window to check within

# port scan detection threshold - distinct ports from one IP
PORT_SCAN_THRESHOLD = 15

# how many historical event counts to keep in the rolling baseline window
BASELINE_WINDOW_SIZE = 100

# TUI asset categories - based on the kinds of systems a travel company
# like TUI would actually have running
ASSET_TYPES = [
    "Booking Platform",
    "Flight Operations System",
    "Customer Database",
    "Payment Gateway",
    "Crew Management System",
    "Hotel Reservation System",
    "Corporate Network",
    "Cloud Infrastructure",
]

# the different log sources the system monitors
EVENT_SOURCES = [
    "auth_log",
    "network_log",
    "application_log",
    "firewall_log",
    "system_log",
]
