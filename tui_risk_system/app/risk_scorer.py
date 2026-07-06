# risk_scorer.py - NIST SP 800-30 risk scoring
#
# implements the risk assessment methodology from NIST SP 800-30 Rev 1
# the core formula is straightforward: Risk = Likelihood x Impact
# both are rated 1-5 (Very Low to Very High) giving a score from 1-25
# that score then maps to a risk level: Low, Medium, High, Very High, or Critical
#
# this approach is justified in the literature review - it's consistent, repeatable,
# and removes the subjectivity you get with manual risk assessments

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LIKELIHOOD_SCALE, IMPACT_SCALE, RISK_THRESHOLDS


# this maps each alert type to likelihood and impact ratings
# based on the NIST 800-30 threat catalogue and TUI's specific context
# the comments explain the reasoning behind each one
THREAT_RISK_MAP = {

    # brute force: High likelihood because these attacks are cheap and automated
    # High impact because compromised credentials could expose booking or crew systems
    "Brute Force Attack": {
        "likelihood": "High",
        "impact": "High",
    },

    # port scan: High likelihood (happens constantly on internet-facing systems)
    # but only Moderate impact because scanning alone doesn't cause damage
    "Port Scan": {
        "likelihood": "High",
        "impact": "Moderate",
    },

    # SQL injection: Moderate likelihood + Very High impact
    # if successful it could expose customer PII and payment data which has GDPR implications
    "SQL Injection Attempt": {
        "likelihood": "Moderate",
        "impact": "Very High",
    },

    # privilege escalation: Moderate likelihood but Very High impact
    # an insider with elevated access could do serious damage to crew or payment systems
    "Privilege Escalation Attempt": {
        "likelihood": "Moderate",
        "impact": "Very High",
    },

    # off-hours access: High likelihood (it happens regularly) + Low impact
    # not necessarily malicious - shift workers exist - hence the Low impact rating
    "Off-Hours Access": {
        "likelihood": "High",
        "impact": "Low",
    },

    # suspicious data transfer: Low-Moderate likelihood + Very High impact
    # TUI holds a huge amount of customer data so exfiltration is their biggest risk
    "Suspicious Data Transfer": {
        "likelihood": "Low",
        "impact": "Very High",
    },

    # config change: Moderate likelihood + High impact
    # misconfigured cloud resources are one of the most common causes of breaches
    "Security Configuration Change": {
        "likelihood": "Moderate",
        "impact": "High",
    },
}

# for anomaly detections there's no fixed threat type, so likelihood and impact
# are derived from the severity the anomaly detector assigned
ANOMALY_SEVERITY_MAP = {
    "Critical": ("Very High", "Very High"),
    "High":     ("High",      "High"),
    "Medium":   ("Moderate",  "Moderate"),
    "Low":      ("Low",       "Low"),
}


def _get_risk_level(score):
    # converts a 1-25 numeric score to a risk level label
    # thresholds come from NIST SP 800-30 Table I-3
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return "Unknown"


def score_alert(alert):
    # takes an alert and returns a full risk assessment dict
    # looks up the threat type in THREAT_RISK_MAP, falls back to anomaly map or defaults
    alert_type = alert.get("alert_type", "")
    severity = alert.get("severity", "Medium")

    if alert_type in THREAT_RISK_MAP:
        mapping = THREAT_RISK_MAP[alert_type]
        likelihood_label = mapping["likelihood"]
        impact_label = mapping["impact"]
    elif alert_type.startswith("Anomaly:"):
        # anomaly detections use their severity to determine the score
        likelihood_label, impact_label = ANOMALY_SEVERITY_MAP.get(
            severity, ("Moderate", "Moderate")
        )
    else:
        # unknown threat type - defaults to Moderate/Moderate as a safe middle ground
        likelihood_label = "Moderate"
        impact_label = "Moderate"

    likelihood_val = LIKELIHOOD_SCALE[likelihood_label]
    impact_val = IMPACT_SCALE[impact_label]
    risk_score = likelihood_val * impact_val
    risk_level = _get_risk_level(risk_score)

    return {
        "threat_type": alert_type,
        "asset": alert.get("asset", "Unknown"),
        "likelihood": likelihood_label,
        "likelihood_val": likelihood_val,
        "impact": impact_label,
        "impact_val": impact_val,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def score_all_alerts(alerts):
    return [score_alert(a) for a in alerts]


def get_overall_risk_level(risk_scores_list):
    # returns the highest risk level from a list of scored alerts
    # this is what gets shown in the dashboard header
    if not risk_scores_list:
        return "Low"

    max_score = max(r["risk_score"] for r in risk_scores_list)
    return _get_risk_level(max_score)


def risk_level_to_colour(level):
    # maps risk levels to Bootstrap colour names for the dashboard badges
    colour_map = {
        "Low":       "success",
        "Medium":    "warning",
        "High":      "orange",    # custom orange - handled in style.css
        "Very High": "danger",
        "Critical":  "dark",
        "Unknown":   "secondary",
    }
    return colour_map.get(level, "secondary")


def get_risk_summary_stats(risk_scores_list):
    # counts how many assessments fall into each risk level
    # used for the summary panel on the dashboard
    counts = {level: 0 for level in RISK_THRESHOLDS}
    for r in risk_scores_list:
        level = r.get("risk_level", "Unknown")
        if level in counts:
            counts[level] += 1
    return counts
