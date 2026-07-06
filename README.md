# automated-risk-management-system
A threat detection and risk scoring platform combining rule-based detection, Z-score anomaly analysis, and NIST SP 800-30 methodology.

# Automated Risk Management System (ARMS)

A Flask-based cybersecurity risk management platform that detects, scores, and prioritises security threats in real time. Built as a final year project, ARMS combines rule-based threat detection with statistical anomaly detection, and applies NIST SP 800-30 risk methodology to turn raw security events into actionable, prioritised alerts.

## Features
- **Hybrid detection engine** — 7 rule-based detectors covering brute force attempts, port scanning, SQL injection, privilege escalation, off-hours access, large data transfers, and unauthorised configuration changes
- **Statistical anomaly detection** — a secondary detection layer using Z-scores to flag behaviour that deviates from established baselines, catching threats that rule-based detection alone would miss
- **NIST SP 800-30 aligned risk scoring** — quantifies each detected event by Likelihood × Impact, giving security teams a consistent, standards-based way to prioritise response
- **Live monitoring dashboard** — REST API endpoints, protected by authentication, surface detected events and risk scores in real time
- **Test-driven** — over 1,200 lines of pytest unit tests covering the rule engine, anomaly detector, and risk scorer

## Tech Stack
Python, Flask, pytest

## How it works
Incoming events are passed through two parallel detection layers. The **rule engine** checks each event against 7 defined threat patterns (e.g. repeated failed logins signalling brute force, sequential port access signalling scanning). Simultaneously, the **anomaly detector** calculates a Z-score for relevant metrics against historical baselines, flagging statistically significant deviations that don't match a predefined rule but still look suspicious.

Every flagged event — whether caught by a rule or an anomaly is passed to the **risk scorer**, which applies NIST SP 800-30 methodology to calculate a risk score from the event's likelihood and potential impact. Scored events are then surfaced on the dashboard via authenticated REST endpoints, allowing an analyst to see not just *what* happened, but how urgently it needs attention.
