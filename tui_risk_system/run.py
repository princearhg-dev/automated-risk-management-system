# run.py - main entry point, just run this file to start everything up
# it creates the Flask app and starts the web server on port 5000

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.flask_app import create_app

if __name__ == "__main__":
    print("=" * 60)
    print("  TUI Group Automated Security Risk Management System")
    print("  FYP Prototype - NIST SP 800-30 / ISO/IEC 27005 aligned")
    print("=" * 60)

    app = create_app(start_monitor=True)

    print("\n[App] Starting Flask server at http://127.0.0.1:5000")
    print("[App] Press Ctrl+C to stop\n")

    # debug=False because Flask's reloader would start the monitor thread
    # twice if it was True, which causes duplicate alerts in the database
    app.run(host="0.0.0.0", port=5000, debug=False)
