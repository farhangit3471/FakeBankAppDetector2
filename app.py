# app.py

import os
import json
import logging
from flask import Flask, request, render_template, jsonify, session
from analyzer.apk_analyzer import analyze_apk, load_safe_apps
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

UPLOAD_DIR = "uploads"
MALICIOUS_APPS_DIR = "maliciousapps"
HISTORY_DIR = "scan_history"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(MALICIOUS_APPS_DIR, exist_ok=True)
os.makedirs(HISTORY_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Needed for session management

# Load safe apps at startup
SAFE_APPS = load_safe_apps()
logger.info(f"Loaded {len(SAFE_APPS)} safe apps at startup")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/debug/safe-apps")
def debug_safe_apps():
    """Debug endpoint to check safe apps loading"""
    return jsonify({
        "safe_apps_count": len(SAFE_APPS),
        "safe_apps_list": list(SAFE_APPS)
    })

def save_scan_result(result, filename):
    """Save scan results to history"""
    try:
        history_path = os.path.join(HISTORY_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}.json")
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error saving scan history: {e}")

@app.route("/scan", methods=["POST"])
def scan():
    try:
        if "apk" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["apk"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        # Validate file extension
        if not file.filename.lower().endswith('.apk'):
            return jsonify({"error": "Please upload an APK file"}), 400

        filepath = os.path.join(UPLOAD_DIR, file.filename)
        file.save(filepath)

        # Analyze APK
        logger.info(f"Analyzing APK: {file.filename}")
        result = analyze_apk(filepath)
        
        # Save to history
        save_scan_result(result, file.filename)
        
        # Store in session for potential false positive reporting
        session['last_scan_result'] = result

        # Clean up uploaded file
        try:
            os.remove(filepath)
        except:
            pass

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error during scan: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/report-false-positive", methods=["POST"])
def report_false_positive():
    """Endpoint to report false positives"""
    try:
        data = request.get_json()
        if not data or 'package_name' not in data:
            return jsonify({"error": "Package name required"}), 400
        
        # Get the last scan result from session
        last_result = session.get('last_scan_result')
        if not last_result or last_result.get('package') != data['package_name']:
            return jsonify({"error": "No matching scan result found"}), 400
        
        # Mark as false positive in history
        last_result['false_positive_reported'] = True
        last_result['false_positive_reason'] = data.get('reason', 'No reason provided')
        last_result['false_positive_timestamp'] = datetime.now().isoformat()
        
        # Save updated result
        save_scan_result(last_result, f"false_positive_{data['package_name']}")
        
        return jsonify({"message": "False positive reported successfully"})
    
    except Exception as e:
        logger.error(f"Error reporting false positive: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/scan-history")
def get_scan_history():
    """Endpoint to retrieve scan history"""
    try:
        history_files = []
        for f in os.listdir(HISTORY_DIR):
            if f.endswith('.json'):
                history_files.append(f)
        
        # Return most recent first
        history_files.sort(reverse=True)
        return jsonify({"history_files": history_files[:10]})  # Last 10 scans
    except Exception as e:
        logger.error(f"Error retrieving scan history: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render's dynamic port or fallback to 5000
    app.run(debug=True, host='0.0.0.0', port=port)

