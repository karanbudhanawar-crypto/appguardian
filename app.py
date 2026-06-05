"""
╔══════════════════════════════════════════════════════════╗
║         APP GUARDIAN - Python Backend Server             ║
║         Run: python app.py                               ║
║         API: http://localhost:5000                       ║
╚══════════════════════════════════════════════════════════╝

Requirements:
    pip install flask flask-cors google-play-scraper
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from scraper import search_apps, get_app_details
from analyzer import analyze_app

app = Flask(__name__)
CORS(app)  # Allow frontend to call this API from any origin


# ─────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    import os
    frontend = os.path.join(os.path.dirname(__file__), "../frontend/index.html")
    if os.path.exists(frontend):
        from flask import send_file
        return send_file(frontend)
    return jsonify({"name": "AppGuardian API", "version": "1.0.0", "status": "running"})


@app.route("/search")
def search():
    """
    Search Google Play Store for apps.
    Query param: q (app name, developer, or package id)
    Returns: list of matching apps
    """
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify({"error": "Query must be at least 2 characters"}), 400

    try:
        results = search_apps(q)
        return jsonify({"query": q, "results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e), "results": []}), 500


@app.route("/scan/<app_id>")
def scan(app_id):
    """
    Full 360° scan of an app by its package ID.
    Example: /scan/com.whatsapp
    Returns: app details + safety analysis
    """
    if not app_id or len(app_id) < 3:
        return jsonify({"error": "Invalid app ID"}), 400

    try:
        # Step 1: Fetch app data from Google Play
        app_data = get_app_details(app_id)

        # Step 2: Run safety analysis
        analysis = analyze_app(app_data)

        return jsonify({
            "app":      app_data,
            "analysis": analysis
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sample-scans")
def sample_scans():
    """Return pre-defined sample apps shown on the homepage."""
    samples = [
        {
            "appId":     "com.google.android.calculator",
            "title":     "Calculator",
            "developer": "Google LLC",
            "letter":    "=",
            "color":     "#1565c0"
        },
        {
            "appId":     "com.whatsapp",
            "title":     "WhatsApp Messenger",
            "developer": "WhatsApp LLC",
            "letter":    "W",
            "color":     "#25d366"
        },
        {
            "appId":     "com.spotify.music",
            "title":     "Spotify: Music and Podcasts",
            "developer": "Spotify AB",
            "letter":    "♪",
            "color":     "#1db954"
        },
        {
            "appId":     "com.bfs.flashcleanerpro",
            "title":     "Flash Cleaner Pro · Super Boost",
            "developer": "BrightCleanLabs",
            "letter":    "F",
            "color":     "#ff6f00"
        },
    ]
    return jsonify({"samples": samples})


# ─────────────────────────────────────────────────────────
# START SERVER
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  APP GUARDIAN Backend  |  http://localhost:5000")
    print("═" * 55)
    print("  Endpoints:")
    print("    GET /search?q=whatsapp")
    print("    GET /scan/com.whatsapp")
    print("    GET /sample-scans")
    print("═" * 55 + "\n")
    port = int(__import__("os").environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
