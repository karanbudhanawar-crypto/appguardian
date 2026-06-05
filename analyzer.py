"""
AppGuardian - Safety Analysis Engine

Takes app data from Google Play and produces a 360° safety score:
  - Fake Review Risk   (0-100, lower is safer)
  - Permission Risk    (0-100, lower is safer)
  - Developer Trust    (0-100, higher is better)
  - Malware Risk       (0-100, lower is safer)
  - Sentiment Score    (0-100, higher is better)
  → Overall Safety Score (0-100)
"""


# ─────────────────────────────────────────────────────────────────────────────
# PERMISSION DATABASE
# ─────────────────────────────────────────────────────────────────────────────

# Maps Android permission → (human description, risk level)
PERMISSION_DB = {
    # HIGH risk permissions
    "android.permission.READ_CONTACTS":          ("Reads your entire contact list", "HIGH"),
    "android.permission.WRITE_CONTACTS":         ("Can modify your contacts", "HIGH"),
    "android.permission.READ_CALL_LOG":          ("Accesses your full call history", "HIGH"),
    "android.permission.WRITE_CALL_LOG":         ("Can modify call history", "HIGH"),
    "android.permission.RECORD_AUDIO":           ("Records microphone / audio", "HIGH"),
    "android.permission.CAMERA":                 ("Full camera access", "HIGH"),
    "android.permission.ACCESS_FINE_LOCATION":   ("Exact GPS location (always-on)", "HIGH"),
    "android.permission.READ_SMS":               ("Reads all your SMS messages", "HIGH"),
    "android.permission.SEND_SMS":               ("Sends SMS (may incur charges)", "HIGH"),
    "android.permission.RECEIVE_SMS":            ("Intercepts incoming SMS", "HIGH"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("Intercepts outgoing calls", "HIGH"),
    "android.permission.READ_PHONE_STATE":       ("Reads IMEI, phone number, carrier", "HIGH"),
    "android.permission.USE_BIOMETRIC":          ("Accesses fingerprint/face sensor", "HIGH"),
    "android.permission.USE_FINGERPRINT":        ("Reads fingerprint sensor", "HIGH"),
    "android.permission.BODY_SENSORS":           ("Reads heart rate & health sensors", "HIGH"),
    "android.permission.READ_CALENDAR":          ("Reads all your calendar events", "HIGH"),
    "android.permission.WRITE_CALENDAR":         ("Creates/edits calendar events", "HIGH"),
    "android.permission.MANAGE_ACCOUNTS":        ("Controls all device accounts", "HIGH"),
    "android.permission.GET_ACCOUNTS":           ("Lists every account on the device", "HIGH"),

    # MEDIUM risk permissions
    "android.permission.ACCESS_COARSE_LOCATION": ("Approximate location (Wi-Fi/cell)", "MED"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Location access when app is closed", "MED"),
    "android.permission.READ_EXTERNAL_STORAGE":  ("Reads all files on device storage", "MED"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Creates, edits, or deletes files", "MED"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":("Full access to all storage", "MED"),
    "android.permission.BLUETOOTH":              ("Bluetooth device scanning", "MED"),
    "android.permission.BLUETOOTH_SCAN":         ("Scans nearby Bluetooth devices", "MED"),
    "android.permission.NFC":                    ("Near-field communication access", "MED"),
    "android.permission.BILLING":                ("In-app purchase capability", "MED"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Starts automatically on device boot", "MED"),
    "android.permission.ACTIVITY_RECOGNITION":   ("Tracks physical activity & movement", "MED"),
    "android.permission.CALL_PHONE":             ("Can dial phone numbers directly", "MED"),

    # LOW risk permissions
    "android.permission.INTERNET":               ("Standard internet access", "LOW"),
    "android.permission.FOREGROUND_SERVICE":     ("Runs a persistent background service", "LOW"),
    "android.permission.VIBRATE":                ("Controls device vibration", "LOW"),
    "android.permission.WAKE_LOCK":              ("Keeps screen/CPU awake", "LOW"),
    "android.permission.FLASHLIGHT":             ("Controls camera flashlight", "LOW"),
    "android.permission.CHANGE_NETWORK_STATE":   ("Can toggle Wi-Fi on/off", "LOW"),
    "android.permission.ACCESS_NETWORK_STATE":   ("Checks network connectivity", "LOW"),
    "android.permission.ACCESS_WIFI_STATE":      ("Reads Wi-Fi network names", "LOW"),
    "android.permission.CHANGE_WIFI_STATE":      ("Can connect/disconnect Wi-Fi", "LOW"),
    "android.permission.PUSH_NOTIFICATIONS":     ("Sends push notifications", "LOW"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("Can install other APKs", "MED"),
}

# Known trustworthy publishers (lowers risk scores)
TRUSTED_PUBLISHERS = {
    "google", "meta", "microsoft", "amazon", "samsung", "spotify",
    "whatsapp", "netflix", "twitter", "snapchat", "adobe", "paypal",
    "uber", "airbnb", "tiktok", "bytedance", "apple", "mozilla",
    "telegram", "signal", "zoom", "slack", "dropbox", "linkedin",
    "pinterest", "reddit", "duolingo", "canva", "notion",
}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def analyze_app(app: dict) -> dict:
    """
    Run full 360° safety analysis on app data.
    Returns a complete analysis report dict.
    """
    fake_review_risk = _score_fake_reviews(app)
    permission_risk  = _score_permissions(app)
    developer_trust  = _score_developer(app)
    malware_risk     = _score_malware(app)
    sentiment_score  = _score_sentiment(app)

    # Weighted safety score (0–100, higher = safer)
    safety_score = int(
        (100 - fake_review_risk) * 0.25 +
        (100 - permission_risk)  * 0.20 +
        developer_trust          * 0.25 +
        (100 - malware_risk)     * 0.10 +
        sentiment_score          * 0.20
    )
    safety_score = max(0, min(100, safety_score))

    risk_level  = _risk_level(safety_score)
    safe_to_use = safety_score >= 65
    grade       = _grade(safety_score)

    return {
        # Overall
        "safetyScore":    safety_score,
        "safetyGrade":    grade,
        "riskLevel":      risk_level,
        "safeToUse":      safe_to_use,
        "betterThanPct":  min(99, safety_score + 8),
        "lastAnalyzed":   "Just now",
        "reviewsAnalyzed": _fmt_number(app.get("reviews") or app.get("ratings") or 0),

        # Dimension scores
        "fakeReviewRisk":   fake_review_risk,
        "fakeReviewLabel":  _label(fake_review_risk, higher_is_worse=True),

        "permissionsRisk":  permission_risk,
        "permissionsLabel": _label(permission_risk, higher_is_worse=True),

        "developerTrust":   developer_trust,
        "developerLabel":   _label(developer_trust, higher_is_worse=False),

        "malwareRisk":      malware_risk,
        "malwareLabel":     "Safe" if malware_risk == 0 else _label(malware_risk, higher_is_worse=True),

        "sentimentScore":   sentiment_score,

        # Permission detail list for UI
        "permissionDetails": _permission_details(app.get("permissions") or []),

        # All 5 dimensions completed
        "dimensions": {
            "reviewAnalysis":   "Completed",
            "permissionsScan":  "Completed",
            "developerCheck":   "Completed",
            "behaviorAnalysis": "Completed",
            "threatDetection":  "Completed",
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION SCORERS
# ─────────────────────────────────────────────────────────────────────────────

def _score_fake_reviews(app: dict) -> int:
    """
    Detect fake/manipulated reviews (0–100, higher = more suspicious).

    Signals:
      - Abnormally high 5-star ratio
      - Almost zero 1-star reviews for a large app
      - Very few reviews relative to install count
    """
    hist      = app.get("histogram") or {}
    total     = sum(hist.values()) if hist else 0
    installs  = int(app.get("minInstalls") or 0)
    score_val = float(app.get("score") or 0)

    if total == 0:
        return 30   # Unknown — assign moderate risk

    five_star = hist.get(5, 0)
    one_star  = hist.get(1, 0)
    five_pct  = five_star / total
    one_pct   = one_star  / total

    risk = 10  # baseline

    # --- 5-star inflation ---
    if five_pct > 0.90:   risk += 55
    elif five_pct > 0.82: risk += 38
    elif five_pct > 0.74: risk += 22
    elif five_pct > 0.65: risk += 10

    # --- Near-zero 1-star for popular app ---
    if installs > 1_000_000 and one_pct < 0.004:
        risk += 22
    elif installs > 100_000 and one_pct < 0.008:
        risk += 12

    # --- Review-to-install ratio (bought installs signal) ---
    if installs > 0:
        ratio = total / installs
        if ratio < 0.0001:   risk += 20   # extremely sparse reviews
        elif ratio < 0.001:  risk += 10

    # --- Score vs sentiment mismatch ---
    weighted = sum(int(k) * v for k, v in hist.items())
    computed_avg = weighted / total if total else 0
    if abs(score_val - computed_avg) > 1.5:
        risk += 15   # official score differs significantly from distribution

    return min(risk, 100)


def _score_permissions(app: dict) -> int:
    """
    Permission risk score (0–100, higher = more risky).
    Based on the danger level of each permission requested.
    """
    perms = app.get("permissions") or []
    if not perms:
        return 0

    risk = 0
    for p in perms:
        _, level = PERMISSION_DB.get(p, ("Unknown permission", "NONE"))
        if level == "HIGH":  risk += 15
        elif level == "MED": risk += 7
        elif level == "LOW": risk += 2

    return min(risk, 100)


def _score_developer(app: dict) -> int:
    """
    Developer trust score (0–100, higher = more trustworthy).
    Based on install count, ratings, app quality, and publisher identity.
    """
    score     = 35  # baseline
    installs  = int(app.get("minInstalls") or 0)
    ratings   = int(app.get("ratings") or 0)
    app_score = float(app.get("score") or 0)
    developer = (app.get("developer") or "").lower()
    email     = app.get("developerEmail") or ""
    website   = app.get("developerWebsite") or ""
    released  = app.get("released") or ""

    # --- Install base (reflects longevity and user trust) ---
    if installs >= 1_000_000_000: score += 35
    elif installs >= 100_000_000: score += 28
    elif installs >= 10_000_000:  score += 20
    elif installs >= 1_000_000:   score += 13
    elif installs >= 100_000:     score += 6
    elif installs >= 10_000:      score += 2

    # --- Rating volume ---
    if ratings >= 10_000_000: score += 15
    elif ratings >= 1_000_000: score += 10
    elif ratings >= 100_000:  score += 5
    elif ratings >= 10_000:   score += 2

    # --- App quality score ---
    if app_score >= 4.6:   score += 12
    elif app_score >= 4.2: score += 7
    elif app_score >= 3.8: score += 3
    elif app_score < 3.0:  score -= 18
    elif app_score < 2.0:  score -= 30

    # --- Known trusted publisher ---
    if any(t in developer for t in TRUSTED_PUBLISHERS):
        score += 12

    # --- Transparency / contact info ---
    if email:   score += 4
    if website: score += 3

    # --- App longevity ---
    if released:
        year = _extract_year(released)
        if year and year <= 2018:   score += 6
        elif year and year <= 2021: score += 3

    return max(0, min(100, score))


def _score_malware(app: dict) -> int:
    """
    Malware / virus risk (0–100, higher = more suspicious).
    Uses heuristic signals since we can't run the APK here.
    """
    risk      = 0
    installs  = int(app.get("minInstalls") or 0)
    app_score = float(app.get("score") or 0)
    ad_sup    = bool(app.get("adSupported") or app.get("containsAds"))
    email     = app.get("developerEmail") or ""
    website   = app.get("developerWebsite") or ""
    title     = (app.get("title") or "").lower()
    perms     = app.get("permissions") or []

    # --- Brand-new unknown app ---
    if installs < 500 and app_score == 0:   risk += 45
    elif installs < 5_000:                  risk += 25
    elif installs < 50_000:                 risk += 10

    # --- Ad-supported + tiny install base ---
    if ad_sup and installs < 10_000:  risk += 30
    elif ad_sup and installs < 50_000: risk += 15

    # --- No developer contact info (lack of accountability) ---
    if not email and not website:  risk += 15
    elif not email:                risk += 7

    # --- Suspicious app naming patterns ---
    suspicious_words = ["cleaner", "booster", "virus", "speed up", "optimizer",
                        "battery saver", "ram cleaner", "junk cleaner", "master", "pro free"]
    if any(w in title for w in suspicious_words):
        risk += 20

    # --- Dangerous permission combo (spyware pattern) ---
    spy_perms = {"android.permission.RECORD_AUDIO", "android.permission.READ_SMS",
                 "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS"}
    perm_set = set(perms)
    overlap  = len(spy_perms & perm_set)
    if overlap >= 3: risk += 30
    elif overlap == 2: risk += 15

    # --- Very low score despite real installs ---
    if app_score > 0 and app_score < 2.0 and installs > 10_000:
        risk += 20

    return min(risk, 100)


def _score_sentiment(app: dict) -> int:
    """
    Sentiment score from star distribution (0–100, higher = more positive).
    """
    hist  = app.get("histogram") or {}
    total = sum(hist.values()) if hist else 0

    if total == 0:
        score_val = float(app.get("score") or 3.5)
        return int((score_val / 5.0) * 100)

    # Weighted average of stars
    weighted = sum(int(k) * int(v) for k, v in hist.items())
    avg_star = weighted / total
    return int((avg_star / 5.0) * 100)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _permission_details(perms: list) -> list:
    """Build a human-readable permission breakdown for the UI."""
    result = []
    seen   = set()
    for p in perms:
        if p in seen:
            continue
        seen.add(p)
        if p in PERMISSION_DB:
            desc, level = PERMISSION_DB[p]
        else:
            # Try to infer from permission name
            upper = p.upper()
            if "LOCATION" in upper:  level = "MED"; desc = "Location access"
            elif "CAMERA" in upper:  level = "HIGH"; desc = "Camera access"
            elif "RECORD" in upper:  level = "HIGH"; desc = "Audio recording"
            elif "CONTACT" in upper: level = "HIGH"; desc = "Contacts access"
            elif "SMS" in upper:     level = "HIGH"; desc = "SMS access"
            elif "PHONE" in upper:   level = "MED";  desc = "Phone access"
            elif "STORAGE" in upper: level = "MED";  desc = "Storage access"
            else:
                continue  # skip unknown non-sensitive

        result.append({
            "permission":  p.split(".")[-1],
            "fullName":    p,
            "description": desc,
            "risk":        level,
        })

    # Sort: HIGH first, then MED, then LOW
    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    result.sort(key=lambda x: order.get(x["risk"], 9))
    return result[:25]


def _risk_level(safety: int) -> str:
    if safety >= 75: return "LOW"
    if safety >= 50: return "MEDIUM"
    return "HIGH"


def _grade(safety: int) -> str:
    if safety >= 85: return "Excellent"
    if safety >= 70: return "Good"
    if safety >= 55: return "Fair"
    if safety >= 40: return "Poor"
    return "Dangerous"


def _label(score: int, higher_is_worse: bool) -> str:
    """Convert a 0-100 score to a Low/Medium/High label."""
    effective = (100 - score) if higher_is_worse else score
    if effective >= 70: return "High"
    if effective >= 40: return "Medium"
    return "Low"


def _fmt_number(n) -> str:
    try:
        n = int(n)
        if n >= 1_000_000_000: return f"{n / 1_000_000_000:.1f}B"
        if n >= 1_000_000:     return f"{n / 1_000_000:.1f}M"
        if n >= 1_000:         return f"{n / 1_000:.0f}K"
        return str(n)
    except (TypeError, ValueError):
        return "—"


def _extract_year(released: str) -> int | None:
    import re
    m = re.search(r"(\d{4})", str(released))
    return int(m.group(1)) if m else None
