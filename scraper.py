"""
AppGuardian - Google Play Store Scraper
Uses: google-play-scraper  (pip install google-play-scraper)

Fetches real app data directly from Google Play Store:
  - search_apps(query)      → search results
  - get_app_details(app_id) → full app metadata
"""

# ── Import google-play-scraper ────────────────────────────────────────────────
try:
    from google_play_scraper import app as gps_app, search as gps_search
    GPS_OK = True
    print("[Scraper] ✓ google-play-scraper connected to Google Play Store")
except ImportError:
    GPS_OK = False
    print("[Scraper] ✗ google-play-scraper not installed")
    print("[Scraper]   Fix: pip install google-play-scraper")


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def search_apps(query: str) -> list:
    """
    Search Google Play Store.
    Returns list of matching apps (max 10).
    """
    if not GPS_OK:
        raise RuntimeError("google-play-scraper not installed. Run: pip install google-play-scraper")

    raw_results = gps_search(
        query,
        n_hits=10,
        lang="en",
        country="us"
    )

    return [_format_search_result(r) for r in raw_results]


def get_app_details(app_id: str) -> dict:
    """
    Fetch full app details from Google Play Store by package ID.
    Example package IDs: com.whatsapp, com.spotify.music
    """
    if not GPS_OK:
        raise RuntimeError("google-play-scraper not installed. Run: pip install google-play-scraper")

    raw = gps_app(
        app_id,
        lang="en",
        country="us"
    )

    return _format_app_details(raw)


# ─────────────────────────────────────────────────────────────────────────────
# FORMATTERS  — clean raw data into consistent dicts
# ─────────────────────────────────────────────────────────────────────────────

def _format_search_result(r: dict) -> dict:
    """Slim down a search result to only what the frontend needs."""
    return {
        "appId":     r.get("appId", ""),
        "title":     r.get("title", ""),
        "developer": r.get("developer", ""),
        "icon":      r.get("icon", ""),
        "score":     _safe_float(r.get("score")),
        "installs":  r.get("installs", ""),
        "free":      r.get("free", True),
        "genre":     r.get("genre", ""),
        "summary":   r.get("summary", ""),
    }


def _format_app_details(d: dict) -> dict:
    """Extract and clean all fields from a full app response."""
    return {
        # Identity
        "appId":             d.get("appId", ""),
        "title":             d.get("title", ""),
        "summary":           d.get("summary", ""),
        "description":       _truncate(d.get("description", ""), 600),

        # Developer info
        "developer":         d.get("developer", ""),
        "developerId":       d.get("developerId", ""),
        "developerEmail":    d.get("developerEmail", ""),
        "developerWebsite":  d.get("developerWebsite", ""),
        "developerAddress":  d.get("developerAddress", ""),
        "privacyPolicy":     d.get("privacyPolicy", ""),

        # Visual assets
        "icon":              d.get("icon", ""),
        "headerImage":       d.get("headerImage", ""),
        "screenshots":       (d.get("screenshots") or [])[:4],

        # Category
        "genre":             d.get("genre", ""),
        "genreId":           d.get("genreId", ""),

        # Ratings & reviews
        "score":             _safe_float(d.get("score")),
        "ratings":           d.get("ratings", 0),
        "reviews":           d.get("reviews", 0),
        "histogram":         _clean_histogram(d.get("histogram")),

        # Install stats
        "installs":          d.get("installs", ""),
        "minInstalls":       d.get("minInstalls", 0),
        "maxInstalls":       d.get("maxInstalls", 0),
        "realInstalls":      d.get("realInstalls", 0),

        # App metadata
        "version":           d.get("version", ""),
        "androidVersion":    d.get("androidVersion", ""),
        "androidVersionText":d.get("androidVersionText", ""),
        "updated":           d.get("updated", 0),
        "released":          d.get("released", ""),
        "contentRating":     d.get("contentRating", ""),
        "contentRatingDescription": d.get("contentRatingDescription", ""),

        # Pricing & ads
        "free":              d.get("free", True),
        "price":             d.get("price", 0),
        "currency":          d.get("currency", "USD"),
        "offersIAP":         d.get("offersIAP", False),
        "IAPRange":          d.get("IAPRange", ""),
        "adSupported":       d.get("adSupported", False),
        "containsAds":       d.get("containsAds", False),

        # Permissions
        "permissions":       d.get("permissions") or [],

        # Scores
        "scoreText":         d.get("scoreText", ""),
        "editorsChoice":     d.get("editorsChoice", False),

        # Store URL
        "url":               f"https://play.google.com/store/apps/details?id={d.get('appId', '')}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _safe_float(val) -> float:
    try:
        return round(float(val), 1) if val else 0.0
    except (TypeError, ValueError):
        return 0.0


def _truncate(text: str, max_len: int) -> str:
    if not text:
        return ""
    text = text.strip()
    return text[:max_len] + "…" if len(text) > max_len else text


def _clean_histogram(hist) -> dict:
    """
    Normalize histogram to {1: N, 2: N, 3: N, 4: N, 5: N}.
    google-play-scraper returns it as {1: N, 2: N, ...} already.
    """
    if not hist or not isinstance(hist, dict):
        return {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    cleaned = {}
    for k, v in hist.items():
        try:
            cleaned[int(k)] = int(v or 0)
        except (TypeError, ValueError):
            pass
    # Ensure all 5 keys present
    for i in range(1, 6):
        cleaned.setdefault(i, 0)
    return cleaned
