# scrape_safe_apps.py

import json
import asyncio
import aiohttp
from google_play_scraper import app, search
from typing import List, Dict

# ---------------- Configuration ----------------
SEARCH_QUERIES = [
    "banking app",
    "finance app",
    "digital wallet",
    "UPI app",
    "payments app"
]

OUTPUT_FILE = "safeapps/safe_apps.json"
MAX_APPS_PER_QUERY = 50  # limit per search query to avoid overload
REQUEST_DELAY = 1        # delay between queries in seconds

# ---------------- Helper Functions ----------------
async def fetch_query(session: aiohttp.ClientSession, query: str) -> List[Dict]:
    """Fetch apps for a single search query."""
    results = []
    try:
        loop = asyncio.get_event_loop()
        search_results = await loop.run_in_executor(None, lambda: search(query, lang="en", country="IN"))
        for app_info in search_results[:MAX_APPS_PER_QUERY]:
            results.append({
                "package_name": app_info["appId"],
                "app_name": app_info["title"],
                "category": "Finance"
            })
    except Exception as e:
        print(f"[!] Error fetching query '{query}': {e}")
    await asyncio.sleep(REQUEST_DELAY)
    return results

async def fetch_all_safe_apps() -> List[Dict]:
    """Fetch safe apps for all search queries asynchronously."""
    safe_apps = []
    seen_packages = set()
    async with aiohttp.ClientSession() as session:
        for query in SEARCH_QUERIES:
            query_apps = await fetch_query(session, query)
            for app_data in query_apps:
                if app_data["package_name"] not in seen_packages:
                    safe_apps.append(app_data)
                    seen_packages.add(app_data["package_name"])
    return safe_apps

def save_to_json(safe_apps: List[Dict]):
    """Save the list of safe apps to a JSON file."""
    with open(OUTPUT_FILE, "w") as f:
        json.dump(safe_apps, f, indent=4)
    print(f"[+] Safe apps JSON updated with {len(safe_apps)} apps.")

# ---------------- Main Execution ----------------
if __name__ == "__main__":
    apps = asyncio.run(fetch_all_safe_apps())
    save_to_json(apps)
