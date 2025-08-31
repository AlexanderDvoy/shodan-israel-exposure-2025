# src/collect_shodan.py
"""
Collect Shodan data and save as CSV under reports/shodan_raw_data.csv
Run:
    python -m src.collect_shodan --country IL --limit 200 --query "port:3389"
"""

import os
import argparse
from pathlib import Path

import pandas as pd

try:
    import shodan
    from shodan.exception import APIError
except Exception as e:
    raise RuntimeError("❌ ספריית shodan לא מותקנת. הרץ: pip install shodan") from e

# --- Project paths (stable regardless of where you run from) ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_OUTPUT = REPORTS_DIR / "shodan_raw_data.csv"

def collect(country: str, query_extra: str, limit: int) -> pd.DataFrame:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise ValueError("❌ חסר משתנה סביבה SHODAN_API_KEY. ב-PowerShell:  $env:SHODAN_API_KEY=\"...\"")

    api = shodan.Shodan(api_key)

    # Build query
    query = f"country:{country}"
    query = f"{query} {query_extra}".strip()
    print(f"[+] Query: {query} | limit={limit}")

    try:
        results = api.search(query, limit=limit)
    except APIError as e:
        raise RuntimeError(f"❌ Shodan API error: {e}") from e

    matches = results.get("matches", [])
    print(f"[+] Matches fetched: {len(matches)}")

    rows = []
    for m in matches:
        rows.append({
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "transport": m.get("transport"),
            "country": (m.get("location") or {}).get("country_code"),
            "org": m.get("org"),
            "asn": m.get("asn"),
            "product": m.get("product"),
            "timestamp": m.get("timestamp"),
        })

    df = pd.DataFrame(rows)
    return df

def main():
    parser = argparse.ArgumentParser(description="Collect Shodan results and save CSV")
    parser.add_argument("--country", "-c", default="IL", help="Country code (default: IL)")
    parser.ad
