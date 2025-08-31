# src/risk_analysis.py
"""
Risk Analysis for Shodan Data
-----------------------------
  Adding risk columns  (Risk Level) CVE data Shodan.
"""

import pandas as pd
from pathlib import Path
from src.risk_mapping import risk_mapping

INPUT_FILE = Path("reports/israel_shodan_2025.csv")   
OUTPUT_FILE = Path("reports/risk_data.csv")

def run_risk_analysis():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"❌ לא נמצא קובץ קלט: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE)

    if "port" not in df.columns:
        raise ValueError("❌ There is no columns   'port' ")

    df["protocol"] = df["port"].map(lambda p: risk_mapping.get(p, {}).get("protocol", "Unknown"))
    df["risk"] = df["port"].map(lambda p: risk_mapping.get(p, {}).get("risk", "Unknown"))
    df["cves"] = df["port"].map(lambda p: ",".join(risk_mapping.get(p, {}).get("cves", [])))

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8")

    print(f"✅ Operation finished  !   Saved at: {OUTPUT_FILE}")

if __name__ == "__main__":
    run_risk_analysis()

