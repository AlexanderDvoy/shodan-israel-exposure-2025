# src/risk_analysis.py
import argparse, json
from pathlib import Path
import pandas as pd
from src.risk_mapping import risk_mapping

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_CSV = REPORTS_DIR / "shodan_raw_data.csv"
DEFAULT_JSON = PROJECT_ROOT / "data" / "raw" / "shodan_data.json"

def load_input(input_path: Path) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"❌ לא נמצא קובץ קלט: {input_path}")

    if input_path.suffix.lower() == ".csv":
        df = pd.read_csv(input_path)
    elif input_path.suffix.lower() == ".json":
        with input_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        matches = data.get("matches", data)
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
    else:
        raise ValueError("תמיכת קלט: .csv או .json בלבד")
    return df

def run(input_path: Path, output_path: Path):
    print(f"[i] Using input:  {input_path.resolve()}")
    print(f"[i] Writing to:  {output_path.resolve()}")

    df = load_input(input_path)
    if "port" not in df.columns:
        raise ValueError("❌ חסרה עמודת 'port' בנתונים")

    df["protocol"] = df["port"].map(lambda p: risk_mapping.get(p, {}).get("protocol", "Unknown"))
    df["risk"]     = df["port"].map(lambda p: risk_mapping.get(p, {}).get("risk", "Unknown"))
    df["cves"]     = df["port"].map(lambda p: ",".join(risk_mapping.get(p, {}).get("cves", [])))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"✅ ניתוח סיכונים הושלם! נשמר: {output_path.resolve()}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Risk analysis for Shodan CSV/JSON")
    p.add_argument("-i", "--input", type=Path, default=None,
                   help="קלט: CSV או JSON (ברירת מחדל: reports/shodan_raw_data.csv או data/raw/shodan_data.json)")
    p.add_argument("-o", "--output", type=Path, default=REPORTS_DIR / "risk_data.csv",
                   help="פלט CSV (ברירת מחדל: reports/risk_data.csv)")
    args = p.parse_args()

    inp = args.input
    if inp is None:
        # אם אין CSV – ננסה את JSON
        inp = DEFAULT_CSV if DEFAULT_CSV.exists() else DEFAULT_JSON
    if not inp.is_absolute():
        inp = (PROJECT_ROOT / inp).resolve()
    out = args.output if args.output.is_absolute() else (PROJECT_ROOT / args.output).resolve()
    run(inp, out)

