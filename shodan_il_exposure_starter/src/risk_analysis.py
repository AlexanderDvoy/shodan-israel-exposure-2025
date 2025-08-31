# src/risk_analysis.py
import argparse
from pathlib import Path
import pandas as pd
from src.risk_mapping import risk_mapping

# מצביע על שורש הפרויקט (תיקייה אחת מעל src/)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"

def autodetect_input():
    csvs = sorted(REPORTS_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return csvs[0] if csvs else None

def run(input_path: Path, output_path: Path):
    print(f"[i] Using input:  {input_path.resolve()}")
    print(f"[i] Writing to:  {output_path.resolve()}")

    if not input_path.exists():
        raise FileNotFoundError(f"❌ לא נמצא קובץ קלט: {input_path}")
    df = pd.read_csv(input_path)
    if "port" not in df.columns:
        raise ValueError("❌ חסרה עמודת 'port' בנתונים")

    df["protocol"] = df["port"].map(lambda p: risk_mapping.get(p, {}).get("protocol", "Unknown"))
    df["risk"]     = df["port"].map(lambda p: risk_mapping.get(p, {}).get("risk", "Unknown"))
    df["cves"]     = df["port"].map(lambda p: ",".join(risk_mapping.get(p, {}).get("cves", [])))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"✅ ניתוח סיכונים הושלם! נשמר: {output_path.resolve()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Risk analysis for Shodan CSV")
    parser.add_argument("-i", "--input", type=Path, default=None, help="נתיב לקובץ CSV גולמי")
    parser.add_argument("-o", "--output", type=Path, default=REPORTS_DIR / "risk_data.csv",
                        help="נתיב פלט (ברירת מחדל: reports/risk_data.csv)")
    args = parser.parse_args()

    inp = args.input or autodetect_input()
    if inp is None:
        raise FileNotFoundError("❌ לא נמצא אף CSV בתיקיית reports/. צור אחד עם collect_shodan.py או ציין --input.")
    # אם המשתמש נתן נתיב יחסי – נפתור ביחס לשורש הפרויקט
    if not inp.is_absolute():
        inp = (PROJECT_ROOT / inp).resolve()
    out = args.output
    if not out.is_absolute():
        out = (PROJECT_ROOT / out).resolve()

    run(inp, out)

