# src/risk_analysis.py
import argparse, json, csv
from pathlib import Path
from src.risk_mapping import risk_mapping

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR  = PROJECT_ROOT / "reports"
DEFAULT_CSV  = REPORTS_DIR / "shodan_raw_data.csv"
DEFAULT_JSON = PROJECT_ROOT / "data" / "raw" / "shodan_data.json"

def load_json(path: Path) -> list[dict]:
    txt = path.read_text(encoding="utf-8").lstrip()
    try:
        data = json.loads(txt)
    except Exception:
        # NDJSON (שורה לכל JSON)
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("matches") or data.get("data") or []
    raise ValueError("מבנה JSON לא נתמך")

def load_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        return list(r)

def run(input_path: Path, output_path: Path):
    print(f"[i] Using input:  {input_path.resolve()}")
    print(f"[i] Writing to:  {output_path.resolve()}")

    if not input_path.exists():
        raise FileNotFoundError(f"❌ לא נמצא קובץ קלט: {input_path}")

    if input_path.suffix.lower() == ".json":
        rows_in = []
        for m in load_json(input_path):
            if not isinstance(m, dict): 
                continue
            loc = m.get("location") or {}
            rows_in.append({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "transport": m.get("transport"),
                "country": loc.get("country_code"),
                "org": m.get("org"),
                "asn": m.get("asn"),
                "product": m.get("product"),
                "timestamp": m.get("timestamp"),
            })
    elif input_path.suffix.lower() == ".csv":
        rows_in = load_csv(input_path)
    else:
        raise ValueError("תמיכת קלט: .csv או .json בלבד")

    # העשרה בסיכון/CVE
    out_fields = ["ip","port","transport","country","org","asn","product","timestamp","protocol","risk","cves"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        w.writeheader()
        wrote = 0
        for row in rows_in:
            try:
                port = int(row.get("port")) if row.get("port") not in (None,"") else None
            except Exception:
                port = None
            rm = risk_mapping.get(port, {})
            row_out = {
                **row,
                "protocol": rm.get("protocol","Unknown"),
                "risk":     rm.get("risk","Unknown"),
                "cves":     ",".join(rm.get("cves", [])),
            }
            w.writerow(row_out); wrote += 1

    print(f"✅ ניתוח סיכונים הושלם! נשמר: {output_path.resolve()} (שורות: {wrote})")

if __name__ == "__main__":
    import sys
    import argparse
    p = argparse.ArgumentParser(description="Risk analysis (no pandas)")
    p.add_argument("-i","--input",  type=Path, default=(DEFAULT_CSV if DEFAULT_CSV.exists() else DEFAULT_JSON))
    p.add_argument("-o","--output", type=Path, default=REPORTS_DIR / "risk_data.csv")
    args = p.parse_args()
    inp = args.input if args.input.is_absolute() else (PROJECT_ROOT / args.input)
    out = args.output if args.output.is_absolute() else (PROJECT_ROOT / args.output)
    run(inp, out)
