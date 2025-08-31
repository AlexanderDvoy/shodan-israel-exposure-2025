# src/collect_shodan.py
"""
Collect Shodan data and save CSV to reports/shodan_raw_data.csv (no pandas)
Run:
  python -m src.collect_shodan -c IL -l 200
  python -m src.collect_shodan -c IL -q "port:3389" -l 200
"""
import os, argparse, csv, json
from pathlib import Path

try:
    import shodan
    from shodan.exception import APIError
except Exception as e:
    raise RuntimeError("❌ 'shodan' לא מותקן. התקן: pip install shodan") from e

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR  = PROJECT_ROOT / "reports"
DATA_RAW     = PROJECT_ROOT / "data" / "raw"
DEFAULT_CSV  = REPORTS_DIR / "shodan_raw_data.csv"
DEFAULT_JSON = DATA_RAW / "shodan_data.json"

def collect(country: str, query_extra: str, limit: int):
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise ValueError("❌ חסר SHODAN_API_KEY. ב-PowerShell:  $env:SHODAN_API_KEY=\"...\"")
    api = shodan.Shodan(api_key)
    query = f"country:{country} {query_extra}".strip()
    print(f"[+] Query: {query} | limit={limit}")
    try:
        return api.search(query, limit=limit)
    except APIError as e:
        raise RuntimeError(f"❌ Shodan API error: {e}") from e

def write_csv(path: Path, matches: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["ip","port","transport","country","org","asn","product","timestamp"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for m in matches:
            loc = (m.get("location") or {})
            w.writerow({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "transport": m.get("transport"),
                "country": loc.get("country_code"),
                "org": m.get("org"),
                "asn": m.get("asn"),
                "product": m.get("product"),
                "timestamp": m.get("timestamp"),
            })

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-c","--country", default="IL")
    p.add_argument("-q","--query",   default="")
    p.add_argument("-l","--limit",   type=int, default=200)
    p.add_argument("-o","--output",  type=Path, default=DEFAULT_CSV)
    p.add_argument("--save-json", action="store_true")
    args = p.parse_args()

    out_csv = args.output if args.output.is_absolute() else (PROJECT_ROOT / args.output)
    results = collect(args.country, args.query, args.limit)
    matches = results.get("matches", [])
    print(f"[+] Matches: {len(matches)}")
    write_csv(out_csv, matches)
    print(f"✅ CSV נשמר: {out_csv.resolve()}  (שורות: {len(matches)})")

    if args.save_json:
        DATA_RAW.mkdir(parents=True, exist_ok=True)
        DEFAULT_JSON.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"✅ JSON נשמר: {DEFAULT_JSON.resolve()}")

if __name__ == "__main__":
    main()
