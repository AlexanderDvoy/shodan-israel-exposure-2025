import os
import time
import json
import argparse
from typing import Dict, List, Any

import pandas as pd
from dotenv import load_dotenv
import shodan


def save_facets_to_csv(facets_dict: Dict[str, List[Dict[str, Any]]], out_prefix: str):
    os.makedirs(os.path.dirname(out_prefix), exist_ok=True)
    for facet_name, items in facets_dict.items():
        rows = [{"value": it.get("value"), "count": it.get("count")} for it in items]
        pd.DataFrame(rows).to_csv(f"{out_prefix}_{facet_name}.csv", index=False)


def flatten_match(m: Dict[str, Any]) -> Dict[str, Any]:
    loc = m.get("location") or {}
    vulns = m.get("vulns") or {}
    if isinstance(vulns, dict):
        vuln_keys = list(vulns.keys())
    elif isinstance(vulns, list):
        vuln_keys = vulns
    else:
        vuln_keys = []

    return {
        "ip": m.get("ip_str"),
        "port": m.get("port"),
        "transport": m.get("transport"),
        "product": m.get("product"),
        "org": m.get("org"),
        "asn": m.get("asn"),
        "isp": m.get("isp"),
        "os": m.get("os"),
        "hostnames": ",".join(m.get("hostnames") or []),
        "tags": ",".join(m.get("tags") or []),
        "city": loc.get("city"),
        "region_code": loc.get("region_code"),
        "country_code": loc.get("country_code"),
        "timestamp": m.get("timestamp"),
        "vulns": ",".join(vuln_keys),
    }


def write_matches_csv(matches: List[Dict[str, Any]], path: str):
    if not matches:
        pd.DataFrame().to_csv(path, index=False)
        return
    df = pd.DataFrame(matches)
    df.to_csv(path, index=False)


def facets_from_count(api, query: str, facets: str):
    res = api.count(query, facets=facets)
    return res.get("facets") or {}


def search_matches(api, query: str, max_matches: int, page_delay: float = 1.2):
    matches = []
    page = 1
    while len(matches) < max_matches:
        try:
            res = api.search(query, page=page)
        except shodan.APIError:
            time.sleep(3)
            break
        page_matches = res.get("matches") or []
        if not page_matches:
            break
        for m in page_matches:
            matches.append(flatten_match(m))
            if len(matches) >= max_matches:
                break
        if len(page_matches) < 100:
            break
        page += 1
        time.sleep(page_delay)
    return matches


def main():
    load_dotenv()
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("Missing SHODAN_API_KEY. Put it in .env or environment.")
    api = shodan.Shodan(api_key)

    parser = argparse.ArgumentParser(description="Collect aggregate exposure data for Israel from Shodan.")
    parser.add_argument("--country", default="IL", help="ISO country code (default: IL)")
    parser.add_argument("--max-matches", type=int, default=1000, help="Max matches to fetch for samples")
    parser.add_argument("--outdir", default="data", help="Base output directory")
    args = parser.parse_args()

    base_query = f"country:{args.country} -tag:honeypot"
    out_processed = os.path.join(args.outdir, "processed")
    os.makedirs(out_processed, exist_ok=True)

    # 1) Global facets
    facets_spec = "port:20,org:20,asn:20,product:20"
    facets = facets_from_count(api, base_query, facets_spec)
    save_facets_to_csv(facets, os.path.join(out_processed, "global_facets"))

    # 2) ICS/SCADA snapshot
    ics_query = f"{base_query} tag:ics"
    ics_facets = facets_from_count(api, ics_query, "product:20,org:20,asn:20,port:20")
    save_facets_to_csv(ics_facets, os.path.join(out_processed, "ics_facets"))
    ics_matches = search_matches(api, ics_query, args.max_matches // 5)
    write_matches_csv(ics_matches, os.path.join(out_processed, "ics_sample_matches.csv"))

    # 3) Vulnerable services snapshot
    vuln_query = f"{base_query} has_vuln:true"
    vuln_facets = facets_from_count(api, vuln_query, "vuln:20,product:20,org:20,asn:20,port:20")
    save_facets_to_csv(vuln_facets, os.path.join(out_processed, "vuln_facets"))
    vuln_matches = search_matches(api, vuln_query, args.max_matches // 2)
    write_matches_csv(vuln_matches, os.path.join(out_processed, "vuln_sample_matches.csv"))

    # 4) Selected ports summary
    interesting_ports = [3389, 21, 445, 22, 80, 443, 8080, 9200, 27017, 6379]
    port_rows = []
    for p in interesting_ports:
        q = f"{base_query} port:{p}"
        f = facets_from_count(api, q, "org:20,asn:20")
        count_total = sum(item["count"] for item in f.get("org", []))
        port_rows.append({"port": p, "estimated_count": count_total})
        save_facets_to_csv(f, os.path.join(out_processed, f"port_{p}_facets"))
        time.sleep(1.0)
    pd.DataFrame(port_rows).to_csv(os.path.join(out_processed, "interesting_ports_summary.csv"), index=False)

    # 5) Metadata
    meta = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "country": args.country,
        "base_query": base_query,
        "max_matches": args.max_matches,
        "notes": "Publish only aggregate results. Avoid publishing raw IPs/hostnames."
    }
    with open(os.path.join(out_processed, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print("Done. Aggregates and samples written to", out_processed)


if __name__ == "__main__":
    main()