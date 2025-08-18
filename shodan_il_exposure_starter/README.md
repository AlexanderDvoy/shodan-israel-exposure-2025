# Israel Cyber Exposure Report (Shodan, 2025)

Practical PT/OSINT project that analyzes exposed services in Israel using the Shodan API, produces aggregate statistics (ports, orgs, ASNs, products), highlights ICS/SCADA exposure, and summarizes vulnerable services (CVE presence).

> Ethical note: This project uses **aggregate** public data via Shodan. Do **not** publish specific IPs/identifying details. Use results for awareness, education, and defense. Respect Shodan's ToS and your local laws.

## Quick Start

1) Python 3.10+ and Git installed.
2) Create virtual env and install deps:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
3) Add your Shodan key to `.env` (do not commit this file):
```
SHODAN_API_KEY=your_api_key_here
```
4) Collect data (facets and samples):
```bash
python src/collect_shodan.py --country IL --max-matches 1000
```
5) Build charts:
```bash
python src/visualize.py
```
6) Draft the report from `reports/Report_ISRAEL_2025.md` and attach charts from `reports/figures/`.
7) Publish on GitHub and share highlights on LinkedIn (see `linkedin_post_ru.txt`).

## What you'll get
- `data/processed/` CSVs with **aggregated** counts and sample matches (no IPs in public release recommended).
- `reports/figures/` charts (Top Ports, Orgs, ASNs, Products, CVEs, ICS product counts).
- A reproducible pipeline you can schedule monthly to show trends.

## Scope
- Base query: `country:IL -tag:honeypot`
- ICS focus: `tag:ics`
- Vulnerable services: `has_vuln:true` with CVE facets

## Disclaimer
This repository is for educational and defensive research only. Do not use for unauthorized access or targeting. Aggregate-only publication is recommended.