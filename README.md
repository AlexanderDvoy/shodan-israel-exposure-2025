Shodan Exposure Risk Analysis

A Python-based project for collecting, analyzing, and visualizing Shodan data to understand cyber exposure at the country and organization level.

🚀 Features

Automated Shodan Collection
Collect exposed services by country, organization (org), or ASN.

Risk Analysis
Maps open ports to:

Protocols

Risk level (Low → Critical)

Relevant CVEs

Multi-Country / Organization Comparison
Run the pipeline for several countries/organizations and compare exposures.

Visualization
Clear bar charts of exposed protocols by country.

Flexible Input Formats
Supports both CSV and JSON/NDJSON Shodan outputs.

🛠️ Project Structure
shodan_il_exposure/
│── reports/                # Output files (CSV, graphs, reports)
│   └── figures/
│── data/
│   └── raw/                # Raw JSON data from Shodan
│── src/
│   ├── collect_shodan.py   # Collects Shodan results
│   ├── risk_analysis.py    # Risk mapping & CVE enrichment
│   ├── risk_mapping.py     # Port → Protocol → Risk → CVEs mapping
│   ├── compare_graphs.py   # Generates comparative charts
│   └── main.py             # Pipeline (collect → analyze → visualize)
│── requirements.txt
│── README.md

⚡ Installation
git clone https://github.com/<your_username>/shodan_il_exposure.git
cd shodan_il_exposure
python -m venv venv
source venv/bin/activate   # (Linux/Mac)
.\venv\Scripts\Activate.ps1 # (Windows PowerShell)
pip install -r requirements.txt

🔑 Shodan API Key

Export your Shodan API key before running:

export SHODAN_API_KEY="your_api_key_here"   # Linux/Mac
$env:SHODAN_API_KEY="your_api_key_here"     # Windows PowerShell

▶️ Usage
Collect data (Israel)
python -m src.collect_shodan -c IL -l 200

Collect data (Organization in Netherlands)
python -m src.collect_shodan -c NL -q 'org:"Brinks Inc"' -l 200

Risk Analysis
python -m src.risk_analysis -i reports/shodan_raw_data.csv -o reports/risk_data.csv

Visualization
python -m src.compare_graphs -i reports/risk_data.csv


Outputs:

reports/risk_data.csv → enriched with protocol, risk, CVEs

reports/figures/comparison_by_country.png

Full Pipeline
python -m src.main

📊 Example Output
IP	Port	Protocol	Country	Org	Risk	CVEs
208.56.32.192	25	SMTP	IL	Meta Networks Inc	Medium	CVE-2020-8616
91.199.111.10	3389	RDP	US	Example ISP	Critical	CVE-2019-0708

Graph output:


📌 Use Cases

Threat Intelligence teams: country-level exposure mapping.

Penetration Testers: OSINT reconnaissance prior to engagements.

Researchers: compare exposure trends across different regions.

⚠️ Disclaimer

This project is for educational and research purposes only.
Do not use it to exploit systems. Always ensure you have permission before scanning or analyzing an organization.
