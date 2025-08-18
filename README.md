Shodan IL Exposure Starter

A simple Python project that queries the Shodan API for exposed services in Israel and stores the results for analysis.
This is intended for educational and cybersecurity research purposes only.

Features

Fetches data from Shodan using multiple queries:

RDP (3389)

FTP (21)

SSH (22)

SMB (445)

HTTP “Index of” pages

RTSP (IP cameras)

Elasticsearch (9200)

MongoDB (27017)

Redis (6379)

Saves results into data/raw/ as JSON files.

Easy to extend with new queries.

Structured for later data analysis (analyze_data.py).

 Quickstart
 
1. Clone the repo
git clone https://github.com/YOUR-USERNAME/shodan_il_exposure_starter.git
cd shodan_il_exposure_starter

2. Setup virtual environment
python -m venv .venv
source .venv/bin/activate   # On Linux/Mac
.venv\Scripts\activate      # On Windows

3. Install dependencies
pip install -r requirements.txt

4. Set your Shodan API key

Create a .env file in the project root:

SHODAN_API_KEY=your_api_key_here

5. Run the data fetcher
python src/fetch_data.py


Results will be saved in data/raw/.

6. (Optional) Run analysis
python src/analyze_data.py

📂 Project Structure
shodan_il_exposure_starter/
│
├── src/
│   ├── fetch_data.py       # Fetch data from Shodan
│   ├── analyze_data.py     # Analyze collected data
│
├── data/
│   └── raw/                # Raw JSON outputs
│
├── .env.example            # Example environment variables
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation

⚠️ Disclaimer

This project is for educational purposes only.
Do not use it for unauthorized scanning or attacks.
Always respect local laws and the Shodan terms of service.
<img width="930" height="374" alt="321" src="https://github.com/user-attachments/assets/848c07f9-1717-4d6f-ad40-f1cd328a3779" />
