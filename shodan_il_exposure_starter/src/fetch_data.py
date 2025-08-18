import os
import json
from shodan import Shodan
from dotenv import load_dotenv

def main():
    # טוען משתני סביבה מקובץ .env
    load_dotenv()

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise ValueError("Please set SHODAN_API_KEY in .env or environment variables")

    api = Shodan(api_key)

    # כל השאילתות שאנחנו רוצים להריץ
    queries = {
        "rdp": 'port:3389 country:"IL"',             # Remote Desktop
        "ftp": 'port:21 country:"IL"',               # FTP
        "smb": 'port:445 country:"IL"',              # SMB
        "ssh": 'port:22 country:"IL"',               # SSH
        "http_index": 'http.title:"index of" country:"IL"',  # Web servers exposing directories
        "rtsp": 'port:554 country:"IL"',             # RTSP (מצלמות רשת)
        "elasticsearch": 'port:9200 country:"IL"',   # Elasticsearch
        "mongodb": 'port:27017 country:"IL"',        # MongoDB
        "redis": 'port:6379 country:"IL"',           # Redis
    }

    os.makedirs("data/raw", exist_ok=True)

    for name, query in queries.items():
        print(f"[+] Running query: {query}")
        try:
            results = api.search(query, limit=100)

            output_file = f"data/raw/shodan_{name}.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

            print(f"[+] Saved {len(results['matches'])} results to {output_file}")

        except Exception as e:
            print(f"[!] Error running query {query}: {e}")

if __name__ == "__main__":
    main()
