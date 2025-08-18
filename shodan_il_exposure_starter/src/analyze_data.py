import json
import os
import pandas as pd
import matplotlib.pyplot as plt

# נתיבים
RAW_DATA = "data/raw/shodan_data.json"
PROCESSED_DIR = "data/processed"
FIGURES_DIR = "reports/figures"

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(FIGURES_DIR, exist_ok=True)

def main():
    # טוען את הנתונים
    with open(RAW_DATA, "r", encoding="utf-8") as f:
        data = json.load(f)

    matches = data.get("matches", [])
    if not matches:
        print("⚠️ לא נמצאו תוצאות בקובץ")
        return

    # רשימה של פורטים לכל מכונה
    ports = [m.get("port") for m in matches if "port" in m]

    # ספירת מופעים של פורטים
    port_counts = pd.Series(ports).value_counts().reset_index()
    port_counts.columns = ["port", "count"]

    # שמירה ל-CSV
    csv_path = os.path.join(PROCESSED_DIR, "open_ports_summary.csv")
    port_counts.to_csv(csv_path, index=False)
    print(f"✅ סיכום פורטים נשמר ב: {csv_path}")

    # ציור גרף
    plt.figure(figsize=(10,6))
    plt.bar(port_counts["port"].astype(str), port_counts["count"])
    plt.xlabel("Port")
    plt.ylabel("Hosts Found")
    plt.title("Distribution of Open Ports (Sample Data)")
    plt.tight_layout()
    fig_path = os.path.join(FIGURES_DIR, "open_ports_distribution.png")
    plt.savefig(fig_path)
    plt.close()
    print(f"📊 גרף נשמר ב: {fig_path}")

if __name__ == "__main__":
    main()
