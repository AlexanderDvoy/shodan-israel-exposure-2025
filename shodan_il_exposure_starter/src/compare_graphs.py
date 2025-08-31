# src/compare_graphs.py
import csv
from collections import defaultdict
from pathlib import Path
import argparse
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR  = PROJECT_ROOT / "reports"
FIG_DIR      = REPORTS_DIR / "figures"
DEFAULT_INPUT = REPORTS_DIR / "risk_data.csv"

def load_counts(path: Path):
    counts = defaultdict(lambda: defaultdict(int))
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            country  = (row.get("country") or "NA")
            protocol = (row.get("protocol") or "Unknown")
            counts[country][protocol] += 1
    return counts

def plot_by_country(counts, out_path: Path):
    countries = sorted(counts.keys())
    protocols = sorted({p for c in counts.values() for p in c.keys()})
    series = {p: [counts[c].get(p,0) for c in countries] for p in protocols}

    x = np.arange(len(countries))
    width = 0.8 / max(1, len(protocols))
    fig, ax = plt.subplots(figsize=(11,6))
    for i, p in enumerate(protocols):
        ax.bar(x + i*width, series[p], width, label=p)

    ax.set_title("Exposed Services by Country")
    ax.set_xlabel("Country")
    ax.set_ylabel("Number of Exposed Hosts")
    ax.set_xticks(x + (len(protocols)-1)*width/2)
    ax.set_xticklabels(countries)
    ax.legend(title="Protocol")

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    print(f"✅ נשמר גרף: {out_path.resolve()}")
    plt.close(fig)

def main():
    p = argparse.ArgumentParser(description="Comparison chart (from reports/risk_data.csv)")
    p.add_argument("-i","--input", type=Path, default=DEFAULT_INPUT)
    args = p.parse_args()

    csv_path = args.input if args.input.is_absolute() else (PROJECT_ROOT / args.input)
    if not csv_path.exists():
        raise FileNotFoundError(f"❌ לא נמצא קובץ: {csv_path}")

    counts = load_counts(csv_path)
    plot_by_country(counts, REPORTS_DIR / "figures" / "comparison_by_country.png")

if __name__ == "__main__":
    main()
