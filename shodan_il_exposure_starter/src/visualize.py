import os
import pandas as pd
import matplotlib.pyplot as plt

BASE = "data/processed"
FIGDIR = "reports/figures"
os.makedirs(FIGDIR, exist_ok=True)

def maybe_plot_counts_csv(path, title, xlab, ylab, xcol="value", ycol="count", outname="chart.png", head=10):
    if not os.path.exists(path):
        return
    df = pd.read_csv(path)
    if df.empty:
        return
    df = df.head(head)
    plt.figure()
    plt.bar(df[xcol].astype(str), df[ycol])
    plt.title(title)
    plt.xlabel(xlab)
    plt.ylabel(ylab)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGDIR, outname))
    plt.close()

# Global facets
maybe_plot_counts_csv(os.path.join(BASE, "global_facets_port.csv"),
                      "Top Open Ports in Israel (Shodan)", "Port", "Count", outname="top_ports.png")

maybe_plot_counts_csv(os.path.join(BASE, "global_facets_org.csv"),
                      "Top Organizations (by exposed hosts)", "Organization", "Count", outname="top_orgs.png")

maybe_plot_counts_csv(os.path.join(BASE, "global_facets_asn.csv"),
                      "Top ASNs (by exposed hosts)", "ASN", "Count", outname="top_asns.png")

maybe_plot_counts_csv(os.path.join(BASE, "global_facets_product.csv"),
                      "Top Exposed Products/Services", "Product", "Count", outname="top_products.png")

# Vulnerabilities
maybe_plot_counts_csv(os.path.join(BASE, "vuln_facets_vuln.csv"),
                      "Top CVEs observed (presence in banners)", "CVE", "Count", outname="top_cves.png")

# ICS
maybe_plot_counts_csv(os.path.join(BASE, "ics_facets_product.csv"),
                      "ICS/SCADA Products Exposed (sample)", "Product", "Count", outname="ics_products.png")

print("Charts saved to", FIGDIR)