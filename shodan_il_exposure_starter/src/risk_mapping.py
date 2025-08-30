risk_mapping = {
    21:  {"protocol": "FTP",  "risk": "Medium",   "issues": ["Anonymous login", "Brute force"], "cves": ["CVE-2015-3306"]},
    22:  {"protocol": "SSH",  "risk": "Medium",   "issues": ["Weak credentials", "User enumeration"], "cves": ["CVE-2018-15473"]},
    23:  {"protocol": "Telnet", "risk": "High",   "issues": ["Cleartext passwords", "Mirai Botnet"], "cves": ["CVE-2016-10401"]},
    3389:{"protocol": "RDP",  "risk": "Critical", "issues": ["Brute force", "BlueKeep"], "cves": ["CVE-2019-0708"]},
    445: {"protocol": "SMB",  "risk": "Critical", "issues": ["EternalBlue", "WannaCry"], "cves": ["CVE-2017-0144"]}
}
