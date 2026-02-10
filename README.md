# 🕵️ IOC Extractor (Python)

A lightweight **SOC-style Python CLI tool** that extracts common **Indicators of Compromise (IOCs)** from logs and text files — including **IPs, emails, URLs, domains, and file hashes**.

Built for **SOC / Blue Team practice** and fast IOC extraction during investigations.

---

## ✨ Features

✅ Extracts:
- 🌐 IPv4 addresses  
- 📧 Emails  
- 🔗 URLs  
- 🏷️ Domains  
- 🔐 Hashes: **MD5 / SHA1 / SHA256**

✅ Clean CLI output report  
✅ Works with any `.txt` log file  
✅ Includes realistic sample logs for testing  
✅ No external dependencies (standard library only)

---

## 🧠 SOC Relevance

In real SOC work, analysts deal with logs from:
- SSH authentication failures (brute-force attempts)
- Web proxy / firewall logs
- Incident reports / phishing emails

This tool helps quickly extract IOCs for:
- Threat hunting  
- Investigation  
- Enrichment (VirusTotal, AbuseIPDB, etc.)   

---



## ⚙️ Requirements

- Python 3.8+ recommended  
- No external dependencies


---

## ▶️ How to Run

### 1) Clone the repository
```bash
git clone https://github.com/<meeran-jeelani>/ioc-extractor.git
cd ioc-extractor
```

### 2) Run on a log file
```bash
python src/ioc_extractor.py samples/sample_log.txt
```

---

## 🧪 Test with Sample Logs

### SSH brute-force style logs
```bash
python src/ioc_extractor.py samples/ssh_failed_log.txt
```

### Web proxy / redirect logs
```bash
python src/ioc_extractor.py samples/web_proxy_log.txt
```

---

## 📌 Output

The tool prints a structured report containing:

- IPv4 addresses
- Emails
- URLs
- Domains
- Hashes (MD5 / SHA1 / SHA256)

This makes it easy to copy-paste IOCs into SOC tools or threat intel platforms.

---

## 🚀 Future Enhancements (Planned)

- Defang support (e.g., `hxxp://`, `[.]`, `[:]`)
- IPv6 IOC extraction
- Improved domain detection (more TLD support)
- Cleaner output + top summary line


---

## 🧑‍💻 Author

Built by **Meeran Jeelani**  
Cybersecurity student | SOC

---

## 📜 License

This project is licensed under the **MIT License**.
