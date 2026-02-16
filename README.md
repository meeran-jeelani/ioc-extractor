# 🕵️ IOC Extractor (Python)

A **SOC-style IOC extractor** written in Python.  
Extracts common Indicators of Compromise (IOCs) from log files and text reports:

- IPv4 + IPv6
- Emails
- URLs
- Domains
- Hashes (MD5 / SHA1 / SHA256)
 
✅ Includes realistic sample logs for testing  
✅ Supports **Defang mode** for safe sharing of IOCs  
✅ Exports results to **JSON** and **CSV**  

---

## ✨ Features

- Extracts:
  - IPv4 addresses
  - IPv6 addresses
  - Emails
  - URLs
  - Domains
  - MD5 / SHA1 / SHA256 hashes
- Output options:
  - Terminal report
  - Save as JSON
  - Save as CSV
- Optional **defang** output:
  - `http://` → `hxxp://`
  - `https://` → `hxxps://`
  - `.` → `[.]`

---

## ⚙️ Requirements

- Python 3.8+ recommended  
- No external dependencies


---

## ▶️ How to Run

### 1) Run the tool
From the repo root:

```bash
python src/ioc_extractor.py samples/sample_log.txt
```

### 2) Save results as JSON
```bash
python src/ioc_extractor.py samples/sample_log.txt --json output/report.json
```

### 3) Save results as CSV
```bash
python src/ioc_extractor.py samples/sample_log.txt --csv output/report.csv
```

### 4) Defang output (safe to share)
```bash
python src/ioc_extractor.py samples/sample_log.txt --defang
```

---

## 📊 Output Example (Summary)

The tool prints a summary at the top:

- Total IOCs found
- Counts per category (IPs, domains, URLs, hashes, etc.)

Then prints the full extracted lists.

---

## 📌 Project Status

✅ **Final Release: v1.1**  
This project is complete and will not receive further feature updates.

---

## 👤 Author

Built by **Meeran Jeelani**  
Cybersecurity Student

---

## 📄 License

MIT License
