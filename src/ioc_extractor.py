import re
import json
import argparse
from pathlib import Path

# Regex patterns (SOC style)
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)
URL_REGEX = re.compile(
    r"\bhttps?://[^\s\"\'<>]+"
)

# Domain regex (simple, safe, not too aggressive)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|in|io|co|ru|uk|xyz|me|edu|gov)\b",
    re.IGNORECASE
)

MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Core extraction functions
def extract_all(text: str) -> dict:
    iocs = {
        "ipv4": sorted(set(IPV4_REGEX.findall(text))),
        "emails": sorted(set(EMAIL_REGEX.findall(text))),
        "urls": sorted(set(URL_REGEX.findall(text))),
        "domains": [],
        "hashes": {
            "md5": sorted(set(MD5_REGEX.findall(text))),
            "sha1": sorted(set(SHA1_REGEX.findall(text))),
            "sha256": sorted(set(SHA256_REGEX.findall(text))),
        }
    }

    # Domains often appear inside URLs/emails, so extract and filter
    raw_domains = DOMAIN_REGEX.findall(text)
    domains = set(d.lower() for d in raw_domains)

    # Remove domains that are actually part of email addresses
    for email in iocs["emails"]:
        try:
            domains.discard(email.split("@")[1].lower())
        except:
            pass
    iocs["domains"] = sorted(domains)
    return iocs

def print_report(iocs: dict) -> None:
    def section(title: str):
        print("\n" + "=" * 60)
        print(title)
        print("=" * 60)
    section("IOC EXTRACTION REPORT")
    section(f"IPv4 Addresses ({len(iocs['ipv4'])})")
    for ip in iocs["ipv4"]:
        print(ip)
    section(f"Emails ({len(iocs['emails'])})")
    for e in iocs["emails"]:
        print(e)
    section(f"URLs ({len(iocs['urls'])})")
    for u in iocs["urls"]:
        print(u)
    section(f"Domains ({len(iocs['domains'])})")
    for d in iocs["domains"]:
        print(d)
    section("Hashes")
    print(f"MD5    ({len(iocs['hashes']['md5'])})")
    for h in iocs["hashes"]["md5"]:
        print(h)
    print(f"\nSHA1   ({len(iocs['hashes']['sha1'])})")
    for h in iocs["hashes"]["sha1"]:
        print(h)
    print(f"\nSHA256 ({len(iocs['hashes']['sha256'])})")
    for h in iocs["hashes"]["sha256"]:
        print(h)


# CLI
def main():
    parser = argparse.ArgumentParser(
        description="SOC-style IOC extractor (IPs, URLs, domains, emails, hashes)"
    )
    parser.add_argument("input_file", help="Path to the text/log file to analyze")
    parser.add_argument("--json", dest="json_out", help="Save results to JSON file")

    args = parser.parse_args()
    file_path = Path(args.input_file)
    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}")
        return
    text = file_path.read_text(errors="ignore")
    iocs = extract_all(text)
    print_report(iocs)
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(iocs, indent=2))
        print(f"\n[OK] JSON report saved to: {out_path}")

if __name__ == "__main__":
    main()
