import re
import json
import csv
import argparse
from pathlib import Path

# Regex patterns
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Practical IPv6 matcher (covers common forms)
IPV6_REGEX = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|"
    r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)"
    r")\b"
)

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)
URL_REGEX = re.compile(
    r"\bhttps?://[^\s\"\'<>]+"
)
# Domain regex (simple and safe)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b",
    re.IGNORECASE
)
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")


# Helpers
def defang_text(value: str) -> str:
    """
    Defang a string so it can be safely shared.
    Example:
      https://evil.com -> hxxps://evil[.]com
    """
    value = value.replace("https://", "hxxps://")
    value = value.replace("http://", "hxxp://")
    value = value.replace(".", "[.]")
    return value
def unique_sorted(items):
    return sorted(set(items))

# Core extraction
def extract_all(text: str) -> dict:
    ipv4 = unique_sorted(IPV4_REGEX.findall(text))
    ipv6 = unique_sorted(IPV6_REGEX.findall(text))
    emails = unique_sorted(EMAIL_REGEX.findall(text))
    urls = unique_sorted(URL_REGEX.findall(text))

    # Domains: extract from raw text
    raw_domains = DOMAIN_REGEX.findall(text)
    domains = set(d.lower() for d in raw_domains)

    # Remove domains that are actually part of email addresses
    for email in emails:
        try:
            domains.discard(email.split("@")[1].lower())
        except Exception:
            pass

    for u in urls:
        try:
            # crude extraction: split by scheme then by /
            host = u.split("://", 1)[1].split("/", 1)[0].lower()
            # remove port if present
            host = host.split(":", 1)[0]
            domains.discard(host)
        except Exception:
            pass

    md5s = unique_sorted(MD5_REGEX.findall(text))
    sha1s = unique_sorted(SHA1_REGEX.findall(text))
    sha256s = unique_sorted(SHA256_REGEX.findall(text))

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "emails": emails,
        "urls": urls,
        "domains": sorted(domains),
        "hashes": {
            "md5": md5s,
            "sha1": sha1s,
            "sha256": sha256s,
        }
    }


# Reporting
def print_summary(iocs: dict, defang: bool = False) -> None:
    total_hashes = (
        len(iocs["hashes"]["md5"]) +
        len(iocs["hashes"]["sha1"]) +
        len(iocs["hashes"]["sha256"])
    )
    total = (
        len(iocs["ipv4"]) +
        len(iocs["ipv6"]) +
        len(iocs["emails"]) +
        len(iocs["urls"]) +
        len(iocs["domains"]) +
        total_hashes
    )
    print("\n" + "=" * 60)
    print("IOC EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Total IOCs found: {total}")
    print(f"IPv4:   {len(iocs['ipv4'])}")
    print(f"IPv6:   {len(iocs['ipv6'])}")
    print(f"Emails: {len(iocs['emails'])}")
    print(f"URLs:   {len(iocs['urls'])}")
    print(f"Domains:{len(iocs['domains'])}")
    print(f"Hashes: {total_hashes}")
    print(f"Defang: {'ON' if defang else 'OFF'}")
    print("=" * 60)
def print_report(iocs: dict, defang: bool = False) -> None:
    def section(title: str):
        print("\n" + "-" * 60)
        print(title)
        print("-" * 60)
    def maybe_defang(value: str) -> str:
        return defang_text(value) if defang else value

    print_summary(iocs, defang=defang)

    section(f"IPv4 Addresses ({len(iocs['ipv4'])})")
    for ip in iocs["ipv4"]:
        print(maybe_defang(ip))

    section(f"IPv6 Addresses ({len(iocs['ipv6'])})")
    for ip in iocs["ipv6"]:
        print(maybe_defang(ip))

    section(f"Emails ({len(iocs['emails'])})")
    for e in iocs["emails"]:
        print(maybe_defang(e))

    section(f"URLs ({len(iocs['urls'])})")
    for u in iocs["urls"]:
        print(maybe_defang(u))

    section(f"Domains ({len(iocs['domains'])})")
    for d in iocs["domains"]:
        print(maybe_defang(d))

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


# Export
def save_json(iocs: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(iocs, indent=2), encoding="utf-8")

def save_csv(iocs: dict, out_path: Path, defang: bool = False) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    def maybe_defang(value: str) -> str:
        return defang_text(value) if defang else value

    rows = []
    for ip in iocs["ipv4"]:
        rows.append(("ipv4", maybe_defang(ip)))

    for ip in iocs["ipv6"]:
        rows.append(("ipv6", maybe_defang(ip)))

    for e in iocs["emails"]:
        rows.append(("email", maybe_defang(e)))

    for u in iocs["urls"]:
        rows.append(("url", maybe_defang(u)))

    for d in iocs["domains"]:
        rows.append(("domain", maybe_defang(d)))

    for h in iocs["hashes"]["md5"]:
        rows.append(("md5", h))

    for h in iocs["hashes"]["sha1"]:
        rows.append(("sha1", h))

    for h in iocs["hashes"]["sha256"]:
        rows.append(("sha256", h))

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        writer.writerows(rows)

# CLI
def main():
    parser = argparse.ArgumentParser(
        description="IOC extractor (IPs, URLs, domains, emails, hashes) - v1.1"
    )
    parser.add_argument("input_file", help="Path to the text/log file to analyze")

    parser.add_argument(
        "--json",
        dest="json_out",
        help="Save results to JSON file (example: output/report.json)"
    )

    parser.add_argument(
        "--csv",
        dest="csv_out",
        help="Save results to CSV file (example: output/report.csv)"
    )

    parser.add_argument(
        "--defang",
        action="store_true",
        help="Defang output for safe sharing (hxxp:// and [.] formatting)"
    )

    args = parser.parse_args()

    file_path = Path(args.input_file)

    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}")
        return

    text = file_path.read_text(errors="ignore", encoding="utf-8")

    iocs = extract_all(text)
    print_report(iocs, defang=args.defang)

    if args.json_out:
        out_path = Path(args.json_out)
        save_json(iocs, out_path)
        print(f"\n[OK] JSON report saved to: {out_path}")

    if args.csv_out:
        out_path = Path(args.csv_out)
        save_csv(iocs, out_path, defang=args.defang)
        print(f"\n[OK] CSV report saved to: {out_path}")


if __name__ == "__main__":
    main()
