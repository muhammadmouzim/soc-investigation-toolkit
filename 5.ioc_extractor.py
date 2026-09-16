import re
import ipaddress


def extract_iocs(text):
    # -----------------------------
    # URLs
    # -----------------------------
    url_pattern = r'https?://[^\s<>"\']+'
    raw_urls = re.findall(url_pattern, text)

    urls = set()

    for url in raw_urls:
        url = url.rstrip(".,;:!?)]}>")
        urls.add(url)

    # -----------------------------
    # IP Addresses
    # -----------------------------
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    ips = set()

    for value in re.findall(ip_pattern, text):
        try:
            ipaddress.ip_address(value)

            # Don't list an IP separately if it is already inside a URL
            if not any(value in url for url in urls):
                ips.add(value)

        except ValueError:
            pass

    # -----------------------------
    # Domains
    # -----------------------------
    domain_pattern = (
        r'\b(?:[a-zA-Z0-9-]+\.)+'
        r'[a-zA-Z]{2,}\b'
    )

    domains = set()

    for domain in re.findall(domain_pattern, text):
        domain = domain.lower().rstrip(".,;:!?)]}>")

        # Don't duplicate domains already contained in URLs
        if not any(domain in url.lower() for url in urls):
            domains.add(domain)

    # -----------------------------
    # Hashes
    # -----------------------------
    hash_pattern = r'\b[a-fA-F0-9]{32,128}\b'

    md5_hashes = set()
    sha1_hashes = set()
    sha256_hashes = set()
    sha512_hashes = set()

    for hash_value in re.findall(hash_pattern, text):
        hash_value = hash_value.lower()

        if len(hash_value) == 32:
            md5_hashes.add(hash_value)

        elif len(hash_value) == 40:
            sha1_hashes.add(hash_value)

        elif len(hash_value) == 64:
            sha256_hashes.add(hash_value)

        elif len(hash_value) == 128:
            sha512_hashes.add(hash_value)

    return (
        sorted(ips),
        sorted(urls),
        sorted(domains),
        sorted(md5_hashes),
        sorted(sha1_hashes),
        sorted(sha256_hashes),
        sorted(sha512_hashes)
    )


def display_results(results):
    (
        ips,
        urls,
        domains,
        md5_hashes,
        sha1_hashes,
        sha256_hashes,
        sha512_hashes
    ) = results

    print("\n=== SOC IOC Extraction Results ===")

    print("\n=== IP Addresses ===")
    if ips:
        for ip in ips:
            print(f"[+] {ip}")
    else:
        print("[+] None found")

    print("\n=== URLs ===")
    if urls:
        for url in urls:
            print(f"[+] {url}")
    else:
        print("[+] None found")

    print("\n=== Domains ===")
    if domains:
        for domain in domains:
            print(f"[+] {domain}")
    else:
        print("[+] None found")

    print("\n=== MD5 Hashes ===")
    if md5_hashes:
        for value in md5_hashes:
            print(f"[+] {value}")
    else:
        print("[+] None found")

    print("\n=== SHA-1 Hashes ===")
    if sha1_hashes:
        for value in sha1_hashes:
            print(f"[+] {value}")
    else:
        print("[+] None found")

    print("\n=== SHA-256 Hashes ===")
    if sha256_hashes:
        for value in sha256_hashes:
            print(f"[+] {value}")
    else:
        print("[+] None found")

    print("\n=== SHA-512 Hashes ===")
    if sha512_hashes:
        for value in sha512_hashes:
            print(f"[+] {value}")
    else:
        print("[+] None found")

    total_iocs = (
        len(ips)
        + len(urls)
        + len(domains)
        + len(md5_hashes)
        + len(sha1_hashes)
        + len(sha256_hashes)
        + len(sha512_hashes)
    )

    print("\n=== IOC Summary ===")
    print(f"[+] IP addresses : {len(ips)}")
    print(f"[+] URLs         : {len(urls)}")
    print(f"[+] Domains      : {len(domains)}")
    print(f"[+] MD5          : {len(md5_hashes)}")
    print(f"[+] SHA-1        : {len(sha1_hashes)}")
    print(f"[+] SHA-256      : {len(sha256_hashes)}")
    print(f"[+] SHA-512      : {len(sha512_hashes)}")
    print(f"[+] Total IOCs   : {total_iocs}")

    print("\n[+] IOC extraction completed.")


def main():
    print("=== SOC IOC Extractor ===")
    print("Paste security alert/log text.")
    print("Press ENTER on an empty line when finished.\n")

    lines = []

    while True:
        line = input()

        if line.strip() == "":
            break

        lines.append(line)

    text = "\n".join(lines)

    if not text.strip():
        print("\n[-] No input provided.")
        return

    results = extract_iocs(text)
    display_results(results)


if __name__ == "__main__":
    main()