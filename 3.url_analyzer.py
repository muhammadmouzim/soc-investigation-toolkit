import re
import socket
import ipaddress
import base64
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
import os


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):
    """
    Add HTTPS if the user does not provide a URL scheme.
    """

    url = url.strip()

    if not url:
        return None

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url):
    """
    Validate basic URL structure.
    """

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        # Validate port if one is supplied
        if parsed.port is not None:
            if not (1 <= parsed.port <= 65535):
                return False

        return True

    except ValueError:
        return False


# ============================================================
# URL COMPONENT ANALYSIS
# ============================================================

def analyze_url(url):
    """
    Break the URL into useful investigation components.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname

    result = {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment
    }

    return result


# ============================================================
# IP ADDRESS DETECTION
# ============================================================

def is_ip_address(hostname):
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


# ============================================================
# SUSPICIOUS URL INDICATORS
# ============================================================

def detect_suspicious_indicators(url, analysis):

    indicators = []

    hostname = analysis["hostname"]
    scheme = analysis["scheme"]

    # --------------------------------------------------------
    # URL length
    # --------------------------------------------------------

    if len(url) > 100:

        indicators.append(
            "Unusually long URL"
        )

    # --------------------------------------------------------
    # HTTP instead of HTTPS
    # --------------------------------------------------------

    if scheme == "http":

        indicators.append(
            "Uses HTTP instead of HTTPS"
        )

    # --------------------------------------------------------
    # IP address instead of domain
    # --------------------------------------------------------

    if is_ip_address(hostname):

        indicators.append(
            "URL uses an IP address instead of a domain"
        )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "update",
        "signin",
        "confirm"
    ]

    url_lower = url.lower()

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:

        indicators.append(
            "Contains potentially sensitive keywords: "
            + ", ".join(found_keywords)
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if "@" in url:

        indicators.append(
            "Contains @ symbol"
        )

    # --------------------------------------------------------
    # Excessive subdomains
    # --------------------------------------------------------

    if not is_ip_address(hostname):

        domain_parts = hostname.split(".")

        if len(domain_parts) > 4:

            indicators.append(
                "Contains an unusually large number of subdomains"
            )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    if "xn--" in hostname.lower():

        indicators.append(
            "Domain contains Punycode"
        )

    return indicators


# ============================================================
# DNS RESOLUTION
# ============================================================

def resolve_domain(hostname):
    """
    Resolve a domain name to its IP addresses.

    For an IP address, return the address itself.
    """

    # If the hostname is already an IP address,
    # DNS resolution is unnecessary.
    if is_ip_address(hostname):

        return [hostname]

    try:

        addresses = socket.gethostbyname_ex(hostname)

        return addresses[2]

    except socket.gaierror:

        return []

    except Exception:

        return []


# ============================================================
# VIRUSTOTAL URL LOOKUP
# ============================================================

def virustotal_url_lookup(url):
    """
    Query VirusTotal for an existing URL report.

    VirusTotal v3 uses a URL-safe Base64 representation
    without '=' padding as the URL identifier.
    """

    if not VT_API_KEY:

        return "missing_api_key"

    try:

        # Correct VirusTotal URL ID generation
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        endpoint = (
            f"https://www.virustotal.com/api/v3/urls/{url_id}"
        )

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        # ----------------------------------------------------
        # Successful response
        # ----------------------------------------------------

        if response.status_code == 200:

            data = response.json()

            attributes = data["data"]["attributes"]

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        # ----------------------------------------------------
        # URL not found
        # ----------------------------------------------------

        elif response.status_code == 404:

            return "not_found"

        # ----------------------------------------------------
        # Invalid API key
        # ----------------------------------------------------

        elif response.status_code == 401:

            return "unauthorized"

        # ----------------------------------------------------
        # Forbidden
        # ----------------------------------------------------

        elif response.status_code == 403:

            return "forbidden"

        # ----------------------------------------------------
        # Rate limit
        # ----------------------------------------------------

        elif response.status_code == 429:

            return "rate_limited"

        # ----------------------------------------------------
        # Other HTTP errors
        # ----------------------------------------------------

        else:

            return f"http_error_{response.status_code}"

    except requests.RequestException as error:

        print(
            f"\n[-] VirusTotal network error: {error}"
        )

        return "network_error"


# ============================================================
# DISPLAY VIRUSTOTAL RESULT
# ============================================================

def display_virustotal_result(result):

    print("\n=== VirusTotal URL Intelligence ===")

    if result == "missing_api_key":

        print(
            "[-] VirusTotal API key not configured"
        )

        return

    if result == "not_found":

        print(
            "[!] URL not found in VirusTotal"
        )

        print(
            "[!] Verdict: Unknown"
        )

        return

    if result == "unauthorized":

        print(
            "[-] VirusTotal API key is invalid or unauthorized"
        )

        return

    if result == "forbidden":

        print(
            "[-] VirusTotal API request is forbidden"
        )

        return

    if result == "rate_limited":

        print(
            "[-] VirusTotal API rate limit reached"
        )

        return

    if result == "network_error":

        print(
            "[-] Could not connect to VirusTotal"
        )

        return

    if isinstance(result, str) and result.startswith(
        "http_error_"
    ):

        print(
            f"[-] VirusTotal returned: {result}"
        )

        return

    # --------------------------------------------------------
    # Display VirusTotal statistics
    # --------------------------------------------------------

    print(
        f"[+] Malicious  : {result['malicious']}"
    )

    print(
        f"[+] Suspicious : {result['suspicious']}"
    )

    print(
        f"[+] Harmless   : {result['harmless']}"
    )

    print(
        f"[+] Undetected : {result['undetected']}"
    )

    print("\n=== VirusTotal Assessment ===")

    if result["malicious"] > 0:

        print(
            "[!] Potentially malicious"
        )

    elif result["suspicious"] > 0:

        print(
            "[!] Suspicious"
        )

    else:

        print(
            "[+] No malicious/suspicious detections reported"
        )


# ============================================================
# DISPLAY URL ANALYSIS
# ============================================================

def display_url_analysis(
    url,
    analysis,
    indicators,
    addresses
):

    print("\n=== URL Analysis ===")

    print(
        f"[+] URL       : {url}"
    )

    print(
        f"[+] Scheme    : {analysis['scheme']}"
    )

    print(
        f"[+] Domain    : {analysis['hostname']}"
    )

    if analysis["port"]:

        print(
            f"[+] Port      : {analysis['port']}"
        )

    else:

        print(
            "[+] Port      : Default"
        )

    print(
        f"[+] Path      : {analysis['path'] or '/'}"
    )

    print(
        f"[+] Query     : {analysis['query'] or 'None'}"
    )

    print(
        f"[+] Fragment  : {analysis['fragment'] or 'None'}"
    )

    # --------------------------------------------------------
    # DNS results
    # --------------------------------------------------------

    print("\n=== DNS Resolution ===")

    if addresses:

        for address in addresses:

            print(
                f"[+] IP Address: {address}"
            )

    else:

        print(
            "[!] Domain could not be resolved"
        )

    # --------------------------------------------------------
    # Suspicious indicators
    # --------------------------------------------------------

    print("\n=== Suspicious Indicators ===")

    if indicators:

        for indicator in indicators:

            print(
                f"[!] {indicator}"
            )

    else:

        print(
            "[+] No obvious suspicious indicators detected"
        )


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print(
        "=== SOC URL Investigation Tool ==="
    )

    url_input = input(
        "\nEnter a URL to investigate: "
    ).strip()

    # --------------------------------------------------------
    # Normalize URL
    # --------------------------------------------------------

    url = normalize_url(url_input)

    if not url:

        print(
            "\n[-] Empty URL"
        )

        return

    # --------------------------------------------------------
    # Validate URL
    # --------------------------------------------------------

    if not validate_url(url):

        print(
            "\n[-] Invalid URL"
        )

        return

    print(
        "\n[+] Valid URL"
    )

    # --------------------------------------------------------
    # Analyze URL
    # --------------------------------------------------------

    analysis = analyze_url(url)

    indicators = detect_suspicious_indicators(
        url,
        analysis
    )

    # --------------------------------------------------------
    # DNS resolution
    # --------------------------------------------------------

    addresses = resolve_domain(
        analysis["hostname"]
    )

    # --------------------------------------------------------
    # Display analysis
    # --------------------------------------------------------

    display_url_analysis(
        url,
        analysis,
        indicators,
        addresses
    )

    # --------------------------------------------------------
    # VirusTotal lookup
    # --------------------------------------------------------

    print(
        "\n[*] Checking VirusTotal..."
    )

    vt_result = virustotal_url_lookup(
        url
    )

    display_virustotal_result(
        vt_result
    )

    # --------------------------------------------------------
    # Final SOC assessment
    # --------------------------------------------------------

    print(
        "\n=== Final SOC Assessment ==="
    )

    if isinstance(vt_result, dict):

        if vt_result["malicious"] > 0:

            print(
                "[!] HIGH PRIORITY: "
                "VirusTotal reported malicious detections."
            )

        elif vt_result["suspicious"] > 0:

            print(
                "[!] REVIEW REQUIRED: "
                "VirusTotal reported suspicious detections."
            )

        elif indicators:

            print(
                "[!] REVIEW REQUIRED: "
                "Suspicious URL characteristics detected."
            )

        else:

            print(
                "[+] No obvious threat indicators detected."
            )

    elif indicators:

        print(
            "[!] REVIEW REQUIRED: "
            "Suspicious URL characteristics detected."
        )

    else:

        print(
            "[+] Static analysis found no obvious indicators."
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()