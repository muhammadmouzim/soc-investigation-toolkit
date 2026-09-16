import re
import hashlib
import os
import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


# ============================================================
# HASH IDENTIFICATION
# ============================================================

def identify_hash(hash_value):
    """
    Identify the likely hash algorithm based on
    hexadecimal character length.
    """

    hash_value = hash_value.strip().lower()

    if re.fullmatch(r"[a-f0-9]{32}", hash_value):
        return "MD5"

    elif re.fullmatch(r"[a-f0-9]{40}", hash_value):
        return "SHA-1"

    elif re.fullmatch(r"[a-f0-9]{64}", hash_value):
        return "SHA-256"

    elif re.fullmatch(r"[a-f0-9]{128}", hash_value):
        return "SHA-512"

    return None


# ============================================================
# FILE HASH CALCULATION
# ============================================================

def calculate_file_hashes(file_path):
    """
    Calculate MD5, SHA-1, SHA-256 and SHA-512
    using chunk-based file reading.
    """

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()

    try:

        with open(file_path, "rb") as file:

            while True:

                chunk = file.read(4096)

                if not chunk:
                    break

                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                sha512_hash.update(chunk)

        return {
            "MD5": md5_hash.hexdigest(),
            "SHA-1": sha1_hash.hexdigest(),
            "SHA-256": sha256_hash.hexdigest(),
            "SHA-512": sha512_hash.hexdigest()
        }

    except FileNotFoundError:

        return None

    except PermissionError:

        return "permission_error"

    except OSError:

        return "os_error"


# ============================================================
# VIRUSTOTAL LOOKUP
# ============================================================

def virustotal_lookup(hash_value):
    """
    Query VirusTotal for an existing file hash.

    VirusTotal accepts MD5, SHA-1 and SHA-256 file hashes.
    """

    if not VT_API_KEY:

        return "missing_api_key"

    url = (
        f"https://www.virustotal.com/api/v3/files/"
        f"{hash_value}"
    )

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.get(
            url,
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
        # Hash not found
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
            f"\n[-] Network error: {error}"
        )

        return "network_error"


# ============================================================
# DISPLAY VIRUSTOTAL RESULTS
# ============================================================

def display_virustotal_result(result):

    print(
        "\n=== VirusTotal Threat Intelligence ==="
    )

    if result == "missing_api_key":

        print(
            "[-] VirusTotal API key not configured"
        )

        return

    if result == "not_found":

        print(
            "[!] Hash not found in VirusTotal"
        )

        print(
            "[!] Verdict: Unknown"
        )

        return

    if result == "unauthorized":

        print(
            "[-] VirusTotal API key is invalid "
            "or unauthorized"
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

    malicious = result["malicious"]
    suspicious = result["suspicious"]
    harmless = result["harmless"]
    undetected = result["undetected"]

    print(
        f"[+] Malicious  : {malicious}"
    )

    print(
        f"[+] Suspicious : {suspicious}"
    )

    print(
        f"[+] Harmless   : {harmless}"
    )

    print(
        f"[+] Undetected : {undetected}"
    )

    print(
        "\n=== SOC Assessment ==="
    )

    if malicious > 0:

        print(
            "[!] Verdict: Potentially malicious"
        )

        print(
            "[!] Further investigation recommended"
        )

    elif suspicious > 0:

        print(
            "[!] Verdict: Suspicious"
        )

        print(
            "[!] Further investigation recommended"
        )

    else:

        print(
            "[+] Verdict: No detections reported "
            "for this hash"
        )


# ============================================================
# DISPLAY FILE HASHES
# ============================================================

def display_file_hashes(file_path, hashes):

    try:

        file_size = os.path.getsize(file_path)

    except OSError:

        file_size = "Unknown"

    print(
        "\n=== File Hash Results ==="
    )

    print(
        f"[+] File       : {file_path}"
    )

    print(
        f"[+] File Size  : {file_size} bytes"
    )

    print(
        "\n[+] Cryptographic Hashes"
    )

    print(
        f"[+] MD5        : {hashes['MD5']}"
    )

    print(
        f"[+] SHA-1      : {hashes['SHA-1']}"
    )

    print(
        f"[+] SHA-256    : {hashes['SHA-256']}"
    )

    print(
        f"[+] SHA-512    : {hashes['SHA-512']}"
    )


# ============================================================
# OPTION 1 — HASH INVESTIGATION
# ============================================================

def investigate_hash():

    hash_input = input(
        "\nEnter a file hash: "
    ).strip().lower()

    if not hash_input:

        print(
            "\n[-] No hash entered"
        )

        return

    hash_type = identify_hash(
        hash_input
    )

    if not hash_type:

        print(
            "\n[-] Invalid or unsupported hash"
        )

        return

    print(
        "\n[+] Valid hash"
    )

    print(
        f"[+] Algorithm : {hash_type}"
    )

    print(
        f"[+] Length    : {len(hash_input)} characters"
    )

    print(
        f"[+] Hash      : {hash_input}"
    )

    print(
        "\n[*] Checking VirusTotal..."
    )

    vt_result = virustotal_lookup(
        hash_input
    )

    display_virustotal_result(
        vt_result
    )


# ============================================================
# OPTION 2 — FILE HASHING + VIRUSTOTAL
# ============================================================

def investigate_file():

    file_path = input(
        "\nEnter file path: "
    ).strip()

    if not file_path:

        print(
            "\n[-] No file path entered"
        )

        return

    if not os.path.isfile(file_path):

        print(
            "\n[-] File not found"
        )

        return

    print(
        "\n[*] Calculating file hashes..."
    )

    file_hashes = calculate_file_hashes(
        file_path
    )

    if file_hashes is None:

        print(
            "\n[-] File not found"
        )

        return

    if file_hashes == "permission_error":

        print(
            "\n[-] Permission denied: "
            "unable to read the file"
        )

        return

    if file_hashes == "os_error":

        print(
            "\n[-] Operating system error "
            "while reading the file"
        )

        return

    print(
        "\n[+] File hashing successful"
    )

    display_file_hashes(
        file_path,
        file_hashes
    )

    # --------------------------------------------------------
    # VirusTotal uses SHA-256 for the file lookup
    # --------------------------------------------------------

    print(
        "\n[*] Checking SHA-256 with VirusTotal..."
    )

    vt_result = virustotal_lookup(
        file_hashes["SHA-256"]
    )

    display_virustotal_result(
        vt_result
    )


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print(
        "=== SOC Hash Investigation Tool ==="
    )

    print(
        "\n[1] Identify and investigate an existing hash"
    )

    print(
        "[2] Calculate hashes from a file"
    )

    choice = input(
        "\nSelect an option (1/2): "
    ).strip()

    if choice == "1":

        investigate_hash()

    elif choice == "2":

        investigate_file()

    else:

        print(
            "\n[-] Invalid option"
        )

        print(
            "[!] Please select 1 or 2"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()