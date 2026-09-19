import re
from collections import Counter
from ipaddress import ip_address


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = "sample_data/auth.log"
FAILED_LOGIN_THRESHOLD = 3


# ============================================================
# LOG PARSING
# ============================================================

def parse_log_line(line):
    """
    Extract timestamp, level, message, username and IP
    from a security log line.
    """

    pattern = (
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s"
        r"\d{2}:\d{2}:\d{2})\s+"
        r"(?P<level>\w+)\s+"
        r"(?P<message>.*?)\s+"
        r"username=(?P<username>\S+)\s+"
        r"ip=(?P<ip>\S+)"
    )

    match = re.search(pattern, line)

    if match:
        return match.groupdict()

    return None


# ============================================================
# IP CLASSIFICATION
# ============================================================

def classify_ip(ip):
    """
    Determine whether the IP is private/internal or public/external.
    """

    try:
        address = ip_address(ip)

        if address.is_private:
            return "Private / Internal"

        return "Public / External"

    except ValueError:
        return "Unknown"


# ============================================================
# EVENT TYPE
# ============================================================

def determine_event(message):
    """
    Determine the type of authentication event.
    """

    message_lower = message.lower()

    if "failed login" in message_lower:
        return "Failed Login"

    if "login successful" in message_lower:
        return "Successful Login"

    if "account locked" in message_lower:
        return "Account Lockout"

    if "unauthorized" in message_lower:
        return "Unauthorized Access"

    if "connection" in message_lower:
        return "Network Connection"

    return "Other Security Event"


# ============================================================
# SINGLE LOG ANALYSIS
# ============================================================

def analyze_single_log():

    print("\n" + "=" * 60)
    print("                 SINGLE LOG ANALYSIS")
    print("=" * 60)

    line = input("\nEnter security log line:\n> ").strip()

    if not line:
        print("\n[-] No input provided.")
        return

    log = parse_log_line(line)

    if not log:

        print("\n[-] Could not parse this log line.")

        print("\nExpected format:")
        print(
            "2026-09-19 10:15:22 WARN "
            "Failed login username=admin ip=203.0.113.50"
        )

        return

    event_type = determine_event(log["message"])
    ip_type = classify_ip(log["ip"])

    message_lower = log["message"].lower()

    # Determine severity
    if "account locked" in message_lower:
        severity = "HIGH"

    elif "failed login" in message_lower:
        severity = "HIGH"

    elif "unauthorized" in message_lower:
        severity = "HIGH"

    elif log["level"].upper() in ["ERROR", "CRITICAL"]:
        severity = "HIGH"

    elif log["level"].upper() == "WARN":
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # ========================================================
    # DISPLAY
    # ========================================================

    print("\n" + "=" * 60)
    print("                    LOG ANALYSIS")
    print("=" * 60)

    print(f"\nTimestamp       : {log['timestamp']}")
    print(f"Log Level      : {log['level']}")
    print(f"Event Type      : {event_type}")
    print(f"Username        : {log['username']}")
    print(f"Source IP       : {log['ip']}")
    print(f"IP Classification: {ip_type}")
    print(f"Severity        : {severity}")

    print("\n" + "-" * 60)
    print("                 SECURITY INDICATORS")
    print("-" * 60)

    indicators = []

    if "failed login" in message_lower:
        indicators.append("Failed authentication detected")

    if "account locked" in message_lower:
        indicators.append("Account lockout detected")

    if "unauthorized" in message_lower:
        indicators.append("Unauthorized access attempt detected")

    if ip_type == "Public / External":
        indicators.append("External source IP detected")

    if log["username"].lower() in ["admin", "root", "administrator"]:
        indicators.append("Privileged account targeted")

    if indicators:

        for indicator in indicators:
            print(f"[!] {indicator}")

    else:

        print("[+] No obvious suspicious indicators")

    # ========================================================
    # SOC ASSESSMENT
    # ========================================================

    print("\n" + "-" * 60)
    print("                    SOC ASSESSMENT")
    print("-" * 60)

    if severity == "HIGH":

        print("[!] Risk Level   : HIGH")
        print(f"[!] Event        : {event_type}")
        print(f"[!] Source       : {log['ip']}")

        print("\n[!] Recommended Investigation:")

        print("[1] Check previous events from this IP.")
        print("[2] Review activity against the same user account.")
        print("[3] Investigate the source IP using IP Lookup.")
        print("[4] Correlate this event with other security logs.")

    elif severity == "MEDIUM":

        print("[!] Risk Level   : MEDIUM")
        print(f"[!] Event        : {event_type}")

        print("\n[+] Recommended Investigation:")

        print("[1] Monitor this source IP.")
        print("[2] Check for repeated events.")
        print("[3] Correlate with other authentication logs.")

    else:

        print("[+] Risk Level   : LOW")
        print(f"[+] Event        : {event_type}")
        print("[+] No immediate suspicious indicator detected.")

    print("\n" + "=" * 60)


# ============================================================
# FILE ANALYSIS
# ============================================================

def load_logs(filename):

    logs = []

    try:

        with open(filename, "r", encoding="utf-8") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                parsed = parse_log_line(line)

                if parsed:
                    logs.append(parsed)

    except FileNotFoundError:

        print(f"\n[-] Log file not found: {filename}")

    except PermissionError:

        print(f"\n[-] Permission denied: {filename}")

    except OSError as error:

        print(f"\n[-] File error: {error}")

    return logs


# ============================================================
# FULL LOG ANALYSIS
# ============================================================

def analyze_full_log():

    print("\n" + "=" * 60)
    print("                  FULL LOG ANALYSIS")
    print("=" * 60)

    logs = load_logs(LOG_FILE)

    if not logs:

        print("\n[-] No valid log entries found.")
        return

    failed_ips = Counter()
    failed_users = Counter()

    successful_ips = Counter()
    successful_users = Counter()

    suspicious_events = []

    for log in logs:

        message = log["message"].lower()

        if "failed login" in message:

            failed_ips[log["ip"]] += 1
            failed_users[log["username"]] += 1
            suspicious_events.append(log)

        elif "login successful" in message:

            successful_ips[log["ip"]] += 1
            successful_users[log["username"]] += 1

        if "account locked" in message:

            suspicious_events.append(log)

    print(f"\n[+] Total log entries : {len(logs)}")

    print("\n=== Failed Login Analysis ===")

    if failed_ips:

        for ip, count in failed_ips.items():

            print(f"[!] IP {ip} → {count} failed login(s)")

    else:

        print("[+] No failed login attempts detected")

    print("\n=== Failed Login Users ===")

    if failed_users:

        for user, count in failed_users.items():

            print(f"[!] User {user} → {count} failed login(s)")

    else:

        print("[+] No failed login users detected")

    print("\n=== Successful Login Analysis ===")

    if successful_ips:

        for ip, count in successful_ips.items():

            print(f"[+] IP {ip} → {count} successful login(s)")

    else:

        print("[!] No successful logins detected")

    print("\n=== Successful Login Users ===")

    if successful_users:

        for user, count in successful_users.items():

            print(f"[+] User {user} → {count} successful login(s)")

    else:

        print("[!] No successful login users detected")

    print("\n=== Suspicious Events ===")

    if suspicious_events:

        for event in suspicious_events:

            print(
                f"[!] {event['timestamp']} | "
                f"{event['level']} | "
                f"{event['message']} | "
                f"user={event['username']} | "
                f"ip={event['ip']}"
            )

    else:

        print("[+] No suspicious events detected")

    print("\n=== SOC Assessment ===")

    high_risk_ips = [
        ip
        for ip, count in failed_ips.items()
        if count >= FAILED_LOGIN_THRESHOLD
    ]

    if high_risk_ips:

        print("[!] HIGH PRIORITY: Repeated failed login activity detected.")

        for ip in high_risk_ips:
            print(f"[!] Investigate IP: {ip}")

    elif suspicious_events:

        print("[!] REVIEW REQUIRED: Suspicious events detected.")

    else:

        print("[+] No obvious suspicious authentication activity detected.")

    print("\n" + "=" * 60)


# ============================================================
# MAIN MENU
# ============================================================

def main():

    print("\n" + "=" * 60)
    print("             SOC AUTHENTICATION LOG PARSER")
    print("=" * 60)

    print("\n[1] Analyze a single log entry")
    print("[2] Analyze complete log file")
    print("[0] Exit")

    choice = input("\nSelect option: ").strip()

    if choice == "1":

        analyze_single_log()

    elif choice == "2":

        analyze_full_log()

    elif choice == "0":

        print("\n[+] Exiting.")

    else:

        print("\n[-] Invalid option.")


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()
