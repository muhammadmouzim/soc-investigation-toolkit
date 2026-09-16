import re
from collections import Counter


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
    Extract useful fields from one authentication log line.
    """

    pattern = (
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2}) "
        r"(?P<level>\w+) "
        r"(?P<message>.*?) "
        r"username=(?P<username>\S+) "
        r"ip=(?P<ip>\S+)"
    )

    match = re.search(pattern, line)

    if match:
        return match.groupdict()

    return None


# ============================================================
# LOAD LOG FILE
# ============================================================

def load_logs(filename):
    """
    Read the log file and parse valid log entries.
    """

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

        print(f"[-] Log file not found: {filename}")

    except PermissionError:

        print(f"[-] Permission denied: {filename}")

    except OSError as error:

        print(f"[-] File error: {error}")

    return logs


# ============================================================
# FAILED LOGIN ANALYSIS
# ============================================================

def analyze_failed_logins(logs):

    failed_ips = Counter()

    failed_users = Counter()

    for log in logs:

        if "Failed login" in log["message"]:

            failed_ips[log["ip"]] += 1
            failed_users[log["username"]] += 1

    return failed_ips, failed_users


# ============================================================
# SUCCESSFUL LOGIN ANALYSIS
# ============================================================

def analyze_successful_logins(logs):

    successful_ips = Counter()

    successful_users = Counter()

    for log in logs:

        if "Login successful" in log["message"]:

            successful_ips[log["ip"]] += 1
            successful_users[log["username"]] += 1

    return successful_ips, successful_users


# ============================================================
# SUSPICIOUS EVENT DETECTION
# ============================================================

def detect_suspicious_events(logs):

    suspicious_events = []

    for log in logs:

        message = log["message"].lower()

        if "account locked" in message:

            suspicious_events.append(log)

        elif "failed login" in message:

            suspicious_events.append(log)

    return suspicious_events


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_results(
    logs,
    failed_ips,
    failed_users,
    successful_ips,
    successful_users,
    suspicious_events
):

    print("\n=== SOC Log Analysis ===")

    print(f"[+] Total log entries : {len(logs)}")

    print("\n=== Failed Login Analysis ===")

    if failed_ips:

        for ip, count in failed_ips.items():

            print(
                f"[!] IP {ip} → {count} failed login(s)"
            )

    else:

        print("[+] No failed login attempts detected")

    print("\n=== Failed Login Users ===")

    if failed_users:

        for username, count in failed_users.items():

            print(
                f"[!] User {username} → {count} failed login(s)"
            )

    else:

        print("[+] No failed login users detected")

    print("\n=== Successful Login Analysis ===")

    if successful_ips:

        for ip, count in successful_ips.items():

            print(
                f"[+] IP {ip} → {count} successful login(s)"
            )

    else:

        print("[!] No successful logins detected")

    print("\n=== Successful Login Users ===")

    if successful_users:

        for username, count in successful_users.items():

            print(
                f"[+] User {username} → {count} successful login(s)"
            )

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

        print(
            "[!] HIGH PRIORITY: Repeated failed login "
            "activity detected."
        )

        for ip in high_risk_ips:

            print(
                f"[!] Investigate IP: {ip}"
            )

    elif suspicious_events:

        print(
            "[!] REVIEW REQUIRED: Suspicious events detected."
        )

    else:

        print(
            "[+] No obvious suspicious authentication "
            "activity detected."
        )


# ============================================================
# MAIN PROGRAM
# ============================================================

print("=== SOC Authentication Log Parser ===")

logs = load_logs(LOG_FILE)

if not logs:

    print("\n[-] No valid log entries were found.")

else:

    failed_ips, failed_users = analyze_failed_logins(logs)

    successful_ips, successful_users = analyze_successful_logins(
        logs
    )

    suspicious_events = detect_suspicious_events(logs)

    display_results(
        logs,
        failed_ips,
        failed_users,
        successful_ips,
        successful_users,
        suspicious_events
    )