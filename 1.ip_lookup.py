import ipaddress
import requests


def ipapi_lookup(ip):
    url = f"https://ipapi.co/{ip}/json/"

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "SOC-Investigation-Toolkit/1.0"},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            if data.get("error"):
                return None

            return {
                "source": "ipapi.co",
                "ip": data.get("ip"),
                "country": data.get("country_name"),
                "region": data.get("region"),
                "city": data.get("city"),
                "org": data.get("org"),
                "asn": data.get("asn")
            }

        if response.status_code == 429:
            print("[!] ipapi.co rate limit reached")
            print("[*] Trying fallback IP intelligence source...")

        return None

    except requests.RequestException:
        return None


def ipinfo_lookup(ip):
    url = f"https://ipinfo.io/{ip}/json"

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "SOC-Investigation-Toolkit/1.0"},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            return {
                "source": "ipinfo.io",
                "ip": data.get("ip"),
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "org": data.get("org"),
                "asn": None
            }

        return None

    except requests.RequestException:
        return None


def main():
    print("=== SOC IP Investigation Tool ===")

    ip_input = input("Enter an IP address: ").strip()

    try:
        ip = ipaddress.ip_address(ip_input)

        print("\n[+] Valid IP address")
        print(f"[+] Version: IPv{ip.version}")

        if ip.is_private:
            print("[+] Type: Private IP")
            print("[!] Private IP - no public intelligence lookup performed.")
            return

        if ip.is_loopback:
            print("[+] Type: Loopback IP")
            return

        if ip.is_reserved:
            print("[+] Type: Reserved IP")
            print("[!] Reserved IP - public intelligence lookup not performed.")
            return

        print("[+] Type: Public IP")
        print("\n[*] Gathering IP intelligence...")

        data = ipapi_lookup(str(ip))

        if data is None:
            data = ipinfo_lookup(str(ip))

        if data:
            print("\n=== IP Intelligence ===")
            print(f"Source     : {data['source']}")
            print(f"IP Address : {data['ip']}")
            print(f"Country    : {data['country']}")
            print(f"Region     : {data['region']}")
            print(f"City       : {data['city']}")
            print(f"ISP/Org    : {data['org']}")
            print(f"ASN        : {data['asn'] or 'Not provided'}")

        else:
            print("\n[-] Unable to retrieve public IP intelligence")
            print("[!] External intelligence services are unavailable or rate limited.")

    except ValueError:
        print("\n[-] Invalid IP address")


if __name__ == "__main__":
    main()