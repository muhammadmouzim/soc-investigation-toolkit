import ipaddress
import requests

print("=== SOC IP Investigation Tool ===")

ip_input = input("Enter an IP address: ").strip()

try:
    ip = ipaddress.ip_address(ip_input)

    print("\n[+] Valid IP address")
    print(f"[+] Version: IPv{ip.version}")

    if ip.is_private:
        print("[+] Type: Private IP")
        print("[!] Private IP - no public geolocation lookup performed.")

    else:
        print("[+] Type: Public IP")
        print("\n[*] Gathering IP intelligence...")

        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()

            print("\n=== IP Intelligence ===")
            print(f"IP Address : {data.get('ip')}")
            print(f"Country    : {data.get('country_name')}")
            print(f"Region     : {data.get('region')}")
            print(f"City       : {data.get('city')}")
            print(f"ISP/Org    : {data.get('org')}")
            print(f"ASN        : {data.get('asn')}")

        else:
            print(f"[-] API request failed")
            print(f"[-] Status code: {response.status_code}")
            print(f"[-] Response: {response.text}")

except ValueError:
    print("\n[-] Invalid IP address")

except requests.RequestException as error:
    print(f"\n[-] Network error: {error}")