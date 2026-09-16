import requests

API_KEY = "a31219b5c3f08b8f15e03362e99a17de0c9d1bfbcb45960cdca5b8e2a59d2d38"

file_hash = "44d88612fea8a8f36de82e1278abb02f"

url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)

print("VirusTotal Analysis")
print("-------------------")

print("Status:", response.status_code)

data = response.json()["data"]
attributes = data["attributes"]
stats = attributes["last_analysis_stats"]

print("MD5:", file_hash)
print("SHA-256:", attributes["sha256"])
print("Malicious:", stats["malicious"])
print("Suspicious:", stats["suspicious"])
print("Harmless:", stats["harmless"])
print("Undetected:", stats["undetected"])