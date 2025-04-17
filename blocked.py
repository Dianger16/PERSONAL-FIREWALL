import requests
import json
import re

def extract_ips(text):
    # Match IPv4 addresses
    return re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)

def fetch_from_sources():
    sources = [
        # 1. Abuse.ch Feodo Tracker
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",

        # 2. Firehol Level 1 Blocklist (safe, clean IPs to block)
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",

        # 3. Emerging Threats IPs
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",

        # 4. Binary Defense Artillery Honeypot Feed
        "https://www.binarydefense.com/banlist.txt"
    ]

    all_ips = set()
    for url in sources:
        try:
            print(f"[*] Fetching from {url}")
            response = requests.get(url, timeout=10)
            ips = extract_ips(response.text)
            all_ips.update(ips)
        except Exception as e:
            print(f"[!] Failed to fetch from {url}: {e}")

    return list(all_ips)

def generate_rules_json(ips, ports):
    rules = {
        "blocked_ips": ips[:1000],  # Truncate to first 1000 for performance
        "blocked_ports": ports
    }
    with open("rules.json", "w") as f:
        json.dump(rules, f, indent=2)
    print(f"[+] rules.json created with {len(rules['blocked_ips'])} IPs and {len(ports)} ports.")

if __name__ == "__main__":
    print("🚀 Collecting bad IPs from public threat feeds...")
    ip_list = fetch_from_sources()

   # Replace existing port list in the script with:
blocked_ports = [
    7, 20, 21, 22, 23, 25, 26, 37, 42, 43, 49, 53, 67, 68, 69, 79, 80, 110, 111, 113,
    119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 427, 443, 445, 465, 500,
    512, 513, 514, 515, 520, 523, 540, 554, 587, 593, 631, 636, 873, 902, 989, 990,
    993, 995, 1024, 1025, 1080, 1352, 1433, 1521, 1723, 1755, 1812, 1813, 1900, 2049,
    2100, 2222, 2375, 2376, 2483, 2484, 3306, 3389, 3690, 4333, 4444, 4500, 4786,
    5000, 5060, 5061, 5432, 5555, 5631, 5632, 5900, 6000, 6379, 6660, 6661, 6662,
    6663, 6664, 6665, 6666, 6667, 6697, 6881, 7000, 7070, 7100, 7777, 8000, 8008,
    8080, 8081, 8086, 8443, 8888, 9000, 9090, 9200, 9300, 9999, 10000, 27017
]

generate_rules_json(ip_list, blocked_ports)
