import json
import subprocess
from datetime import datetime
import os 

def log_event(messages):
    with open("log.txt","a") as log_file:
        log_file.write(f"{datetime.now()} - {messages}\n")

def load_rules():
    with open("rules.json", "r") as f:
        rules = json.load(f)
    return rules["blocked_ips"], rules["blocked_ports"]

def block_ip(ip):
    rule_name = f"Block_IP_{ip}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ]
    subprocess.run(" ".join(cmd), shell=True)
    log_event(f"Applied firewall rule to block IP: {ip}")

def block_port(port):
    rule_name = f"Block_Port_{port}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        "protocol=TCP",
        f"localport={port}",
        "enable=yes"
    ]
    subprocess.run(" ".join(cmd), shell=True)
    log_event(f"Applied firewall rule to block Port: {port}")

def apply_rules(ips, ports):
    for ip in ips:
        block_ip(ip)

    for port in ports:
        block_port(port)

if __name__ == "__main__":
    print("🚀 Loading firewall rules...")
    blocked_ips, blocked_ports = load_rules()
    print(f"[+] Blocking {len(blocked_ips)} IPs and {len(blocked_ports)} ports...")
    apply_rules(blocked_ips, blocked_ports)
    print("[✅] Firewall rules applied and logged.")
