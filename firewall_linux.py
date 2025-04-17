import subprocess
import json
import logging
from scapy.all import sniff,IP, TCP

#from rules
with open("rules.json") as f:
    rules = json.load(f)

#setting up logger
logging.basicConfig(filename="firewall.log",level=logging.INFO, format="%(asctime)s - %(message)s")

def is_blocked(packet):
    """checking if the packet matches blocked IPS or ports."""
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip in rules["blocked_ips"]:
           return True
    if TCP in packet:
      sport = packet[TCP].sport
      dport = packet[TCP].dport
      if sport in rules["blocked_ports"] or dport in rules["blocked_ports"]:
         return True
    return False

def packet_callback(packet):
    if is_blocked(packet):
        logging.info(f"BLOCKED {packet[IP].src}) -> {packet[IP].dst}")
    else:
        logging.info(f"ALLOWED: {packet[IP].src} -> {packet[IP].dst}")

def apply_iptables_rules():
    print("Applying iptables rules...")
for ip in rules["blocked_ips"]:
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
for port in rules["blocked_ports"]:
    subprocess.call(["iptables","-A","INPUT","-p","tcp","--dport",str(port),"-j","DROP"])

def main():
    apply_iptables_rules()
    print("firewall is now running...Monitoring traffic.")
    sniff(filter="ip",prn=packet_callback,store=False)

if __name__ == "_main_":
    main()