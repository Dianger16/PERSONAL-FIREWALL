from scapy.all import sniff, IP

def show_packet(packet):
    if IP in packet:
        print(f"{packet[IP].src} -> {packet[IP].dst}")

sniff(filter="ip", prn=show_packet, store=False)
