#!/usr/bin/env python3
import json
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

RULES_FILE = "rules.json"
LOG_FILE = "firewall_log.txt"

def load_rules():
    with open(RULES_FILE) as f:
        return json.load(f)

def proto_name_from_num(n):
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(n, f"OTHER({n})")

def is_blocked(packet, rules):
    if IP not in packet:
        return False, "no-ip-layer"
    src = packet[IP].src
    dst = packet[IP].dst
    proto_name = proto_name_from_num(packet[IP].proto)

    if src in rules.get("blocked_ips", []) or dst in rules.get("blocked_ips", []):
        return True, f"ip-block ({src} or {dst})"
    if proto_name in rules.get("block_protocols", []):
        return True, f"proto-block ({proto_name})"

    dport = None
    if TCP in packet:
        dport = packet[TCP].dport
    elif UDP in packet:
        dport = packet[UDP].dport
    if dport and dport in rules.get("blocked_ports", []):
        return True, f"port-block (dport={dport})"
    return False, "allowed"

def packet_callback(packet):
    rules = load_rules()
    blocked, reason = is_blocked(packet, rules)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = proto_name_from_num(packet[IP].proto)
    else:
        src = dst = proto = "N/A"
    status = "BLOCKED" if blocked else "ALLOWED"
    line = f"[{ts}] {src} -> {dst} ({proto}) => {status} [{reason}]"
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

if __name__ == "__main__":
    print("[*] Starting firewall sniffer... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)
