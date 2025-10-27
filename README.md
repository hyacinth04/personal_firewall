# 🔥 Personal Firewall using Python

A lightweight, CLI-based personal firewall built using **Python** and **Scapy**.  
It monitors, filters, and logs incoming and outgoing packets based on configurable rules defined in a JSON file.

---

## ⚙️ Features
- Sniffs packets in real-time using Scapy  
- Blocks traffic based on IP, port, or protocol  
- Displays live console logs of ALLOWED/BLOCKED packets  
- Customizable rules via `rules.json`  
- Runs entirely in user-space — no kernel modifications required  

---

## 🧩 Tech Stack
- Python 3  
- Scapy  
- JSON  
- Linux (Kali OS)

---

## 🚀 How to Run
```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip install scapy

git clone https://github.com/<your-username>/personal-firewall-python.git
cd personal-firewall-python

sudo python3 firewall_sniffer.py

