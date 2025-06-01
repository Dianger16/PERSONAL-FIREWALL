# 🔥 Personal Firewall – Python (Windows + Linux)

A cross-platform "Personal Firewall" built with Python to monitor real-time network traffic and block unwanted IPs and ports. 
This project demonstrates practical system security by applying OS-level firewall rules using `netsh` on Windows and `iptables` on Linux. 🔐


 📌 Features

- 🕵️ Real-time packet monitoring using **Scapy**
- 🚫 Block traffic from specific **IP addresses** and **TCP ports**
- ⚙️ Configurable rules via a simple `rules.json` file
- 💻 Works on both **Windows** and **Linux**
- 📁 Logs all activity to `firewall.log`
- 📎 Shows system-level understanding of networking and OS internals

🗂️ Project Structure
personal-firewall/
├── firewall_windows.py # Firewall script for Windows
├── firewall_linux.py # Firewall script for Linux
├── rules.json # Customizable blocked IPs and ports
├── requirements.txt # Python dependencies
├── firewall.log # Log of allowed/blocked traffic
├── README.md # This file
└── .gitignore # To exclude unnecessary files

DEMO VIDEO LINK :- https://www.youtube.com/watch?v=Vee1Q8m_i1c
