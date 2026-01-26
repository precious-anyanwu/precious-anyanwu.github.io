---
title: "Observing Plaintext HTTP Traffic Using Packet Capture"
date: 2026-01-26
categories: [Networking, Security Fundamentals, Traffic Analysis]
---

## 🌐 Project Overview

This lab demonstrates how HTTP traffic is transmitted in plaintext and can be observed using packet capture tools. The objective was to show why unencrypted protocols like HTTP present security risks, as sensitive data can be exposed during transmission.

📄 **Full Technical Report:**  
[Download the Plaintext HTTP Traffic Analysis Report](/assets/reports/plaintext-http-traffic-analysis-report.pdf)

---

## 🧪 Lab Setup

| Role | Tool Used |
|------|-----------|
| Packet Capture | tcpdump |
| Server | Netcat (nc) listening on port 80 |
| Client | Netcat (nc) connecting to localhost |
| Interface | Loopback (lo) |

---

## ⚙️ Packet Capture

```bash
sudo tcpdump -i lo -A

![Packet capture showing plaintext traffic](/assets/images/http-plaintext/tcpdump-plaintext.png)

Server Configuration

nc -lvp 80

![Netcat server listening](/assets/images/http-plaintext/server-listening.png)

Client Connection

nc 127.0.0.1 80 -v

![Netcat client connection](/assets/images/http-plaintext/client-connection.png)

🔍 Key Observation
The captured packets revealed that HTTP traffic is readable in plaintext. Data appeared in ASCII format within tcpdump output, demonstrating the absence of encryption.

🔐 Security Implication

Unencrypted HTTP traffic allows attackers on the network to intercept and read transmitted data. This highlights the importance of HTTPS and TLS encryption.

.

🎯 Skills Demonstrated

Packet capture and inspection

Understanding of plaintext vs encrypted traffic

Security implications of unencrypted protocols

Practical traffic monitoring
