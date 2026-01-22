# PESD — Privilege Escalation Signal Detector (Wazuh + Python)

This project demonstrates how privilege escalation signals can be detected
using custom JSON logs sent from endpoints to Wazuh SIEM.

## 🔗 Detection Pipeline

Endpoint (Windows/Linux)
→ PESD Python Logger (JSONL)
→ Wazuh Agent (localfile json)
→ Wazuh Manager Rules
→ 🚨 Security Alert

## 🎯 Detected Scenarios

- Linux sudo success
- Linux admin group membership change
- Linux SUID binary execution (signal)
- Windows high privilege token assignment (simulated)
- Windows Administrators group addition

Mapped to MITRE ATT&CK:
- T1548 – Abuse Elevation Control Mechanism
- T1098 – Account Manipulation

## ▶️ Demo Usage

### Linux
```bash
mkdir -p /tmp/pesd

python -m pesd.cli --os linux --log /tmp/pesd/pesd-events.jsonl sudo --result success --command "cat /etc/shadow"
