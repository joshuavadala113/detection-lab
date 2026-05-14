# Detection Lab

## Stack
- **Sensor OS:** WSL2 Ubuntu 22.04 on Windows 11
- **IDS:** Suricata (Docker) → EVE JSON logs
- **NSM:** Zeek (Docker) → conn, dns, http, ssl logs
- **Agent:** Elastic Agent 8.13 via Fleet
- **SIEM:** Elastic Cloud (free tier)

## Architecture
Suricata and Zeek monitor eth0 inside Docker containers.
Elastic Agent ships logs from both tools to Elastic Cloud via Fleet.
All detections are written in KQL and mapped to MITRE ATT&CK.

## Detections
| # | Technique | ATT&CK ID | Tool | Write-up |
|---|-----------|-----------|------|----------|
| 001 | PurpleFox C2 Beacon — hex .moe URI | T1071.001 | Suricata | [link](detections/001-purplefox-c2/README.md) |
| 002 | Qakbot C2 Check-in — numeric .dat URI | T1071.001 | Suricata | [link](detections/002-qakbot-c2/README.md) |
| 003 | Emotet C2 POST — multipart form-data | T1071.001 | Suricata | [link](detections/003-emotet-c2/README.md) |
| 004 | IcedID C2 — suspicious TLD SSL/SNI | T1071.001, T1573.002 | Zeek + KQL | [link](detections/004-icedid-c2/README.md) |
| 005 | Cobalt Strike HTTP Beacon — short URI burst | T1071.001, T1001 | Suricata | [link](detections/005-cobalt-strike-beacon/README.md) |
