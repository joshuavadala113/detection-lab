\# Detection Lab



A self-hosted detection engineering homelab built to simulate real-world threat detection across network and endpoint telemetry. All detections are mapped to MITRE ATT\&CK.



\## Stack



| Component | Tool | Purpose |

|-----------|------|---------|

| Sensor OS | WSL2 Ubuntu 22.04 on Windows 11 | Host environment |

| IDS | Suricata (Docker) | Network threat detection via EVE JSON |

| NSM | Zeek (Docker) | Network metadata — conn, dns, http, ssl logs |

| Endpoint | Sysmon + Elastic Defend | Windows process and registry telemetry |

| Agent | Elastic Agent 8.13 | Log shipping via Fleet |

| SIEM | Self-hosted Elasticsearch + Kibana (Docker) | Detection rule engine and alerting |



\## Architecture



```

Suricata + Zeek (Docker, network\_mode: host)

&#x20;       ↓ EVE JSON + conn/dns/http/ssl logs

Elastic Agent (Docker)

&#x20;       ↓ Fleet-managed log shipping

Elasticsearch + Kibana (Docker, self-hosted)

&#x20;       ↓ KQL detection rules + alerting

Windows 11 VM (VirtualBox)

&#x20;       ↓ Sysmon + Elastic Defend endpoint telemetry

```



\## ATT\&CK Coverage



!\[ATT\&CK Navigator Heatmap](Detection\_Lab\_Coverage.svg)



\## Detections



| # | Technique | ATT\&CK ID | Tool | Write-up |

|---|-----------|-----------|------|----------|

| 001 | PurpleFox C2 Beacon — hex .moe URI | T1071.001 | Suricata | \[link](detections/001-purplefox-c2/README.md) |

| 002 | Qakbot C2 Check-in — numeric .dat URI | T1071.001 | Suricata | \[link](detections/002-qakbot-c2/README.md) |

| 003 | Emotet C2 POST — multipart form-data | T1071.001 | Suricata | \[link](detections/003-emotet-c2/README.md) |

| 004 | IcedID C2 — suspicious TLD SSL/SNI | T1071.001, T1573.002 | Zeek + KQL | \[link](detections/004-icedid-c2/README.md) |

| 005 | Cobalt Strike HTTP Beacon — short URI burst | T1071.001, T1001 | Suricata | \[link](detections/005-cobalt-strike-beacon/README.md) |

| 006 | PowerShell CreateRemoteThread — Process Injection | T1055 | Sysmon + KQL | \[link](detections/006-powershell-process-injection/README.md) |

| 007 | System Information Discovery — systeminfo.exe | T1082 | Elastic Defend + KQL | \[link](detections/007-system-information-discovery/README.md) |

| 008 | Registry Run Key Persistence | T1547.001 | Elastic Defend + KQL | \[link](detections/008-registry-run-key-persistence/README.md) |



\## Detection Gaps



| Technique | ATT\&CK ID | Gap Reason | Telemetry Status |

|-----------|-----------|------------|-----------------|

| OS Credential Dumping: LSASS Memory | T1003.001 | Blocked by Windows Credential Guard — no process telemetry generated | ⚠️ No signal |



\## Repository Structure



```

detection-lab/

├── detections/               # Individual detection write-ups + KQL rules

│   └── rules\_export.ndjson   # Exported KQL detection rules

├── suricata/                 # Suricata config and custom rules

├── zeek/                     # Zeek logs

├── kibana/                   # Kibana config (encryption keys, settings)

├── scripts/                  # Startup and maintenance scripts

├── attack-navigator-layer.json

└── Detection\_Lab\_Coverage.svg

```

