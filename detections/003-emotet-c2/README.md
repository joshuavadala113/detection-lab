# Detection 003 — Emotet C2 POST Beacon

## ATT&CK Mapping
- Tactic: Command and Control
- Technique: T1071.001 — Application Layer Protocol: Web Protocols

## Malware Family
Emotet — a modular banking trojan and malware loader. One of the most prolific
malware families of 2019-2021. Delivered via malspam, used to load Trickbot,
Qakbot, and ransomware.

## PCAP Source
malware-traffic-analysis.net — 2021-01-15 Emotet epoch 1 infection traffic

## What I Observed
The infected host (10.1.15.101) made HTTP POST requests to 3 C2 servers.
Unlike typical web traffic, these POSTs used multipart/form-data encoding
to exfiltrate data and receive commands. URIs were randomly generated
alphanumeric path segments with no consistent structure.

C2 servers observed:
- 200.75.39.254 — 9 POST connections
- 37.187.195.209 — 7 POST connections
- 201.185.69.28 — 2 POST connections

Key indicators:
- HTTP POST (not GET) for C2 — unusual for malware
- multipart/form-data content type with no legitimate form context
- Random alphanumeric URI path segments
- No browser-initiated session context

## Detection Logic
Suricata rule matching HTTP POST requests with multipart/form-data headers
targeting random alphanumeric URI paths. Fired on all 18 C2 connections.

## Rule
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"EMOTET C2 POST - multipart form-data to random URI"; flow:established,to_server; http.method; content:"POST"; http.header; content:"multipart/form-data"; http.uri; pcre:"/^\/[a-z0-9]{8,20}\//i"; classtype:trojan-activity; sid:9000003; rev:1;)

## False Positive Considerations
Medium risk. Legitimate multipart/form-data POSTs exist for file uploads and
web forms. The random URI path pattern reduces false positives significantly.
Tune by whitelisting known-good form submission endpoints.

## Response Recommendation
Isolate the infected host immediately. Block all 3 C2 IPs at the perimeter.
Hunt for Emotet persistence via scheduled tasks and registry run keys.
Check for secondary payloads — Emotet commonly drops Trickbot or Qakbot.
