# Detection 001 — PurpleFox C2 Beacon

## ATT&CK Mapping
- Tactic: Command and Control
- Technique: T1071.001 — Application Layer Protocol: Web Protocols

## Malware Family
PurpleFox — a rootkit and exploit kit targeting Windows systems.

## PCAP Source
malware-traffic-analysis.net — 2021-01-05 PurpleFox EK and post-infection traffic

## What I Observed
The infected host (10.1.5.101) made HTTP GET requests to three external IPs.
Each request had a URI matching the pattern of exactly 8 uppercase hex characters
followed by .moe — a pattern consistent with randomly generated C2 callback URIs.

C2 servers observed:
- 60.12.109.73 → /BB732D8A.moe
- 59.45.79.40 → /6730A78E.moe
- 58.64.128.29 → /BFA5A83F.moe

The .moe TLD is uncommon in legitimate traffic. Combined with the hex filename
pattern and lack of a browser-like browsing session, this is clearly C2 beaconing.

## Detection Logic
Suricata rule matching HTTP GET requests where the URI is exactly 8 hex characters
followed by .moe — validated against the PCAP, fired on all 3 C2 connections.

## Rule
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PURPLEFOX C2 Beacon - Hex filename .moe URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:".moe"; fast_pattern; pcre:"/^\/[0-9A-F]{8}\.moe$/i"; classtype:trojan-activity; sid:9000001; rev:1;)

## False Positive Considerations
Low risk. The .moe TLD combined with an 8-character hex filename is highly specific.

## Response Recommendation
Block outbound connections to identified C2 IPs. Isolate the infected host.
Investigate for PurpleFox rootkit indicators on the endpoint.
