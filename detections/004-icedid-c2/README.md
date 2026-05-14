# Detection 004 — IcedID C2 via Suspicious TLD SSL Connections

## ATT&CK Mapping
- Tactic: Command and Control
- Technique: T1071.001 — Application Layer Protocol: Web Protocols
- Technique: T1573.002 — Encrypted Channel: Asymmetric Cryptography

## Malware Family
IcedID (Bokbot) — a banking trojan and loader. Commonly delivered via malspam,
used to load Cobalt Strike and ransomware.

## PCAP Source
malware-traffic-analysis.net — 2021-03-19 IcedID infection traffic (carved)

## What I Observed
The infected host made repeated HTTPS connections to a single IP (165.227.28.47)
using four different domains, all with uncommon TLDs:
- agitopinaholop.uno (5 connections)
- dedupomoshi.space (3 connections)
- twotoiletsr.space (1 connection)
- iporumuski.fun (1 connection)

All domains resolved to the same IP, indicating a single C2 server using
multiple domain aliases. The .uno, .space, and .fun TLDs are cheap throwaway
domains commonly used in malware campaigns. Detected via Zeek ssl.log
server name indication (SNI) field.

## Detection Tool
Zeek ssl.log + Elastic KQL — HTTP content is encrypted so Suricata
content matching is ineffective. SNI field in TLS handshake reveals
the destination domain even over encrypted traffic.

## KQL Detection Rule
event.dataset: "zeek.ssl" AND (
tls.server_name: *.uno OR
tls.server_name: *.space OR
tls.server_name: *.fun OR
tls.server_name: *.top OR
tls.server_name: *.xyz
) AND NOT tls.server_name: *.amazonaws.com

## False Positive Considerations
Medium risk. Some legitimate services use .space and .xyz TLDs.
Tune by maintaining an allowlist of known-good domains using these TLDs.
The combination of uncommon TLD + single resolving IP + no browser context
reduces false positives significantly.

## Response Recommendation
Block outbound connections to 165.227.28.47 at the perimeter.
Investigate the infected host for IcedID persistence mechanisms.
Hunt for additional hosts connecting to the same C2 IP.
Check for secondary payloads — IcedID commonly leads to Cobalt Strike.
