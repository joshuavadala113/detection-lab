# Detection 002 — Qakbot C2 Check-in

## ATT&CK Mapping
- Tactic: Command and Control
- Technique: T1071.001 — Application Layer Protocol: Web Protocols

## Malware Family
Qakbot (Qbot) — a banking trojan and loader active since 2007.
Commonly delivered via malspam, used to load ransomware.

## PCAP Source
malware-traffic-analysis.net — 2021-02-24 Qakbot infection with spambot traffic

## What I Observed
The infected host (10.2.24.101) made HTTP GET requests to 5 different external IPs.
Each URI followed the pattern: /[random_lowercase_path]/[numeric_campaign_id].dat
The numeric suffix 44251798532407400000 was identical across all 5 C2 servers —
this is Qakbot's bot/campaign ID used to identify the infected host to its C2 infrastructure.

C2 servers observed:
- 207.244.235.57 → /nseoqnwbbvmc/44251798532407400000.dat
- 185.182.57.107 → /rmyjq/44251798532407400000.dat
- 136.243.123.152 → /gwixglx/44251798532407400000.dat
- 128.199.91.194 → /noexyryqori/44251798532407400000.dat
- 162.241.252.38 → /xjhuljbqv/44251798532407400000.dat

## Detection Logic
Suricata rule matching HTTP GET requests where the URI matches the pattern
of a lowercase alphabetic path segment followed by a 10+ digit numeric .dat filename.
Fired on all 5 C2 connections.

## Rule
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"QAKBOT C2 Checkin - Numeric .dat URI pattern"; flow:established,to_server; http.method; content:"GET"; http.uri; pcre:"/\/[a-z]+\/[0-9]{10,}\.dat$/i"; classtype:trojan-activity; sid:9000002; rev:1;)

## False Positive Considerations
Medium risk. Legitimate .dat file downloads exist but the combination of a purely
lowercase random-looking path and a long numeric filename is uncommon in normal traffic.
Tune by adding known-good destinations to an exclusion list if needed.

## Response Recommendation
Isolate the infected host immediately. Block all 5 C2 IPs at the perimeter.
Search for the Qakbot campaign ID in other host logs to identify additional infections.
