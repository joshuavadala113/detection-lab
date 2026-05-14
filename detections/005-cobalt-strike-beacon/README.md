# Detection 005 — Cobalt Strike HTTP Beacon

## ATT&CK Mapping
- Tactic: Command and Control
- Technique: T1071.001 — Application Layer Protocol: Web Protocols
- Technique: T1001 — Data Obfuscation

## Malware Family
Cobalt Strike — a commercial adversary simulation tool widely abused by
ransomware groups, APTs, and criminal actors as a post-exploitation framework.

## PCAP Source
malware-traffic-analysis.net — 2021-02-02 Hancitor with Ficker Stealer,
Cobalt Strike, and NetSupport RAT

## What I Observed
The infected host (10.2.2.101) made 2,102 HTTP GET requests to a single IP
(192.254.79.71) using a 3-character URI path /ptj at regular intervals.
This is the Cobalt Strike default HTTP beacon check-in pattern — short random
URI, high frequency, no user-initiated browsing context.

Additionally, periodic POST requests to /submit.php?id=242569267 on the same
IP — this is the beacon's tasking response channel, used to send results
back to the Cobalt Strike team server.

Traffic breakdown:
- 192.254.79.71 → 2,102 GET /ptj (beacon heartbeat)
- 192.254.79.71 → 3 POST /submit.php?id=242569267 (task results)
- 192.254.79.71 → 1 GET /EbHm (secondary beacon URI)

## Detection Logic
Suricata rule with threshold matching — fires when a single destination IP
receives 10+ HTTP GET requests to a short alphabetic URI within 60 seconds.
The threshold suppresses noise while catching the sustained beaconing pattern.

## Rule
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"COBALT STRIKE Beacon - High frequency short URI GET"; flow:established,to_server; http.method; content:"GET"; http.uri; pcre:"/^\/[A-Za-z]{3,5}$/"; threshold:type threshold,track by_dst,count 10,seconds 60; classtype:trojan-activity; sid:9000004; rev:1;)

## False Positive Considerations
Medium risk. Some legitimate APIs use short URI paths. The combination of
high frequency + short random URI + no browser context reduces false positives.
Tune threshold count and interval based on environment baseline.
Consider adding a whitelist of known CDN and API IPs.

## Response Recommendation
Isolate the infected host immediately — Cobalt Strike indicates an active
hands-on-keyboard threat actor, not just malware. Escalate to incident response.
Assume lateral movement has occurred. Hunt for additional beaconing hosts.
Check for Hancitor initial infection vector — likely malspam with Word macro.
