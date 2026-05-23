# Detection 007 — System Information Discovery

## ATT&CK Mapping
- Tactic: Discovery (TA0007)
- Technique: T1082 — System Information Discovery

## Test Source
Atomic Red Team — T1082 Test 1

## What I Observed
Atomic Red Team executed systeminfo.exe via cmd.exe on the Windows target.
The command dumped full system profile including OS version, hardware,
network configuration, and hotfix inventory.

Telemetry captured by Elastic Defend:
- process.name: systeminfo.exe
- process.command_line: systeminfo
- process.parent.name: cmd.exe
- host.name: detection-targe
- user.name: vboxuser

## Detection Tool
Elastic Defend endpoint.events.process + KQL rule in Elastic SIEM

## KQL Detection Rule
event.dataset: "endpoint.events.process" AND process.name: "systeminfo.exe"

## Why This Matters
Systeminfo.exe is a native Windows binary used by attackers immediately
after initial access to understand the target environment. Seeing it run
outside of normal administrative activity is a strong indicator of
post-exploitation discovery activity.

## False Positive Considerations
Low-medium risk. IT administrators occasionally run systeminfo for
troubleshooting. Tune by excluding known admin accounts or scheduled
task contexts if false positives appear.

## Response Recommendation
Investigate what preceded systeminfo execution. Check for initial access
indicators — phishing, exploit, or lateral movement. Review all process
activity from the same user session within 30 minutes of this alert.
