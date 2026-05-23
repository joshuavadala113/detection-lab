# Detection 008 — Registry Run Key Persistence

## ATT&CK Mapping
- Tactic: Persistence (TA0003)
- Technique: T1547.001 — Boot/Logon Autostart Execution: Registry Run Keys

## Test Source
Atomic Red Team — T1547.001 Test 1 (Reg Key Run)

## What I Observed
Atomic Red Team used reg.exe to write a value to the CurrentVersion\Run
registry key, establishing persistence that would survive reboots.

Telemetry captured by Elastic Defend:
- registry.key: S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run
- registry.value: Atomic Red Team
- process.executable: C:\Windows\System32\reg.exe
- user.name: vboxuser
- host.name: detection-targe

## Detection Tool
Elastic Defend endpoint.events.registry + KQL rule in Elastic SIEM

## KQL Detection Rule
event.dataset: "endpoint.events.registry" AND
registry.key: "*CurrentVersion\\Run*" AND
process.executable: "*reg.exe*"

## Why This Matters
Registry Run keys are one of the most common persistence mechanisms used
by malware and attackers. Writing to CurrentVersion\Run causes the specified
program to execute every time a user logs in. This is used by RATs, backdoors,
and ransomware to survive reboots.

## False Positive Considerations
Medium risk. Legitimate software installers occasionally write to Run keys.
Tune by whitelisting known-good executables and signed software using
process.code_signature fields.

## Response Recommendation
Identify what value was written and what executable it points to.
Remove the Run key entry and investigate the process that wrote it.
Check for additional persistence mechanisms — attackers rarely use only one.
Hunt for lateral movement from the same host.
