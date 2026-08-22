# Detection 010 — Scheduled Task Persistence via Atomic Red Team

## ATT&CK Mapping
- Tactic: Persistence, Privilege Escalation
- Technique: T1053.005 — Scheduled Task/Job: Scheduled Task

## Test Source
Atomic Red Team — T1053.005 Test 1 (Scheduled Task Startup Script)

## What I Observed
Atomic Red Team successfully created two scheduled tasks on the target system:
- T1053_005_OnLogon — triggers on user logon
- T1053_005_OnStartup — triggers on system startup

Both tasks were created without triggering Defender. Sysmon captured the schtasks.exe process creation event.

Sysmon telemetry:
- EventID: 1 (Process Create)
- Image: C:\Windows\System32\schtasks.exe
- CommandLine: /Create /RU system /SC ONLOGON /TN T1053_005_OnLogon
- User: target-machine\Admin
- ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

## Detection Tool
Sysmon Event ID 1 + KQL

## KQL Detection Rule
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
process.name: "schtasks.exe" AND
process.command_line: (*\/Create* OR *-RegisterScheduledTask*)

## Why This Matters
Scheduled tasks are one of the most common persistence mechanisms used by threat actors including ransomware groups and APTs. They survive reboots, run with elevated privileges, and are often overlooked during incident response.

## False Positive Considerations
Legitimate software frequently creates scheduled tasks during installation. Tune by whitelisting known software installers and IT management tools. Focus on tasks created by user-context processes or PowerShell parents.

## Response Recommendation
Examine the task action immediately. Check the task trigger and run-as user. Cross-reference with software installation logs. If no legitimate software installation explains the task, treat as compromise.
