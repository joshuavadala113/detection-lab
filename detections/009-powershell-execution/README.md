# Detection 009 — PowerShell Execution via Atomic Red Team

## ATT&CK Mapping
- Tactic: Execution
- Technique: T1059.001 — Command and Scripting Interpreter: PowerShell

## Test Source
Atomic Red Team — T1059.001 Test 1 (Mimikatz execution via PowerShell)

## What I Observed
Atomic Red Team attempted to launch Mimikatz via PowerShell. Microsoft Defender blocked the execution with "Access is denied", however Sysmon captured the PowerShell process creation event before the block occurred.

Sysmon telemetry:
- EventID: 1 (Process Create)
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CommandLine: Contains encoded/obfuscated Mimikatz invocation
- User: target-machine\Admin
- ParentImage: C:\Windows\System32\cmd.exe

## Detection Tool
Sysmon Event ID 1 + KQL

## KQL Detection Rule
event.provider: "Microsoft-Windows-Sysmon" AND
event.code: "1" AND
process.name: "powershell.exe" AND
process.command_line: (*mimikatz* OR *-enc* OR *EncodedCommand* OR *IEX* OR *Invoke-Expression*)

## Why This Matters
PowerShell is the most commonly abused scripting interpreter by threat actors. Encoded commands and IEX are hallmarks of fileless malware, C2 post-exploitation, and credential theft tools like Mimikatz. Even when execution is blocked by AV, the process creation event provides a high-fidelity detection opportunity.

## False Positive Considerations
Encoded PowerShell commands are used by some legitimate software installers and management tools. Tune by whitelisting known parent processes and signed binaries. Alert on unsigned or user-initiated encoded commands.

## Response Recommendation
Investigate the full command line. Identify the parent process and user context. Check for lateral movement indicators. Assume credential access was attempted even if execution failed.
