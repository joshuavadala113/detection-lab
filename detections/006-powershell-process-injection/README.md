# Detection 006 — PowerShell Process Injection via CreateRemoteThread

## ATT&CK Mapping
- Tactic: Defense Evasion / Privilege Escalation
- Technique: T1055 — Process Injection

## Test Source
Atomic Red Team — T1059.001 Test 1 (Mimikatz execution attempt)

## What I Observed
Atomic Red Team attempted to execute Mimikatz via PowerShell. Although the
execution failed with "Access is denied", Sysmon Event ID 8 (CreateRemoteThread)
fired — capturing PowerShell attempting to create a thread in another process.

Sysmon telemetry:
- SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- TargetImage: <unknown process>
- Event: CreateRemoteThread detected
- User: DETECTION-TARGE\vboxuser

## Detection Tool
Sysmon Event ID 8 + Elastic KQL rule

## KQL Detection Rule
event.provider: "Microsoft-Windows-Sysmon" AND
event.action: "CreateRemoteThread detected" AND
winlog.event_data.SourceImage: "*powershell.exe"

## Why This Matters
CreateRemoteThread from PowerShell is a high-fidelity indicator of process
injection. Legitimate software almost never injects threads from PowerShell.
This pattern is consistent with Mimikatz, Cobalt Strike, and other offensive
tools that use PowerShell as a loader.

## False Positive Considerations
Low risk. Very few legitimate applications spawn threads from powershell.exe
into other processes. Tune by whitelisting known-good parent processes if
needed in your environment.

## Response Recommendation
Isolate the host immediately. Investigate what process was targeted. Assume
credential theft occurred even if the tool appeared to fail — partial execution
can still dump credentials. Review authentication logs for lateral movement.
