# Detection Gap 001 — LSASS Credential Dump (T1003.001)

## ATT&CK Mapping
- Tactic: Credential Access (TA0006)
- Technique: T1003.001 — OS Credential Dumping: LSASS Memory

## Tests Attempted
- T1003.001 Test 1 — ProcDump: Access denied
- T1003.001 Test 2 — comsvcs.dll: Access denied
- T1003.001 Test 4 — NanoDump: Payload not installed

## What Happened
All LSASS memory dump attempts were blocked by Windows Credential Guard
and Elastic Defend. No process telemetry was generated because the
processes were terminated before execution completed.

## Why This Is a Gap
My current detection stack cannot detect LSASS dump attempts that are
blocked at the OS level. The attempt itself generates no observable
telemetry in endpoint.events.process or endpoint.events.security.

## How to Close This Gap
1. Enable Windows Security event ID 4656 (handle request to LSASS)
   via advanced audit policy — this fires even when access is denied
2. Use Sysmon Event ID 10 (ProcessAccess) which fires when any process
   attempts to open a handle to lsass.exe regardless of success
3. KQL rule: event.dataset: "windows.sysmon_operational" AND
   winlog.event_data.TargetImage: "*lsass.exe*"

## Lesson Learned
Blocked attacks still leave traces — but in different telemetry sources
than successful attacks. Detection engineers need coverage across both
success and failure paths.
