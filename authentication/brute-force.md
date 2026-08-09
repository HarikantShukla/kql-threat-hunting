# Brute Force Authentication Detection
## MITRE ATT&CK
**Technique:** T1110 — Brute Force

## Objective
Identify source IP addresses generating a high volume of failed authentication attempts that may indicate brute-force activity.

## Data Source
- Microsoft Sentinel
- `SigninLogs`

## Detection Logic
The hunt looks for multiple failed authentication attempts from the same source IP within a defined time window.

```kql

let FailureThreshold = 10;
let TimeWindow = 15m;
let FailedLogins = 
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != 0
| Summarize FailedAttempts =count(),
            LastFailure = max(TimeGenerated)
    by UserprincipalName, IPAddress
| where FailedAttempts >= FailureThreshold;
let SuccessfulLogins = 
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| project UserPrincipalName, IPAddress, SuccessTime=TimeGenerated;
FailedLogins
| join kind=inner SuccessFulLogins on UserPrincipalName, IPAddress
| where SuccessTime between (LastFailure .. LastFailure + TimeWindow)
| project SuccessTime, UserPrincipalName, IPAddress, FailedAttempts, LastFailure
| order by FailedAttempts desc
