# Brute Force Followed by Successful Authentication

## MITRE ATT&CK
**Technique:** T1110 — Brute Force

## Objective
Detect potential account compromise by identifying repeated failed authentication attempts from the same user and source IP, followed by a successful authentication within a short time window.

## Data Source
* Microsoft Sentinel
* `SigninLogs`

## Detection Logic

The query:
1. Searches the last **24 hours** of authentication activity.
2. Identifies failed sign-ins.
3. Groups failures by **user and source IP**.
4. Flags users with **10 or more failed attempts**.
5. Identifies successful sign-ins from the same user and IP.
6. Checks whether the successful login occurred within **15 minutes** of the last failure.
7. Returns the activity as a potential account-compromise signal.

## KQL

```kql
let FailureThreshold = 10;
let TimeWindow = 15m;
let FailedLogins = 
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    LastFailure = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= FailureThreshold;
let SuccessfulLogins = 
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| project
    UserPrincipalName,
    IPAddress,
    SuccessTime = TimeGenerated;
FailedLogins
| join kind=inner SuccessfulLogins
    on UserPrincipalName, IPAddress
| where SuccessTime between (LastFailure .. LastFailure + TimeWindow)
| project
    SuccessTime,
    UserPrincipalName,
    IPAddress,
    FailedAttempts,
    LastFailure
| order by FailedAttempts desc
```

## Detection Flow

```text
Failed Sign-ins
      ↓
Same User + Same IP
      ↓
10+ Failed Attempts
      ↓
Successful Sign-in
      ↓
Within 15 Minutes
      ↓
Potential Account Compromise
```

## False Positives

* Users repeatedly entering incorrect passwords
* Expired or changed credentials
* Misconfigured applications
* Service accounts
* Automated authentication processes
* Legitimate administrative activity

## Tuning

* Adjust the failure threshold based on the environment.
* Exclude known service accounts where appropriate.
* Exclude trusted automation or application IPs.
* Baseline normal authentication failures.
* Correlate with device, location, MFA, and sign-in risk.

## Related Techniques

* **T1110 — Brute Force**
* **T1110.001 — Password Guessing**
* **T1078 — Valid Accounts**
