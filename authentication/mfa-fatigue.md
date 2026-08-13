# MFA Fatigue / MFA Bombing Detection

## MITRE ATT&CK
**Technique:** T1621 — Multi-Factor Authentication Request Generation

## Objective
Detect potential MFA fatigue attacks by identifying repeated MFA denials against a user from multiple IP addresses, followed by a successful authentication shortly afterward.

## Data Source
* Microsoft Sentinel
* `SigninLogs`

## Detection Logic
The query:

1. Searches the last **24 hours** of sign-in activity.
2. Identifies MFA-related authentication denials using `ResultType == 500121`.
3. Counts MFA denials for each user.
4. Identifies the number of distinct source IPs generating the denials.
5. Flags users with **5 or more MFA denials from at least 2 IP addresses**.
6. Correlates the MFA denials with a successful login from the same user.
7. Flags a successful authentication occurring within **30 minutes** of the last MFA denial.

## KQL

```kql
let Lookback = 24h;
let DenialThreshold = 5;
let CorrelationWindow = 30m;
let MFADenials =
SigninLogs
| where TimeGenerated > ago(Lookback)
| where ResultType == 500121
| summarize
    DenialCount = count(),
    DistinctIPs = dcount(IPAddress),
    FailureIPs = make_set(IPAddress, 20),
    LastDenied = max(TimeGenerated)
    by UserPrincipalName
| where DenialCount >= DenialThreshold
| where DistinctIPs >= 2;
let Successes =
SigninLogs
| where TimeGenerated > ago(Lookback)
| where ResultType == 0
| project
    UserPrincipalName,
    SuccessTime = TimeGenerated,
    SuccessIP = IPAddress,
    AppDisplayName;
MFADenials
| join kind=inner Successes on UserPrincipalName
| where SuccessTime between (LastDenied .. LastDenied + CorrelationWindow)
| project
    UserPrincipalName,
    DenialCount,
    DistinctIPs,
    FailureIPs,
    SuccessIP,
    SuccessTime,
    AppDisplayName
| order by DenialCount desc
```

## Detection Flow

```text
Multiple MFA Denials
        ↓
5+ Denials
        ↓
2+ Source IPs
        ↓
Same User
        ↓
Successful Authentication
        ↓
Within 30 Minutes
        ↓
Potential MFA Fatigue Attack
```

## False Positives

* Users repeatedly rejecting legitimate MFA requests
* Authentication/application issues
* Mobile device or network changes
* VPN or proxy usage
* Multiple legitimate authentication attempts

## Tuning

* Adjust the denial threshold based on normal user behavior.
* Baseline legitimate MFA rejection patterns.
* Account for corporate VPN and proxy infrastructure.
* Correlate with device information and authentication method.
* Consider user risk, location, and unfamiliar devices.
* Exclude known automation where appropriate.

## Related Techniques

* **T1621 — Multi-Factor Authentication Request Generation**
* **T1078 — Valid Accounts**
