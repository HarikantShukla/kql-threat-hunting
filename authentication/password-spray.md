# Password Spray Detection

## MITRE ATT&CK
**Technique:** T1110.003 — Password Spraying

## Objective
Detect potential password spraying by identifying a source IP generating failed authentication attempts against a large number of user accounts within a short time window.

## Data Source
* Microsoft Sentinel
* `SigninLogs`

## Detection Logic
The query:

1. Searches the last **1 hour** of authentication activity.
2. Filters for failed sign-ins.
3. Groups authentication failures by **source IP address**.
4. Counts the number of failed attempts and unique targeted users.
5. Flags IP addresses targeting **15 or more users**.
6. Correlates the source IP with successful sign-ins during the same time window.
7. Returns the targeted accounts and authentication activity for investigation.

## KQL

```kql
let TimeWindow = 1h;
let UserThreshold = 15;
SigninLogs
| where TimeGenerated >= ago(TimeWindow)
| where ResultType != 0
| where isnotempty(IPAddress)
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 100)
    by IPAddress
| where TargetUsers >= UserThreshold
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated >= ago(TimeWindow)
    | where ResultType == 0
    | summarize SuccessfulLogins = count() by IPAddress
) on IPAddress
| project
    IPAddress,
    FailedAttempts,
    TargetUsers,
    SuccessfulLogins = coalesce(SuccessfulLogins, 0),
    Users
| order by TargetUsers desc, FailedAttempts desc
```

## Detection Flow

```text
Single Source IP
       ↓
Failed Sign-ins
       ↓
Multiple User Accounts
       ↓
15+ Targeted Users
       ↓
Check Successful Logins
       ↓
Potential Password Spray
```

## False Positives

* Vulnerability scanners
* Identity or authentication testing
* Misconfigured applications
* Shared proxy infrastructure
* Security testing activities
* Legitimate administrative tools

## Tuning

* Adjust the targeted-user threshold based on the environment.
* Exclude known security scanners and trusted infrastructure.
* Baseline normal authentication behavior.
* Consider source IP reputation and location.
* Correlate with successful authentication and sign-in risk.
* Investigate whether the source IP belongs to a corporate proxy or VPN.

## Related Techniques

* **T1110 — Brute Force**
* **T1110.003 — Password Spraying**
* **T1078 — Valid Accounts**

```
```
