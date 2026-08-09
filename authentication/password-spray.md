# Password Spray Detection

## MITRE ATT&CK
**Technique:** T1110.003 — Password Spraying

## Objective
Detect authentication activity where a single source IP attempts authentication against multiple user accounts with a relatively low number of failures per account.

## Data Source
- Microsoft Sentinel
- `SigninLogs`

## Detection Logic
Password spraying differs from traditional brute force because the attacker typically tries a small number of common passwords against many accounts to avoid account lockouts.

The query looks for:
- Multiple targeted user accounts
- Multiple failed authentication attempts
- A single source IP
- A low number of failures per individual account

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
| project IPAddress, FailedAttempts, TargetUsers, SuccessfulLogins= coalesce(SuccessfulLogins, 0), Users
| order by TargetUsers desc, FailedAttempts desc 
