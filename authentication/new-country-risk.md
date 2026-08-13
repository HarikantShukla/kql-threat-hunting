# New Country Sign-in/login with Elevated Risk

## MITRE ATT&CK
**Technique:** T1078.004 — Valid Accounts: Cloud Accounts

## Objective
Detect potentially compromised cloud accounts by identifying successful sign-ins from countries not previously observed for the user, combined with medium or high sign-in risk.

## Data Source
- Microsoft Sentinel
- `SigninLogs`

## Detection Logic
The query:

1. Builds a **30-day baseline** of countries previously used by each user.
2. Excludes the most recent 24 hours from the baseline.
3. Identifies successful sign-ins during the last **24 hours**.
4. Compares the current sign-in country against the user's historical countries.
5. Uses a `leftanti` join to identify previously unseen countries.
6. Filters for **medium or high aggregated sign-in risk**.
7. Returns the new-country authentication activity for investigation.

## KQL

```kql
let Baseline = 30d;
let KnownCountries =
SigninLogs
| where TimeGenerated between (ago(Baseline) .. ago(1d))
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| distinct UserPrincipalName, Country;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=leftanti KnownCountries
    on UserPrincipalName, Country
| where RiskLevelAggregated in ("medium", "high")
| project
    TimeGenerated,
    UserPrincipalName,
    Country,
    IPAddress,
    RiskLevelAggregated,
    AppDisplayName

## False Positives

- Legitimate business travel
- Remote work from a new location
- VPN or proxy usage
- Corporate network egress
- Cloud-based authentication infrastructure
- New users without sufficient historical baseline
- Newly deployed applications
- Temporary changes in user location

## Tuning

- Adjust the baseline period based on the environment.
- Maintain trusted corporate VPN and proxy ranges.
- Consider known business travel patterns.
- Establish sufficient user authentication history.
- Correlate with device familiarity and authentication method.
- Consider user and application context.
- Correlate with MFA status and sign-in risk.
- Exclude known trusted infrastructure where appropriate.

## Related Techniques

- **T1078 — Valid Accounts**
- **T1078.004 — Valid Accounts: Cloud Accounts**
