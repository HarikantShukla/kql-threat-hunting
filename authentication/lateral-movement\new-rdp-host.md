# New RDP Host Activity

## MITRE ATT&CK
**Technique:** T1021.001 — Remote Services: Remote Desktop Protocol

## Objective
Detect potentially suspicious RDP activity by identifying user accounts accessing multiple hosts that were not previously associated with the account during the historical baseline period.

## Data Source
- Microsoft Defender for Endpoint
- `DeviceLogonEvents`

## Detection Logic
The query:

1. Builds a **30-day baseline** of hosts previously accessed by each account.
2. Excludes the most recent 24 hours from the historical baseline.
3. Focuses on **Remote Interactive** logons associated with RDP activity.
4. Excludes system, service, and default Windows accounts.
5. Identifies account and host combinations not present in the historical baseline using a `leftanti` join.
6. Counts the number of new hosts accessed by each account during the last **1 hour**.
7. Flags accounts accessing **10 or more previously unseen hosts**.
8. Returns the affected hosts and the first and last observed activity.

## KQL

```kql
let BaselinePeriod = 30d;
let DetectionWindow = 1h;
let HostThreshold = 10;
let HistoricalHosts =
DeviceLogonEvents
| where TimeGenerated between (ago(BaselinePeriod) .. ago(1d))
| where AccountName !contains "$"
| where AccountName !startswith "UMFD"
| where AccountName !startswith "DWM"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON")
| where LogonType == "RemoteInteractive"
| distinct AccountName, DeviceName;
DeviceLogonEvents
| where TimeGenerated > ago(DetectionWindow)
| where LogonType == "RemoteInteractive"
| where AccountName !contains "$"
| where AccountName !startswith "UMFD"
| where AccountName !startswith "DWM"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON")
| join kind=leftanti HistoricalHosts
    on AccountName, DeviceName
| summarize
    NewHostCount = dcount(DeviceName),
    Hosts = make_set(DeviceName, 50),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccountName
| where NewHostCount >= HostThreshold
| order by NewHostCount desc
```

## Detection Flow

```text
30-Day Historical Baseline
        ↓
Known Account + Host Pairs
        ↓
New RDP Activity
        ↓
Account Accesses Previously Unseen Hosts
        ↓
10+ New Hosts Within 1 Hour
        ↓
Potential Lateral Movement
```

## Example

An account has historically accessed:

- SERVER01
- SERVER02
- SERVER03

During the last hour, the same account accesses:

- SERVER15
- SERVER16
- SERVER17
- SERVER18
- SERVER19
- SERVER20
- SERVER21
- SERVER22
- SERVER23
- SERVER24

Because these hosts were not previously associated with the account and the number of new hosts reaches the configured threshold, the activity is flagged for investigation.

## False Positives

- Legitimate administrators managing multiple servers
- Helpdesk or IT support activity
- Server maintenance
- Vulnerability assessment activities
- Newly assigned administrative responsibilities
- Temporary changes in account access
- New infrastructure deployments

## Tuning

- Adjust the historical baseline period based on the environment.
- Tune the new-host threshold according to normal administrative activity.
- Exclude approved administrative or service accounts where appropriate.
- Establish separate baselines for privileged and standard accounts.
- Consider server criticality when prioritizing alerts.
- Correlate with the source device and user context.
- Correlate with other lateral movement indicators.

## Related Techniques

- **T1021 — Remote Services**
- **T1021.001 — Remote Services: Remote Desktop Protocol**
- **T1078 — Valid Accounts**
- **T1078.002 — Valid Accounts: Domain Accounts**
