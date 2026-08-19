# NTLM Lateral Movement Detection

## MITRE ATT&CK
**Technique:** T1550.002 — Use Alternate Authentication Material: Pass the Hash

## Objective
Detect potentially suspicious lateral movement by identifying successful NTLM network authentication from the same source IP to multiple target hosts using a non-machine account.

## Data Source
- Microsoft Sentinel
- `SecurityEvent`

## Detection Logic

The query:
1. Searches for successful Windows logons using **Event ID 4624**.
2. Filters for **Logon Type 3**, representing network authentication.
3. Identifies authentication using the **NTLM** authentication package.
4. Excludes machine accounts ending with `$`.
5. Excludes local loopback addresses.
6. Groups authentication activity by **account and source IP address**.
7. Counts the number of distinct target hosts accessed by the account.
8. Flags activity where the same account and source IP access **3 or more target hosts**.
9. Returns the affected hosts and the first and last observed authentication activity.

## KQL

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where Account !endswith "$"
| where IpAddress !in ("127.0.0.1", "::1", "-")
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetHosts = dcount(Computer),
    Hosts = make_set(Computer, 50)
    by Account, IpAddress
| where TargetHosts >= 3
| project
    FirstSeen,
    LastSeen,
    Account,
    IpAddress,
    TargetHosts,
    Hosts
| order by TargetHosts desc
```

## Detection Flow

```text
Successful Windows Logon
        ↓
Event ID 4624
        ↓
Logon Type 3
        ↓
NTLM Authentication
        ↓
Non-Machine Account
        ↓
Same Source IP
        ↓
Multiple Target Hosts
        ↓
3+ Target Hosts
        ↓
Potential Lateral Movement
```

## Example

An account authenticates using NTLM from the same source IP:

- Account: `adminuser`
- Source IP: `10.10.10.25`

During the observed period, the account successfully authenticates to:

- SERVER01
- SERVER02
- SERVER03
- SERVER04

Because the same account and source IP accessed **3 or more target hosts using NTLM**, the activity is flagged for further investigation.

## False Positives
- Legacy applications using NTLM
- Legitimate administrative activity
- File server access
- Approved management tools
- Service accounts
- Applications that require NTLM authentication
- Older systems that do not support Kerberos

## Tuning
- Establish a baseline of legitimate NTLM authentication.
- Identify applications that legitimately require NTLM.
- Exclude approved administrative infrastructure where appropriate.
- Monitor privileged accounts more closely.
- Adjust the target-host threshold based on the environment.
- Correlate with source device and process activity.
- Correlate with PsExec, WMI, SMB, or other remote administration activity.
- Investigate unusual NTLM usage where Kerberos would normally be expected.

## Related Techniques

- **T1550 — Use Alternate Authentication Material**
- **T1550.002 — Use Alternate Authentication Material: Pass the Hash**
- **T1021 — Remote Services**
- **T1078 — Valid Accounts**
- **T1078.002 — Valid Accounts: Domain Accounts**
