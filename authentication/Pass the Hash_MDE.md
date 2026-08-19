# NTLM Authentication to Multiple Devices

## MITRE ATT&CK
**Technique:** T1550.002 — Use Alternate Authentication Material: Pass the Hash

## Objective
Detect potentially suspicious lateral movement by identifying successful NTLM network authentication from the same account and source IP address to multiple target devices within a short time window.

## Data Source
- Microsoft Defender for Endpoint
- `DeviceLogonEvents`

## Detection Logic

The query:
1. Searches for successful logon activity using **ActionType `LogonSuccess`**.
2. Filters for **Network** logons.
3. Identifies authentication using the **NTLM** protocol.
4. Groups authentication activity by **account, source IP address, and 1-hour time window**.
5. Counts the number of distinct target devices accessed by the same account and source IP.
6. Collects the affected devices for investigation.
7. Flags activity where the same account and source IP access **5 or more target devices within 1 hour**.
8. Returns the first and last observed authentication activity.
9. Orders the results by the number of target devices accessed.

## KQL

```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where Protocol == "NTLM"
| summarize
    TargetDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccountName, RemoteIP, bin(TimeGenerated, 1h)
| where TargetDevices >= 5
| order by TargetDevices desc

## Detection Flow
```text
Successful Network Logon
        ↓
Network Logon Type
        ↓
NTLM Authentication
        ↓
Same Account + Source IP
        ↓
1-Hour Time Window
        ↓
Multiple Target Devices
        ↓
5+ Target Devices
        ↓
Potential Lateral Movement
```

## Example
An account authenticates using NTLM from the same source IP:

- Account: `adminuser`
- Source IP: `10.10.10.25`

During a 1-hour window, the account successfully authenticates to:
- SERVER01
- SERVER02
- SERVER03
- SERVER04
- SERVER05
- SERVER06

Because the same account and source IP accessed **5 or more target devices using NTLM within 1 hour**, the activity is flagged for further investigation.

## False Positives
- Legitimate administrative activity
- Helpdesk or IT support operations
- Software deployment systems
- Configuration management tools
- Backup infrastructure
- Monitoring systems
- Service accounts accessing multiple systems
- Legacy applications requiring NTLM
- Approved automation
- Vulnerability scanning or management infrastructure

## Tuning
- Establish a baseline of legitimate NTLM authentication.
- Adjust the **5-device threshold** based on the environment.
- Adjust the **1-hour time window** based on normal administrative activity.
- Identify applications and systems that legitimately require NTLM.
- Exclude approved management infrastructure where appropriate.
- Monitor privileged accounts more closely.
- Establish separate baselines for administrative and standard accounts.
- Correlate with source device and process activity.
- Correlate with PsExec, WMI, SMB, or other remote administration activity.
- Investigate unusual NTLM usage where Kerberos would normally be expected.

## Related Techniques

- **T1550 — Use Alternate Authentication Material**
- **T1550.002 — Use Alternate Authentication Material: Pass the Hash**
- **T1021 — Remote Services**
- **T1021.002 — SMB/Windows Admin Shares**
- **T1047 — Windows Management Instrumentation**
- **T1078 — Valid Accounts**
- **T1078.002 — Valid Accounts: Domain Accounts**
