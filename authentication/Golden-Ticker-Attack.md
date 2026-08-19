# Kerberoasting Detection

## MITRE ATT&CK
**Technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

## Objective
Detect potentially suspicious Kerberos service ticket activity by identifying accounts requesting a high number of service tickets without a corresponding Ticket Granting Ticket request from the same account and source IP.

## Data Source
- Microsoft Sentinel
- `SecurityEvent`

## Detection Logic

The query:
1. Identifies **Event ID 4768**, representing Kerberos Ticket Granting Ticket (TGT) requests.
2. Stores the account, source IP, and TGT request timestamp.
3. Identifies **Event ID 4769**, representing Kerberos service ticket requests.
4. Uses a `leftanti` join to exclude service ticket activity associated with accounts and source IPs that also generated TGT requests.
5. Groups the remaining service ticket requests by **account, source IP, and 1-hour time window**.
6. Counts the number of service tickets requested.
7. Collects the services accessed by the account.
8. Flags activity where more than **10 service tickets are requested within 1 hour**.
9. Returns the account, source IP, service ticket count, and services accessed for investigation.

## KQL

```kql
let TGTRequests =
SecurityEvent
| where EventID == 4768
| project
    TargetUserName,
    IpAddress,
    TGT_Time = TimeGenerated;
SecurityEvent
| where EventID == 4769
| project
    TimeGenerated,
    TargetUserName,
    IpAddress,
    ServiceName
| join kind=leftanti (
    TGTRequests
) on TargetUserName, IpAddress
| summarize
    ServiceTicketCount = count(),
    ServicesAccessed = make_set(ServiceName, 10)
    by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where ServiceTicketCount > 10
| order by ServiceTicketCount desc
```

## Detection Flow

```text
Kerberos Authentication Activity
        ↓
Event ID 4768 — TGT Request
        ↓
Event ID 4769 — Service Ticket Request
        ↓
Compare Account + Source IP
        ↓
Identify Service Ticket Activity
Without Matching TGT Activity
        ↓
1-Hour Time Window
        ↓
More Than 10 Service Tickets
        ↓
Potential Kerberoasting Activity
```

## Example
An account generates multiple Kerberos service ticket requests from the same source IP:

- Account: `user01`
- Source IP: `10.10.10.25`

During a 1-hour window, the account requests service tickets for multiple services:

- `MSSQLSvc/dbserver01`
- `HTTP/webserver01`
- `CIFS/fileserver01`
- `MSSQLSvc/dbserver02`
- `HTTP/webserver02`
- `CIFS/fileserver02`

If the account generates **more than 10 service ticket requests within 1 hour** without a corresponding TGT request from the same account and source IP, the activity is flagged for investigation.

## False Positives

- Legitimate applications requesting multiple Kerberos service tickets
- Service accounts accessing multiple applications
- Automated applications
- Database applications
- Web applications
- File servers
- Enterprise applications using Kerberos
- Administrative activity
- Scheduled tasks generating service ticket requests
- Authentication patterns involving multiple Kerberos services

## Tuning

- Establish a baseline of normal Kerberos service ticket activity.
- Adjust the **10-ticket threshold** based on the environment.
- Adjust the **1-hour detection window** based on normal authentication behavior.
- Identify service accounts that legitimately request multiple service tickets.
- Exclude approved application or automation accounts where appropriate.
- Monitor privileged accounts more closely.
- Correlate service ticket activity with the requested `ServiceName`.
- Prioritize requests involving unusual or sensitive service accounts.
- Correlate with endpoint and authentication activity.
- Investigate unusual bursts of service ticket requests.

## Detection Limitations

A high number of Kerberos service ticket requests does not by itself prove Kerberoasting.

Legitimate applications and service accounts can generate large numbers of service ticket requests.

For stronger detection, correlate this activity with:

- Unusual service ticket volume
- Sensitive service accounts
- Privileged accounts
- Unusual source devices
- Abnormal authentication patterns
- Suspicious process execution
- Credential access indicators
- Service Principal Name (SPN) activity
- Other identity and endpoint telemetry

## Related Techniques

- **T1558 — Steal or Forge Kerberos Tickets**
- **T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting**
- **T1078 — Valid Accounts**
- **T1078.002 — Valid Accounts: Domain Accounts**
