🔎 KQL Threat Hunting
A practical collection of **KQL threat hunting queries** for Microsoft Sentinel and Microsoft Defender, focused on identifying attacker behavior and mapping detections to the **MITRE ATT&CK framework**.

🎯 Objectives
- Develop practical KQL threat hunting queries
- Detect common attacker techniques and behaviors
- Map hunts to MITRE ATT&CK
- Document investigation and tuning considerations
- Build reusable detection logic for SOC investigations

🛡️ Threat Hunting Coverage
| Category | Techniques |
|---|---|
| Authentication | Brute Force, Password Spraying, Valid Accounts |
| Credential Access | Pass-the-Hash, Golden Ticket, Kerberoasting |
| Lateral Movement | PsExec, WMI, RDP |
| Execution | PowerShell, Command Shell |

🧰 Technologies
`Microsoft Sentinel` · `Microsoft Defender` · `KQL` · `MITRE ATT&CK`

📂 Repository Structure

kql-threat-hunting/
├── authentication/
├── credential-access/
├── lateral-movement/
└── execution/

All queries are designed for defensive security research, threat hunting, and educational purposes using authorized environments.
