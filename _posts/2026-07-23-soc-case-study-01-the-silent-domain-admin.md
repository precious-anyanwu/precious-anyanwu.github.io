---
layout: post
title: "SOC Case Study 01 – The Silent Domain Admin"
date: 2026-07-05
categories: [SOC Case Studies]
tags:
  - Splunk
  - SOC
  - Incident Response
  - Active Directory
  - Windows Security
  - MITRE ATT&CK
---

# SOC Case Study 01 – The Silent Domain Admin

## Investigating Active Directory Reconnaissance, Lateral Movement, and Suspected Data Exfiltration

## Overview

This case study documents a simulated Security Operations Center (SOC) investigation in which multiple Windows Security Events, Sysmon logs and PowerShell telemetry were correlated to determine whether suspicious administrator activity represented legitimate administration or an active compromise.

Unlike previous labs that focused on individual Event IDs, this exercise required reconstructing the complete attack timeline, determining when suspicious behaviour became a security incident, assessing impact, mapping activity to the MITRE ATT&CK framework and recommending containment and recovery actions.

---

## Objectives

- Correlate multiple Windows events into one attack story.
- Identify attacker behaviour across multiple hosts.
- Determine the earliest point of suspicion.
- Decide when to declare an incident.
- Scope affected assets and data.
- Recommend containment and recovery actions.
- Map observed behaviour to MITRE ATT&CK.

---

## Lab Environment

| System | Role |
|--------|------|
| CLIENT01 | User Workstation |
| CLIENT02 | Suspected Compromised Workstation |
| CLIENT03 | User Workstation |
| FILESERVER01 | File Server |
| DC01 | Domain Controller |

---

# Incident Evidence

The following alerts were provided for investigation.

### Event 1
**09:18:02**

```
CLIENT02
Event ID 4624
User: SOCAdmin
Logon Type: 2 (Interactive)
```

### Event 2

```
CLIENT02
Sysmon Event ID 1

Parent:
explorer.exe

Process:
powershell.exe

Command:
whoami
```

### Event 3

```
PowerShell 4104
Get-ADDomain
```

### Event 4

```
PowerShell 4104
Get-ADComputer -Filter *
```

### Event 5

```
PowerShell 4104
Get-ADGroupMember "Domain Admins"
```

### Event 6

```
DC01
Event ID 4769
Service: ldap/DC01
```

### Event 7

```
DC01
Event ID 4769
Service: HOST/DC01
```

### Event 8

```
CLIENT02
Sysmon Event ID 3

powershell.exe

Destination:
192.168.56.10

Port:
389 (LDAP)
```

### Event 9

```
CLIENT02
Event ID 4688

powershell.exe

net use \\FILESERVER01\Finance
```

### Event 10

```
FILESERVER01

4624

SOCAdmin

Logon Type 3

Source:
CLIENT02
```

### Event 11

```
FILESERVER01

4663

Payroll2026.xlsx

ReadData
```

### Event 12

```
FILESERVER01

4663

Payroll2026.xlsx

WriteData
```

### Event 13

```
CLIENT02

4688

Compress-Archive Payroll2026.xlsx Payroll.zip
```

### Event 14

```
CLIENT02

Sysmon Event 3

powershell.exe

172.64.152.44

443
```

### Event 15

```
CLIENT02

4688

Remove-Item Payroll.zip
```

---

# Executive Summary

The investigation identified behaviour consistent with a compromised privileged account performing Active Directory reconnaissance, accessing sensitive financial information, preparing data for exfiltration and attempting to remove forensic evidence.

The activity began with PowerShell-based domain enumeration before progressing to lateral access of FILESERVER01, interaction with a payroll spreadsheet, archive creation, suspicious outbound HTTPS communication and deletion of the archive.

Although individual events could be legitimate, the combined sequence strongly indicated malicious activity requiring immediate incident response.

---

# Timeline Reconstruction

1. SOCAdmin logged onto CLIENT02 interactively.
2. PowerShell was launched and the attacker verified execution context using **whoami**.
3. Active Directory reconnaissance was performed using Get-ADDomain, Get-ADComputer and Get-ADGroupMember.
4. Kerberos service tickets and LDAP communication confirmed interaction with DC01.
5. A connection was established to the Finance share on FILESERVER01.
6. Payroll2026.xlsx was read and modified.
7. The spreadsheet was archived into Payroll.zip.
8. PowerShell established an outbound HTTPS connection to 172.64.152.44.
9. Payroll.zip was deleted, suggesting an attempt to remove evidence.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Discovery | Account & Domain Discovery |
| Discovery | Remote System Discovery |
| Lateral Movement | SMB/Windows Admin Shares |
| Collection | Data from Network Share |
| Collection | Archive Collected Data |
| Exfiltration | Exfiltration over Web Services (Suspected) |
| Defense Evasion | File Deletion |

---

# Earliest Point of Suspicion

The earliest indicator was the execution of **whoami** immediately after interactive logon.

While legitimate, it became suspicious because it was immediately followed by extensive Active Directory enumeration. Together these actions resembled attacker reconnaissance far more than routine administration.

---

# Incident Declaration

The activity became a confirmed security incident once Payroll2026.xlsx was accessed on FILESERVER01.

At this stage confidentiality had been impacted and the attack had progressed beyond reconnaissance into unauthorized access of sensitive business data.

---

# Scope Assessment

**Affected Systems**

- CLIENT02
- FILESERVER01
- DC01

**Affected Account**

- SOCAdmin

**Affected Data**

- Payroll2026.xlsx
- Finance Share

---

# Additional Telemetry

Further investigation should include:

- PowerShell Script Block Logging (4104) to recover executed commands.
- Sysmon Event ID 1 for parent-child process analysis.
- DNS queries to resolve external infrastructure.
- Firewall/Proxy logs to confirm successful exfiltration.
- Event ID 4672 to identify privileged logons.
- Scheduled Tasks, Services and Registry Run Keys to identify persistence.
- EDR telemetry for additional malicious activity.

---

# Containment

Immediate priorities:

1. Isolate CLIENT02.
2. Protect FILESERVER01.
3. Disable SOCAdmin pending investigation.
4. Revoke Kerberos tickets and active sessions.
5. Block outbound communication to the suspicious IP.
6. Preserve forensic evidence before remediation.

---

# Recovery

- Restore affected files if integrity was compromised.
- Reset privileged credentials.
- Validate payroll data.
- Review privileged workstation policies.
- Perform forensic review of affected hosts.

---

# Lessons Learned

This exercise demonstrated that high-confidence detection depends on correlating authentication events, PowerShell telemetry, file access, archive creation and network activity rather than relying on isolated alerts.

Monitoring privileged account usage, Active Directory reconnaissance and archive creation followed by outbound HTTPS communication can significantly improve early detection.

---

# Skills Demonstrated

- Splunk investigation
- Windows Event Log analysis
- Sysmon analysis
- PowerShell investigation
- Active Directory security
- MITRE ATT&CK mapping
- Threat hunting
- Incident response
- Event correlation

---

# Conclusion

This case study simulated the workflow expected of a Tier 1/Tier 2 SOC Analyst. By correlating telemetry from multiple Windows log sources, I reconstructed the attack lifecycle, identified the impact, recommended containment actions and mapped observed behaviour to MITRE ATT&CK.

The exercise reinforced the importance of contextual analysis and event correlation in modern Security Operations Centers.
