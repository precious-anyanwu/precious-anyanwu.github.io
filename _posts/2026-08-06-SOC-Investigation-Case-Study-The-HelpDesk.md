# SOC Investigation Case Study: The HelpDesk Account

## Investigating Suspicious Active Directory Enumeration and Remote PowerShell Administration

---

## Overview

This case study documents a simulated SOC investigation involving a legitimate-looking helpdesk account, **HelpDesk01**, performing Active Directory enumeration followed by remote PowerShell administration of another workstation.

The investigation was designed to answer an important SOC question:

> **When does legitimate administrative activity become suspicious enough to investigate as potential attacker behaviour?**

Rather than treating individual events as malicious in isolation, the investigation focused on correlating authentication, process creation, PowerShell, Kerberos, WinRM and network telemetry to determine whether the activity represented legitimate helpdesk administration or potential account compromise.

---

# Investigation Scenario

The investigation began with activity observed on **CLIENT14**.

### Initial Event Sequence

```text
09:14:02  CLIENT14
4624
Account: HelpDesk01
Logon Type: 2
```

HelpDesk01 successfully authenticated interactively to CLIENT14.

```text
09:14:09  CLIENT14
4688

explorer.exe
    └── mmc.exe
```

A Microsoft Management Console process was launched.

```text
09:14:15  CLIENT14
4688

mmc.exe
    └── powershell.exe
```

PowerShell was then launched from MMC.

The investigation subsequently identified PowerShell Script Block Logging activity:

```text
09:14:21  CLIENT14
4104

Get-ADComputer -Filter *
```

```text
09:14:29  CLIENT14
4104

Get-ADUser -Filter *
```

```text
09:14:41  CLIENT14
4104

Get-ADGroupMember "Domain Admins"
```

The activity then progressed to the Domain Controller:

```text
09:15:02  DC01
4769

Account: HelpDesk01
Service: ldap/DC01
```

```text
09:15:08  DC01
4769

Account: HelpDesk01
Service: cifs/CLIENT14
```

Additional local enumeration was observed:

```text
09:15:14  CLIENT14
4688

cmd.exe

net localgroup administrators
```

followed by:

```text
09:15:32  CLIENT14
4688

powershell.exe

Get-Service
```

Network telemetry then showed:

```text
09:16:01  CLIENT14
Sysmon Event ID 3

powershell.exe
    ↓
10.0.0.10:5985
```

Port **5985** is commonly associated with Windows Remote Management (WinRM).

Shortly afterwards:

```text
09:16:07  CLIENT14
4688

powershell.exe

Enter-PSSession -ComputerName CLIENT15
```

The remote session resulted in:

```text
09:16:19  CLIENT15
4624

Account: HelpDesk01
Logon Type: 3
Source: CLIENT14
```

The remote PowerShell session then generated:

```text
09:16:24  CLIENT15
4688

wsmprovhost.exe
Parent: svchost.exe
```

and:

```text
09:16:31  CLIENT15
4104

Get-Process
```

```text
09:16:42  CLIENT15
4104

Get-Service
```

---

# 1. First Point of Suspicion

### Event:

```text
09:14:41
CLIENT14
4104

Get-ADGroupMember "Domain Admins"
```

This is the first event that would make me pause and begin active investigation.

The command itself is not malicious. Administrators and helpdesk personnel may legitimately query Active Directory.

However, the **context** increases suspicion.

The sequence was:

```text
HelpDesk01
     ↓
PowerShell
     ↓
Get-ADComputer -Filter *
     ↓
Get-ADUser -Filter *
     ↓
Get-ADGroupMember "Domain Admins"
```

This represents broad Active Directory reconnaissance followed by enumeration of a highly privileged group.

For a SOC analyst, the important distinction is:

> **The command is not inherently malicious; the behaviour and context are what make it suspicious.**

---

# 2. Initial Classification

### Classification: SUSPICIOUS

At this stage, I would classify the activity as **Suspicious**, rather than immediately declaring an incident.

There is not yet enough evidence to demonstrate compromise.

The account is named **HelpDesk01**, which provides a credible legitimate explanation for administrative activity.

A legitimate helpdesk workflow could involve:

```text
HelpDesk01
     ↓
CLIENT14
     ↓
PowerShell
     ↓
Active Directory queries
     ↓
Identify CLIENT15
     ↓
Remote PowerShell session
     ↓
Get-Process
     ↓
Get-Service
```

For example, a helpdesk technician troubleshooting CLIENT15 could legitimately use these commands to identify the computer, inspect its services and investigate a problem.

Therefore, the correct SOC response at this point is:

**Investigate further — do not prematurely escalate.**

---

# 3. The Critical Question: Could This Be Legitimate?

Yes.

The presence of:

```text
Enter-PSSession -ComputerName CLIENT15
```

does not automatically establish malicious lateral movement.

Helpdesk personnel commonly use remote administration technologies to troubleshoot endpoints.

The activity could represent:

* Troubleshooting a workstation
* Investigating a service failure
* Checking running processes
* Performing software maintenance
* Responding to a user support ticket

The key question becomes:

> **Was HelpDesk01 expected to perform this activity from CLIENT14 against CLIENT15 at this time?**

This requires additional context outside the individual security events.

---

# 4. First Splunk Investigation Pivot

My first investigation would establish the complete activity surrounding the suspicious PowerShell enumeration.

A useful initial search would be:

```spl
index=wineventlog
(EventCode=4624 OR EventCode=4688 OR EventCode=4104 OR EventCode=4769 OR EventCode=3)
("HelpDesk01" OR "Get-ADGroupMember" OR "CLIENT14")
| sort _time
```

This provides a broader view of:

* Authentication
* Process creation
* PowerShell activity
* Kerberos activity
* Network communication

I would also investigate a wider time window before and after the alert rather than restricting the investigation to the exact events supplied.

For example:

```spl
index=wineventlog
earliest=-2h latest=+2h
"HelpDesk01"
| sort _time
```

The purpose is to answer:

> **What happened before 09:14 and what happened after 09:16?**

---

# 5. LogonGUID and ProcessGUID Correlation

Once the relevant authentication event has been identified, I would use available identifiers to correlate activity.

### LogonGUID

LogonGUID is useful for answering:

> **Which activity is associated with this authentication session?**

For example:

```text
4624
   ↓
LogonGUID
   ↓
subsequent activity
```

This can help establish whether multiple events belong to the same logon context.

### ProcessGUID

ProcessGUID answers a different question:

> **Which process instance generated or spawned this activity?**

For example:

```text
explorer.exe
      ↓
mmc.exe
      ↓
powershell.exe
      ↓
child process
```

Therefore, I would not rely exclusively on LogonGUID.

I would use:

**LogonGUID → authentication/session context**

and

**ProcessGUID → process execution context**

This provides a stronger investigation model.

---

# 6. CLIENT15: Is This Lateral Movement?

At first glance:

```text
CLIENT14
    ↓
PowerShell
    ↓
Enter-PSSession
    ↓
CLIENT15
    ↓
4624 Type 3
    ↓
wsmprovhost.exe
    ↓
Get-Process
    ↓
Get-Service
```

looks like lateral movement.

However, I would **not immediately classify it as malicious lateral movement**.

The evidence establishes remote administration, but not attacker intent.

The activity is also technically consistent with legitimate WinRM administration.

The presence of:

```text
wsmprovhost.exe
```

on CLIENT15 is particularly important because it is consistent with a remote PowerShell session being hosted through Windows Remote Management.

Therefore:

> **Remote administration has been established, but malicious lateral movement has not yet been established.**

This distinction is important in a real SOC because incorrectly treating legitimate helpdesk activity as an attack can generate significant false positives.

---

# 7. Evidence Required Before Escalation

The next stage of the investigation would focus on establishing whether HelpDesk01 was expected to perform this activity.

## Account Role

I would verify:

* Is HelpDesk01 a legitimate helpdesk account?
* Who is assigned to the account?
* What systems is the account normally permitted to administer?
* Does the account normally use CLIENT14?
* Is CLIENT15 within its support scope?

---

## Change and Ticket Records

I would search the helpdesk/ticketing system for:

* An active ticket involving CLIENT15
* A troubleshooting request
* A scheduled maintenance activity
* A software deployment
* A service investigation

A matching ticket would substantially reduce suspicion.

---

## Historical Behaviour

I would compare the current activity with the account's historical baseline.

Questions include:

* Has HelpDesk01 previously logged into CLIENT14?
* Has it previously administered CLIENT15?
* Does it normally use PowerShell?
* Does it normally use WinRM?
* Has it previously queried Domain Admins?
* Is this activity occurring during normal working hours?

A sudden deviation from the account's normal behaviour would increase risk.

---

# 8. PowerShell Investigation

PowerShell 4104 logs should be reviewed on both CLIENT14 and CLIENT15.

I would specifically look for:

* Encoded commands
* Obfuscated scripts
* Download activity
* Credential access
* Discovery commands beyond normal troubleshooting
* Persistence mechanisms
* Security-control modification
* External network communication

The current commands:

```text
Get-Process
Get-Service
```

are relatively benign and strongly compatible with troubleshooting.

However, if additional commands appeared such as:

```text
Invoke-WebRequest
DownloadString
IEX
Get-Credential
sekurlsa
whoami /all
```

the assessment would change significantly.

---

# 9. WinRM and Network Investigation

The Sysmon Event ID 3 connection to:

```text
10.0.0.10:5985
```

would be investigated to establish whether the destination corresponds to CLIENT15 or another approved management endpoint.

I would verify:

* Destination hostname
* Source process
* Connection frequency
* Whether CLIENT14 normally administers CLIENT15
* Other systems contacted by HelpDesk01
* Whether external destinations were contacted

A connection to an approved internal management endpoint is considerably less concerning than unexpected external communication.

---

# 10. What Happened Before 09:14?

This is one of the most important unanswered questions.

I would investigate the preceding hours for:

* Initial logon
* Failed authentication
* Phishing-related activity
* Suspicious process execution
* Malware alerts
* New services
* Scheduled tasks
* Registry persistence
* Downloads
* Browser activity
* Privilege escalation
* Unusual network connections

If suspicious activity preceded the HelpDesk session, the likelihood of account compromise would increase significantly.

---

# 11. What Happened After 09:16?

I would continue monitoring CLIENT14 and CLIENT15 for:

* Credential dumping
* New persistence
* File creation
* Malware execution
* Additional remote sessions
* Lateral movement to other hosts
* External connections
* Data access
* Security-tool tampering

The current evidence ends shortly after legitimate-looking troubleshooting commands.

Therefore, the investigation should remain open until sufficient surrounding telemetry has been reviewed.

---

# 12. Current Assessment

Based solely on the evidence provided:

### Severity

**Low–Moderate Suspicion**

### Classification

**Suspicious — Pending Validation**

### Confidence

**Moderate**

### Rationale

The strongest suspicious behaviour is the sequence:

```text
Get-ADComputer -Filter *
        ↓
Get-ADUser -Filter *
        ↓
Get-ADGroupMember "Domain Admins"
        ↓
Remote PowerShell
        ↓
CLIENT15
```

However, the account's helpdesk role provides a credible legitimate explanation.

The remote session also performs:

```text
Get-Process
Get-Service
```

which are highly consistent with endpoint troubleshooting.

At present, there is insufficient evidence to confidently classify the activity as malicious.

---

# 13. Conditions That Would Increase Severity

I would escalate the investigation if additional telemetry revealed:

* HelpDesk01 logging into an unusual workstation
* No corresponding support ticket
* After-hours activity inconsistent with the user's schedule
* Credential dumping
* Encoded or obfuscated PowerShell
* Malware execution
* Persistence creation
* Access to unrelated sensitive systems
* External command-and-control communication
* Attempts to disable security controls
* Repeated lateral movement
* Access to sensitive data outside the account's normal responsibilities

The investigation would move from:

**Suspicious → Confirmed Incident**

once evidence demonstrated unauthorized activity or compromise.

---

# 14. SOC Analyst Takeaway

This investigation reinforced an important principle:

> **Context determines whether an event is suspicious.**

A PowerShell command such as:

```text
Get-ADComputer -Filter *
```

is not automatically malicious.

Neither is:

```text
Enter-PSSession -ComputerName CLIENT15
```

nor:

```text
Get-Service
```

But when these events occur together, they create a behavioural pattern that deserves investigation.

At the same time, the presence of a legitimate helpdesk account and a plausible troubleshooting workflow prevents the analyst from prematurely declaring an incident.

The correct SOC approach is therefore:

```text
Detect
   ↓
Investigate
   ↓
Correlate
   ↓
Validate Context
   ↓
Assess Risk
   ↓
Escalate if Evidence Supports It
```

---

# Skills Demonstrated

This investigation strengthened practical skills in:

* Splunk event correlation
* Windows Security Event analysis
* PowerShell 4104 investigation
* Sysmon network telemetry
* Process ancestry analysis
* LogonGUID investigation
* ProcessGUID investigation
* Active Directory reconnaissance detection
* WinRM investigation
* Lateral movement analysis
* False-positive reduction
* SOC triage and escalation decisions

---

# Conclusion

The **HelpDesk01** case demonstrates why effective SOC analysis requires more than identifying suspicious commands.

The initial Active Directory enumeration was concerning, but the legitimate role of the account created an alternative explanation. The subsequent WinRM session to CLIENT15 could represent either attacker lateral movement or legitimate remote administration.

Rather than immediately escalating, the appropriate response is to correlate authentication, process, PowerShell, network and historical activity while validating the account's role and associated support activity.

This investigation reinforced the importance of **behavioural context, historical baselining and evidence-driven escalation** in SOC operations.
