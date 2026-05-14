# Splunk PowerShell Network Correlation Lab

## Detecting Suspicious PowerShell Download Activity Using Sysmon and Splunk

---

# Overview

This project documents a hands-on SOC detection lab focused on identifying suspicious PowerShell activity and correlating process creation events with outbound network connections using Splunk and Sysmon.

The objective of the lab was to simulate attacker-like PowerShell behavior commonly observed during:

* Malware downloads
* Initial access activity
* Command-and-control communication
* Living Off The Land (LOLBins) abuse
* PowerShell-based execution

Using Splunk Enterprise and Sysmon telemetry, I investigated:

* Suspicious PowerShell execution
* Hidden PowerShell activity
* Parent-child process relationships
* Outbound network connections
* Process and network event correlation using ProcessGuid

This lab demonstrates how SOC analysts reconstruct attack activity by correlating multiple event sources.

---

# Lab Environment

## Virtual Machines Used

| Machine       | Purpose                        |
| ------------- | ------------------------------ |
| Ubuntu VM     | Splunk Enterprise Server       |
| Windows VM    | Endpoint telemetry source      |
| Kali Linux VM | Additional SOC lab environment |

---

# Technologies Used

| Tool                       | Purpose                         |
| -------------------------- | ------------------------------- |
| Splunk Enterprise          | SIEM and log analysis           |
| Sysmon                     | Endpoint telemetry collection   |
| Splunk Universal Forwarder | Windows log forwarding          |
| Windows Event Logs         | Security telemetry              |
| PowerShell                 | Suspicious execution simulation |
| CMD                        | Parent process execution        |

---

# Understanding the Detection Scenario

Attackers commonly abuse PowerShell because it:

* Is built into Windows
* Can execute remote content
* Supports hidden execution
* Allows outbound network communication
* Blends with legitimate administrative activity

SOC analysts frequently monitor PowerShell activity for:

* Hidden execution flags
* Encoded commands
* Network connections
* Download activity
* Parent-child process anomalies

---

# LAB — Suspicious PowerShell Download Activity

## Objective

The goal of this lab was to simulate suspicious PowerShell activity involving:

* PowerShell launched from CMD
* Hidden PowerShell execution
* Outbound HTTPS communication
* Potential malware download behavior

The investigation focused on correlating:

* Sysmon Event ID 1 (Process Creation)
* Sysmon Event ID 3 (Network Connection)

---

# PowerShell Command Executed

The following command was executed from CMD:

```powershell
powershell -nop -w hidden -c "iwr https://example.com -UseBasicParsing"
```

This command:

* Launches PowerShell
* Disables PowerShell profile loading using `-nop`
* Executes with a hidden window using `-w hidden`
* Uses `Invoke-WebRequest` (`iwr`)
* Initiates outbound HTTPS communication

This behavior resembles activity commonly observed in real-world attacks.

---

# Screenshot 1 — Suspicious PowerShell Command Executed in CMD

![Suspicious PowerShell Command Executed in CMD](https://precious-anyanwu.github.io/assets/images/splunk-network/powershell-download-command-cmd.png)

---

# Sysmon Event ID 1 — Process Creation Investigation

## Purpose

Sysmon Event ID 1 records process creation activity.

This allows analysts to identify:

* Which process executed
* Parent-child process relationships
* Suspicious command-line arguments
* Hidden PowerShell execution

---

# SPL Query Used

```spl
index=wineventlog EventCode=1 Image="*powershell.exe"
| table _time User ParentImage Image CommandLine ProcessGuid
```

---

# Investigation Findings

The investigation revealed:

## Parent Process

```text
cmd.exe
```

## Child Process

```text
powershell.exe
```

Suspicious observations included:

* Hidden PowerShell execution
* Use of `-nop`
* Use of `Invoke-WebRequest`
* PowerShell launched from CMD
* Potential download behavior

This type of activity is frequently investigated during malware and intrusion analysis.

---

# Screenshot 2 — Sysmon Event ID 1 PowerShell Process Creation

![Sysmon Event ID 1 PowerShell Process Creation](https://precious-anyanwu.github.io/assets/images/splunk-network/sysmon-eventid1-powershell-process.png)

---

# Sysmon Event ID 3 — Network Connection Investigation

## Purpose

Sysmon Event ID 3 records outbound network connections initiated by processes.

This telemetry helps analysts identify:

* Suspicious outbound communication
* Command-and-control traffic
* Malware download activity
* Beaconing behavior
* External connections initiated by PowerShell

---

# SPL Query Used

```spl
index=wineventlog EventCode=3 Image="*powershell.exe"
| table _time User Image DestinationIp DestinationPort ProcessGuid
```

---

# Investigation Findings

The network investigation revealed:

* powershell.exe initiating outbound HTTPS communication
* Destination IP visibility
* Destination port 443 activity
* Correlation with the same ProcessGuid observed in Event ID 1

This demonstrated how process creation and network telemetry can be linked together during investigations.

---

# Screenshot 3 — Sysmon Event ID 3 PowerShell Network Connection

![Sysmon Event ID 3 PowerShell Network Connection](https://precious-anyanwu.github.io/assets/images/splunk-network/sysmon-eventid3-powershell-network-connection.png)
---

# Correlating Process Creation and Network Activity

## Why Correlation Matters

One of the most important SOC investigation skills is event correlation.

Attack investigations rarely rely on a single log.

Instead, analysts correlate:

* Process execution
* Network activity
* Authentication events
* File activity
* Endpoint telemetry

In this lab, I correlated Sysmon Event IDs 1 and 3 using:

```text
ProcessGuid
```

This allowed me to reconstruct the full activity chain.

---

# Correlation SPL Query

```spl
index=wineventlog (EventCode=1 OR EventCode=3)
ProcessGuid="{PASTE-GUID-HERE}"
| table _time EventCode ParentImage Image CommandLine DestinationIp DestinationPort User
```

---

# Correlation Findings

By correlating both events, I observed:

```text
cmd.exe
      └── powershell.exe
              └── outbound HTTPS connection
```

The correlation showed:

* The originating process
* Suspicious PowerShell arguments
* The outbound network connection
* Destination communication details
* Unified attack activity tied to a single ProcessGuid

This mirrors how SOC analysts investigate suspicious PowerShell activity in real environments.

---

# Screenshot 4 — Correlated PowerShell Process and Network Activity

![Correlated PowerShell Process and Network Activity](https://precious-anyanwu.github.io/assets/images/splunk-network/correlated-powershell-network-activity.png)


![ProcessGuid Correlation Filter](https://precious-anyanwu.github.io/assets/images/splunk-network/processGUID-filter.png)

---

# Why This Detection Is Important

This detection technique is highly valuable because attackers frequently use PowerShell for:

* Malware downloads
* Payload staging
* Remote command execution
* Credential theft tools
* Command-and-control communication
* Evasion techniques

Hidden PowerShell execution combined with outbound network communication is a common detection scenario in modern SOC environments.

---

# Skills and Knowledge Gained

Through this project, I gained practical experience in:

* PowerShell threat detection
* Sysmon analysis
* Splunk SPL searches
* Event correlation
* Parent-child process investigation
* Network connection analysis
* ProcessGuid correlation
* Threat hunting concepts
* SOC investigation workflows

---

# Challenges Encountered

Some challenges encountered during the lab included:

* Understanding Sysmon event structure
* Correlating multiple event types
* Interpreting PowerShell command-line arguments
* Understanding ProcessGuid usage
* Distinguishing suspicious vs legitimate PowerShell activity

Resolving these challenges improved my investigative and analytical skills.

---

# Future Improvements

Future improvements planned for this lab include:

* Detecting encoded PowerShell commands
* Building Splunk detection dashboards
* Creating PowerShell correlation alerts
* Simulating command-and-control traffic
* Investigating additional LOLBins
* Expanding network telemetry monitoring

---

# Conclusion

This lab improved my understanding of how SOC analysts investigate suspicious PowerShell activity using Splunk and Sysmon.

By correlating process creation events with network connection telemetry, I gained practical experience in:

* PowerShell monitoring
* Process analysis
* Event correlation
* Threat hunting workflows
* Suspicious network activity detection
* SOC investigation techniques

This project strengthened my understanding of how multiple telemetry sources are combined to reconstruct attacker behavior in modern security operations environments.

---

Splunk, SIEM, Sysmon, PowerShell Detection, Event Correlation, Event ID 1, Event ID 3, Threat Hunting, SOC Analyst, Blue Team, Windows Telemetry, ProcessGuid, Security Monitoring, PowerShell Network Connection, Detection Engineering

---

# Author

Precious Anyanwu

Cybersecurity Learner | SOC Analyst Path | Splunk SIEM Practice
