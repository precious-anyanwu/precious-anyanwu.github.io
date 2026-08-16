# SOC Phishing Investigation — Microsoft Account Verification

## Credential Phishing Analysis and Post-Click Investigation

---

## 1. Investigation Overview

This case study presents a hypothetical SOC investigation involving a phishing email impersonating Microsoft Security.

The exercise was designed to evaluate how a SOC analyst moves from:

```text
Suspicious Email
      ↓
Sender Analysis
      ↓
Authentication Analysis
      ↓
URL Investigation
      ↓
User Interaction
      ↓
Endpoint Investigation
      ↓
Identity Investigation
      ↓
Impact Assessment
````

The objective was not simply to determine whether the email was malicious, but to determine:

* Why the message was malicious
* Whether authentication results changed the assessment
* Whether the user was actually compromised
* What telemetry should be investigated after the click
* How the SOC should contain the threat
* How to distinguish exposure from confirmed compromise

---

# 2. Scenario

The SOC received a report concerning a suspicious Microsoft 365 security email.

### Email

```text
From:
Microsoft Security <security@microsoft-login-alert.com>

To:
j.smith@company.com

Subject:
URGENT: Your Microsoft 365 account will be suspended

Date:
14 August 2026 08:42 UTC
```

### Email Body

```text
Microsoft Security Alert

Your Microsoft 365 account requires immediate verification.

Our security system detected unusual activity associated
with your account.

If you do not verify your account within 24 hours,
access to your mailbox will be suspended.

Verify your account here:

https://microsoft-login-alert.com/verify

Microsoft Security Team
```

The user reported that they clicked the link because they were concerned that their account would be disabled.

The user stated that the resulting Microsoft-style login page was closed before credentials were entered.

---

# 3. Email Authentication Results

The message returned:

```text
SPF: PASS
DKIM: PASS
DMARC: PASS
```

At first glance, these results might appear reassuring.

However, authentication passing does **not** establish that an email is legitimate.

SPF, DKIM and DMARC primarily provide evidence about whether the message was authorized/authenticated according to the sending domain's configured policies.

An attacker-controlled domain can also have properly configured email authentication.

Therefore:

```text
SPF PASS
DKIM PASS
DMARC PASS
```

does not automatically mean:

```text
BENIGN
```

The authentication results must be evaluated together with the sender domain, email content, URL infrastructure and user interaction.

---

# 4. First Point of Suspicion

## Suspicious Sender Domain

The first major indicator was:

```text
security@microsoft-login-alert.com
```

The sender presents itself as Microsoft Security, but the domain:

```text
microsoft-login-alert.com
```

is not an official Microsoft-owned domain.

This creates a strong brand-impersonation indicator.

The display name:

```text
Microsoft Security
```

does not establish legitimacy.

The domain behind the sender address is considerably more important.

---

# 5. URL Investigation

The email contained:

```text
https://microsoft-login-alert.com/verify
```

The URL redirected to:

```text
microsoft-login-alert.com/verify
        ↓
login-microsoft365-security.com/auth
```

The resulting page was designed to resemble a Microsoft 365 authentication page.

It requested:

```text
Email address
Password
```

This significantly increased confidence that the objective of the campaign was credential harvesting.

The investigation therefore moved beyond:

> "This looks like a suspicious email."

to:

> "The email contains infrastructure designed to impersonate Microsoft and solicit authentication credentials."

---

# 6. Assessment

## Verdict: Malicious

I assess the email as a **credential-phishing attempt**.

The assessment is based on the combination of:

1. Microsoft impersonation
2. A sender domain unrelated to Microsoft's legitimate infrastructure
3. Urgency designed to pressure the user into acting
4. A suspicious authentication URL
5. Redirection to another Microsoft-themed domain
6. A fake Microsoft 365 login page
7. Collection of email addresses and passwords

The SPF, DKIM and DMARC passes do not overturn this assessment.

Instead, they indicate that the email was successfully authenticated according to the relevant domain configuration.

---

# 7. User Interaction and Compromise Assessment

This is where the investigation requires careful distinction.

The available evidence establishes:

```text
Email received
      ↓
Link clicked
      ↓
Phishing page displayed
      ↓
User reports closing page
      ↓
No confirmed credential submission
```

Therefore, based on the currently available evidence:

### Confirmed

* Malicious email received
* User clicked the phishing URL
* Phishing page was accessed

### Not confirmed

* Credentials were submitted
* Credentials were stolen
* Microsoft account was compromised
* Malware was downloaded
* Endpoint was compromised

I would therefore describe the user as **exposed to a credential-phishing attempt**, rather than declaring the account compromised.

However, the user's statement should not be treated as the only source of truth.

The SOC should verify the claim using telemetry.

---

# 8. Why User Statements Are Not Sufficient

A user may genuinely believe they did not submit credentials.

However, the SOC should verify the situation independently.

The investigation should determine whether authentication activity occurred after the phishing interaction.

For example:

```text
Phishing click
      ↓
Credential submission?
      ↓
Successful authentication?
      ↓
Unusual source IP?
      ↓
New device?
      ↓
Impossible travel?
      ↓
Session/token activity?
```

The absence of a user-reported password submission does not eliminate the possibility of compromise.

---

# 9. Immediate Containment

My first containment action would be to block the malicious sender/domain and prevent further delivery or interaction with the phishing infrastructure.

### Priority actions

```text
1. Block sender/domain
        ↓
2. Search mail gateway for matching messages
        ↓
3. Remove/quarantine matching emails
        ↓
4. Block malicious URLs/domains
        ↓
5. Investigate affected user's endpoint
        ↓
6. Investigate identity authentication
```

The email gateway should be searched for other recipients.

This is important because a phishing campaign rarely targets only one employee.

---

# 10. Enterprise-Wide Email Search

I would search the email security platform for:

```text
microsoft-login-alert.com
login-microsoft365-security.com
```

and other available indicators from the message.

The objective would be to identify:

* Other recipients
* Delivery status
* Click activity
* Additional messages from the sender
* Other related URLs
* Potentially compromised users

If additional copies are found, they should be quarantined or removed before other employees interact with them.

---

# 11. Endpoint Investigation

Because the user clicked the URL, I would investigate the endpoint for evidence of additional activity.

Relevant telemetry would include:

### Sysmon Event ID 1

Process creation.

I would look for unexpected processes spawned around the time of the click.

For example:

```text
Browser
   ↓
powershell.exe
   ↓
unknown.exe
```

would require immediate investigation.

### Sysmon Event ID 3

Network connections.

I would investigate whether the endpoint established unexpected connections following the phishing interaction.

### Sysmon Event ID 11

File creation.

I would determine whether the phishing interaction resulted in:

* File downloads
* Executables
* Scripts
* Archives
* Other suspicious files

### Windows Event ID 4688

Process creation telemetry would provide additional visibility into processes launched around the event.

---

# 12. Identity Investigation

The next major investigation area would be the user's Microsoft account.

I would investigate authentication activity around and after the phishing event.

Questions include:

* Did the account authenticate after the click?
* Was there a successful login from an unusual IP?
* Was a new device observed?
* Was MFA challenged?
* Was MFA successfully completed?
* Were there unusual geographic locations?
* Were sessions created from unfamiliar devices?
* Were mailbox or account settings modified?

The objective is to determine whether:

```text
Phishing Exposure
```

became:

```text
Credential Compromise
```

or:

```text
Account Takeover
```

---

# 13. Splunk Investigation

If relevant endpoint telemetry is available in Splunk, I would begin by investigating activity around the phishing event.

For example:

```spl
index=wineventlog earliest=-2h latest=+2h
(EventCode=4688 OR EventCode=4624 OR EventCode=4625)
| table _time host EventCode AccountName ParentImage NewProcessName CommandLine Source_Network_Address
| sort _time
```

I would then pivot into:

```text
Account
    ↓
Host
    ↓
LogonGUID
    ↓
ProcessGUID
    ↓
Network activity
```

The exact query would depend on the fields available in the environment.

---

# 14. Investigation Questions

The investigation should answer:

### Email

* Who else received the message?
* Was the message delivered successfully?
* Were there additional related emails?

### URL

* What domains were involved?
* Where did the URL redirect?
* Was the page collecting credentials?
* What infrastructure hosted the phishing page?

### Endpoint

* Did the user download anything?
* Did any suspicious process execute?
* Did the browser spawn unusual child processes?
* Were there unexpected network connections?

### Identity

* Did the user authenticate after clicking?
* Were there unusual successful logins?
* Were sessions created from unfamiliar locations or devices?
* Was MFA triggered or bypassed?

### Impact

* Was the account compromised?
* Was mailbox data accessed?
* Were rules or forwarding settings created?
* Did the attacker attempt further activity?

---

# 15. Preliminary Severity

## Severity: High

I would initially assign a **High preliminary severity** because:

* The email is assessed as malicious.
* The user interacted with the phishing URL.
* The destination requested authentication credentials.
* The attack directly targeted an enterprise identity.

However, severity should be refined as additional evidence becomes available.

There is an important distinction between:

```text
High-risk exposure
```

and:

```text
Confirmed account compromise
```

At the current stage, the evidence supports the former.

If authentication logs demonstrate that stolen credentials were subsequently used, the incident severity and scope should be escalated accordingly.

---

# 16. Recommended Detection Improvements

This case also demonstrates several opportunities for improving detection.

### Email Security

Detect:

* Microsoft impersonation
* Newly observed sender domains
* Lookalike domains
* Credential-harvesting URLs
* Microsoft-themed domains outside Microsoft's legitimate infrastructure

### Endpoint

Correlate:

```text
Phishing URL click
      ↓
Browser activity
      ↓
File creation
      ↓
Process execution
      ↓
Network connection
```

### Identity

Alert on:

```text
Phishing interaction
      ↓
Successful authentication
      ↓
Unusual source/device/location
```

This type of correlation can help identify account compromise following phishing activity.

---

# 17. Lessons Learned

The most important lesson from this investigation is that **email authentication is only one part of the investigation**.

A message can pass:

```text
SPF
DKIM
DMARC
```

and still be malicious.

The analyst must correlate:

```text
Sender
   ↓
Authentication
   ↓
Domain
   ↓
URL
   ↓
User interaction
   ↓
Endpoint
   ↓
Identity
   ↓
Impact
```

Another important lesson is the distinction between **exposure and compromise**.

A user clicking a phishing link is serious, but it does not automatically prove that credentials were stolen.

The SOC must investigate the evidence before making that determination.

---

# 18. Final Analyst Assessment

### Verdict

**Malicious — Credential Phishing**

### User Status

**Exposed; compromise not currently confirmed**

### Primary Risks

* Credential theft
* Microsoft 365 account takeover
* Session/token compromise
* Follow-on identity attacks

### Immediate Actions

```text
Block malicious sender/domain
        ↓
Search and remove campaign emails
        ↓
Block phishing URLs/domains
        ↓
Investigate endpoint telemetry
        ↓
Review identity authentication
        ↓
Continue monitoring the affected account
```

---

# 19. SOC Analyst Takeaway

This exercise reinforced an important SOC investigation principle:

> **Do not stop at identifying the phishing email. Determine what happened after the user interacted with it.**

The real investigation begins when we ask:

```text
Did they click?
      ↓
Did they submit credentials?
      ↓
Did the account authenticate elsewhere?
      ↓
Did the endpoint execute anything?
      ↓
Did the attacker gain persistence?
      ↓
Was organizational data accessed?
```

That progression turns a phishing alert into a defensible incident assessment.

---

# Skills Demonstrated

Through this investigation, I practiced:

* Phishing analysis
* Email authentication analysis
* Sender/domain investigation
* URL and redirect analysis
* Credential-phishing detection
* User interaction assessment
* Windows endpoint telemetry analysis
* Splunk investigation methodology
* Identity investigation
* Incident severity assessment
* Containment planning
* SOC reporting

---

# Conclusion

This hypothetical investigation strengthened my understanding of how a SOC analyst should investigate phishing beyond simply identifying a malicious email.

The key objective is to establish the complete chain:

**Email → Interaction → Endpoint → Identity → Impact**

By separating confirmed evidence from assumptions, the analyst can avoid both underestimating a potential compromise and prematurely declaring an account compromised without supporting evidence.

---

## Author

**Precious Anyanwu**

Cybersecurity Learner | SOC Analyst Path | Splunk SIEM Practice

```
