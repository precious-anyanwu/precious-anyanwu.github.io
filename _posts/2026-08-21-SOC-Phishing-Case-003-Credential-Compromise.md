---

layout: post
title: "SOC Investigation Case Study — Credential Phishing and Microsoft 365 Account Compromise"
date: 2026-08-21
categories: [SOC, Phishing, Incident Response, Microsoft 365]
tags: [phishing, credential-theft, account-compromise, MFA, Microsoft-365, SOC, incident-response]
--------------------------------------------------------------------------------------------------

# 🧪 SOC Phishing Case #003 — Credential Phishing + Possible Account Compromise

## Overview

This investigation analyzes a phishing attack targeting an HR employee through a fake Microsoft password-expiration notification.

Unlike a simple phishing attempt where a user clicks a malicious link but does not provide credentials, this case progressed further. The user entered valid Microsoft 365 credentials, approved an MFA request, and a successful Microsoft 365 authentication subsequently originated from the same infrastructure associated with the phishing activity.

The investigation therefore focuses on determining exactly how far the attack progressed and separating **confirmed credential compromise** from evidence that would be required to prove broader endpoint or account compromise.

---

## Alert Summary

| Field           | Value                                                                         |
| --------------- | ----------------------------------------------------------------------------- |
| User            | Michael Adeyemi                                                               |
| Role            | HR Specialist                                                                 |
| Host            | WS-HR-014                                                                     |
| Alert Time      | 21 Aug 2026, 10:32 UTC                                                        |
| Alert           | Suspicious URL                                                                |
| Sender          | [hr-support@micr0soft-security.com](mailto:hr-support@micr0soft-security.com) |
| Subject         | Action Required: Password Expiration Notice                                   |
| Phishing Domain | micr0soft-security.com                                                        |

---

# 1. Initial Phishing Email

The user received an email claiming that their Microsoft 365 password was about to expire.

### Email

**From:**

`hr-support@micr0soft-security.com`

**Subject:**

`Action Required: Password Expiration Notice`

**Message:**

> Your Microsoft 365 password will expire today.
> Please verify your account to prevent interruption of access.

**URL:**

`https://micr0soft-security.com/verify`

The message used urgency and an account-verification theme to encourage the recipient to click the link.

---

# 2. First Point of Suspicion

The first significant indicator was the phishing domain:

`micr0soft-security.com`

The domain uses **typosquatting/brand impersonation**, replacing the letter `o` in "Microsoft" with the number `0`.

The domain also contains `security.com`, making it appear related to Microsoft security services.

Another important indicator was the domain age.

> **Domain registration age: 11 days**

A newly registered domain combined with Microsoft impersonation and an urgent password-expiration message significantly increases the likelihood of phishing.

### Important observation

The email passed:

| Control | Result |
| ------- | ------ |
| SPF     | PASS   |
| DKIM    | PASS   |
| DMARC   | PASS   |

These results do **not** establish that the sender or domain is legitimate.

Email authentication verifies aspects of domain authorization and message integrity; it does not determine whether the domain itself is trustworthy.

---

# 3. Proxy Investigation

The proxy telemetry shows the user interacting with the suspicious website.

### 10:27:14

```text
michael.adeyemi → 104.21.55.72:443
URL: /verify
User-Agent: Chrome/140.0
```

The user initially accessed the phishing verification page.

### 10:27:22

```text
michael.adeyemi → 104.21.55.72:443
URL: /login
```

The browser was then redirected to a login page.

### 10:28:03

```text
michael.adeyemi → 104.21.55.72:443
URL: /login
HTTP POST observed
```

The HTTP POST is particularly significant because it indicates that information was submitted to the login endpoint.

---

# 4. User Interview

During the investigation, Michael stated:

> "I clicked the link because I thought my password was expiring. The page looked like Microsoft. I entered my username and password. It then asked me to approve an MFA notification, which I did. After that it redirected me to Microsoft 365."

This statement confirms that the user:

1. Clicked the phishing link.
2. Entered their username.
3. Entered their password.
4. Approved an MFA request.
5. Was subsequently redirected to Microsoft 365.

This moves the incident significantly beyond a simple phishing attempt.

---

# 5. Identity Investigation

At **10:28:17**, Microsoft 365 recorded:

```text
Successful authentication

User: michael.adeyemi
Source IP: 104.21.55.72
User-Agent: Chrome
MFA: Satisfied
```

This event occurred only **14 seconds after the HTTP POST** to the phishing login page.

The sequence is highly significant:

```text
10:28:03
Credential submission to phishing infrastructure
        ↓
10:28:17
Successful Microsoft 365 authentication
        ↓
MFA satisfied
```

Combined with the user's admission that credentials were entered and MFA was approved, this provides strong evidence that the credentials were successfully captured and subsequently used.

---

# 6. Subsequent Authentication

At **10:31:42**, another successful Microsoft 365 authentication was recorded:

```text
User: michael.adeyemi
Source IP: 197.210.45.18
User-Agent: Chrome
MFA: Satisfied
```

At **10:32:01**, Microsoft 365 recorded:

```text
Microsoft 365 session established

Source IP: 197.210.45.18
```

This activity requires further investigation because it occurred shortly after the suspicious authentication.

The available telemetry does not, by itself, establish exactly who controlled each session. Therefore, this activity should be correlated with Michael's expected location, device, browser session and normal authentication behavior.

---

# 7. Endpoint Investigation

Endpoint telemetry from `WS-HR-014` showed:

```text
No suspicious process creation
No PowerShell activity
No suspicious file creation
No malware alerts from EDR
```

This is important because the available evidence does **not** currently support an endpoint malware compromise.

The attack appears to have primarily targeted the user's credentials and Microsoft 365 account rather than relying on malware execution on the workstation.

---

# 8. Attack Chain

Based on the available evidence:

```text
Phishing Email
      ↓
Typosquatted Microsoft Domain
      ↓
Phishing Login Page
      ↓
Credential Submission
      ↓
MFA Approval
      ↓
Successful Microsoft 365 Authentication
      ↓
Microsoft 365 Session
```

### Evidence-supported progression

**Email received:** Confirmed

**Phishing URL accessed:** Confirmed

**Credentials submitted:** Confirmed

**MFA approval:** Confirmed

**Credentials subsequently used:** Strongly supported / confirmed by authentication telemetry

**Microsoft 365 account accessed:** Strongly supported

**Endpoint compromise:** Not supported by current evidence

---

# 9. Incident Verdict

### Classification

| Finding               | Assessment                               |
| --------------------- | ---------------------------------------- |
| Phishing attempt      | ✅ Confirmed                              |
| Successful phishing   | ✅ Confirmed                              |
| Credential compromise | 🔴 Confirmed                             |
| Account compromise    | 🔴 Highly likely / supported by evidence |
| Endpoint compromise   | ❌ Not supported                          |
| Malware execution     | ❌ Not observed                           |

The incident should therefore be escalated beyond a phishing-only classification.

The strongest evidence is the combination of:

```text
Credential submission
        +
MFA approval
        +
Successful Microsoft 365 authentication
        +
Subsequent Microsoft 365 session
```

---

# 10. Priority Investigation Steps

As a SOC analyst, I would prioritize the following actions.

### 1. Investigate Microsoft 365 sign-in activity

Review all authentication events surrounding the incident:

* Source IP
* Geographic location
* User-Agent
* Authentication method
* MFA details
* Device information
* Session timestamps

The goal is to determine whether the subsequent activity was legitimate or attacker-controlled.

### 2. Revoke active sessions

Terminate existing Microsoft 365 sessions and revoke active authentication tokens where supported.

This reduces the possibility of an attacker continuing to use an established session.

### 3. Force credential reset

Immediately reset Michael's password and ensure the compromised password cannot continue to be used.

### 4. Investigate MFA activity

Review the MFA approval and authentication-method configuration for:

* Unexpected MFA registrations
* Additional authentication methods
* Suspicious MFA activity
* Repeated MFA prompts

### 5. Search for other phishing victims

Search the email gateway for:

```text
micr0soft-security.com
hr-support@micr0soft-security.com
https://micr0soft-security.com/verify
```

Identify other recipients, clicks and users who may have submitted credentials.

### 6. Investigate Microsoft 365 account activity

Review activity following the suspicious authentication for:

* Mailbox access
* Email forwarding rules
* Inbox rules
* Suspicious outbound messages
* File access
* Privilege changes
* OAuth/application consent
* Additional suspicious sessions

### 7. Contain the phishing infrastructure

Block or quarantine the phishing domain and remove remaining messages containing the malicious indicators.

The IP should be evaluated carefully before blocking because infrastructure such as reverse proxies/CDNs can be shared.

### 8. Continue monitoring

Monitor Michael's identity and endpoint for further authentication anomalies or suspicious activity.

---

# 11. SOC Incident Note

> A staff member from the HR department received a phishing email impersonating Microsoft and was directed to `micr0soft-security.com`, a recently registered typosquatted domain. Proxy telemetry confirmed access to the phishing site, followed by an HTTP POST to its login endpoint at 10:28:03. The user confirmed entering their Microsoft 365 username and password and approving an MFA notification. At 10:28:17, a successful Microsoft 365 authentication was recorded from `104.21.55.72` with MFA satisfied, strongly supporting credential compromise and likely account compromise. A subsequent Microsoft 365 authentication and session were established from `197.210.45.18`, requiring further investigation to determine whether the activity was legitimate or attacker-controlled. No suspicious process creation, PowerShell activity, file creation or EDR malware detection was observed on the endpoint. Recommended containment includes password reset, session/token revocation, MFA review, phishing IOC blocking and enterprise-wide IOC searching, followed by continued monitoring of the affected account.

---

# 12. Lessons Learned

This investigation demonstrates why a SOC analyst should avoid stopping at the initial phishing alert.

The important progression was:

```text
Suspicious Email
      ↓
Malicious Link
      ↓
Credential Submission
      ↓
MFA Approval
      ↓
Successful Authentication
      ↓
Potential Account Takeover
```

A phishing email alone does not necessarily mean compromise.

However, once credentials are submitted and successful authentication occurs shortly afterward, the investigation must shift from **phishing detection** to **identity compromise and account containment**.

Another important lesson is that **MFA satisfaction does not automatically make an authentication legitimate**. In this case, the user was socially engineered into approving the MFA request after submitting credentials.

Finally, the absence of malicious endpoint telemetry is significant. The available evidence indicates a credential-focused attack rather than malware-based workstation compromise.

---

## MITRE ATT&CK Mapping

| Technique                                        | Relevance                                                                 |
| ------------------------------------------------ | ------------------------------------------------------------------------- |
| **T1566.002 — Phishing: Spearphishing Link**     | User received a malicious link designed to capture credentials            |
| **T1056.002 — Input Capture: GUI Input Capture** | Phishing login page captured credentials                                  |
| **T1078 — Valid Accounts**                       | Compromised credentials were used for Microsoft 365 authentication        |
| **T1098 — Account Manipulation**                 | Should be investigated for unauthorized MFA/authentication-method changes |

---

# Conclusion

The investigation confirms a **successful credential-phishing attack** against an HR employee.

The user interacted with a typosquatted Microsoft domain, submitted valid credentials, approved MFA, and a successful Microsoft 365 authentication occurred shortly afterward from infrastructure associated with the phishing activity.

At this stage, **credential compromise is confirmed and account compromise is strongly supported**, while there is insufficient evidence to classify the endpoint as compromised.

## The appropriate SOC response is therefore to contain the identity compromise, investigate post-authentication activity, identify additional victims, remove the phishing infrastructure from the organization's environment, and continue monitoring for further abuse.
