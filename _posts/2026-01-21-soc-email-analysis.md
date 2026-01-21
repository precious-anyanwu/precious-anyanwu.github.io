---
layout: post
title: "SOC Email Analysis: Investigating a Suspicious Email"
categories: [SOC, Blue Team]
tags: [phishing, email-analysis, cybersecurity]
---

## Introduction

As part of my journey into Security Operations (SOC), I analyzed a suspicious email to identify potential phishing indicators. This post documents the investigation process and key observations from a SOC analyst perspective.

---

## Objective

The goal of this analysis was to:
- Review email headers and metadata
- Identify spoofing or phishing indicators
- Understand how email authentication impacts trust

---

## Analysis Summary

During the analysis, I observed inconsistencies between the sender address and return-path, along with failed or missing authentication checks such as SPF, DKIM, and DMARC.

Multiple mail relay servers were involved, and the originating IP address did not align with the claimed sender domain.

---

## Security Observations

- Sender and return-path mismatch
- Weak or failed authentication results
- Characteristics consistent with phishing attempts

---

## Conclusion

Based on the findings, this email should be treated as potentially malicious. This type of investigation reflects common SOC workflows where analysts must quickly assess risk and recommend action.

---

## Next Steps

Future analysis will include:
- Log correlation
- IOC extraction
- Detection improvements
