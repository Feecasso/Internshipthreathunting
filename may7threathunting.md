# 🛡️ Threat Hunt Report: Brute Force Attack Detection

**Report Date:** 2025-05-07  
**Detection Tool:** Microsoft Defender for Endpoint  
**Query Language:** Kusto Query Language (KQL)  
**Target Device:** `windows-cyber`

---

## 🎯 Objective

To identify and assess potential brute-force attack activity targeting the endpoint `windows-cyber` by analyzing failed authentication attempts and enriching them with IP intelligence.

---

## 🔍 Methodology

A KQL query was executed to analyze failed login attempts:


let TargetDevice = "windows-cyber";
DeviceLogonEvents
| where DeviceName == TargetDevice
| where ActionType == "LogonFailed"
| project Timestamp, ActionType, DeviceName, AccountName, RemoteIP
| summarize FailedAttempts = count() by RemoteIP
| sort by FailedAttempts desc

A KQL query was executed to analyze failed login attempts:




| Remote IP          | Failed Attempts | Owner / ISP                    | Location              | Notes / Abuse Reports                         |
| ------------------ | --------------- | ------------------------------ | --------------------- | --------------------------------------------- |
| **94.102.52.73**   | 23              | Bytedance / NordVPN            | China                 | VPN usage, anonymized source                  |
| **92.63.197.9**    | 22              | Telkom Internet LTD            | Unknown               | Found in abuse database                       |
| **185.156.73.169** | 20              | Telkom Internet LTD (AS210848) | Lelystad, Netherlands | 2,412 abuse reports, 60% abuse confidence     |
| **185.243.96.116** | 19              | Google                         | Unknown               | Possibly misattributed, further review needed |
| **185.243.96.107** | 16              | GTT Communications Inc.        | Palisades, NY, USA    | Netblock: 185.243.96.0/22                     |


⚠️ Risk Assessment

    Attack Type: Credential-based brute-force attempt

    Source: VPNs, data centers, anonymizing infrastructure

Indicators of Risk:

    High volume of failed login attempts

    Repeated activity from known abusive or obfuscated IPs

    IPs tied to anonymization and hosting services

Potential Impact:

    Account compromise

    Privilege escalation

    Lateral movement

🛠️ Recommended Actions

    Block IPs: Add all identified IPs to firewall and security blocklists.

    Enable Account Lockout: Apply automatic lockouts after defined failed attempts.

    Monitor & Alert: Set up alerts for abnormal failed login rates.

    Audit Logs: Review logs for successful logins from suspect IPs.

    Harden Access Controls: Implement MFA and review least privilege policies.

    Add ASN Watchlist: Monitor ASN AS210848 and similar high-abuse sources.

✅ Summary

A brute-force login attempt targeting the windows-cyber VM was detected. The attack originated from multiple suspicious IP addresses, including VPNs and high-abuse hosting providers. These findings confirm deliberate unauthorized access attempts requiring immediate response.

    Status: 🚨 Active Threat
    Action Required: Block offending IPs, enhance authentication defenses, and audit potentially compromised accounts.
