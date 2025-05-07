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

```kusto
let TargetDevice = "windows-cyber";
DeviceLogonEvents
| where DeviceName == TargetDevice
| where ActionType == "LogonFailed"
| project Timestamp, ActionType, DeviceName, AccountName, RemoteIP
| summarize FailedAttempts = count() by RemoteIP
| sort by FailedAttempts desc

| Remote IP          | Failed Attempts | Owner / ISP                    | Location              | Notes / Abuse Reports                         |
| ------------------ | --------------- | ------------------------------ | --------------------- | --------------------------------------------- |
| **94.102.52.73**   | 23              | Bytedance / NordVPN            | China                 | VPN usage, anonymized source                  |
| **92.63.197.9**    | 22              | Telkom Internet LTD            | Unknown               | Found in abuse database                       |
| **185.156.73.169** | 20              | Telkom Internet LTD (AS210848) | Lelystad, Netherlands | 2,412 abuse reports, 60% abuse confidence     |
| **185.243.96.116** | 19              | Google                         | Unknown               | Possibly misattributed, further review needed |
| **185.243.96.107** | 16              | GTT Communications Inc.        | Palisades, NY, USA    | Netblock: 185.243.96.0/22                     |







