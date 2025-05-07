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





