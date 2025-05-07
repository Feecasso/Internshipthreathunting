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






![Screenshot 2025-05-07 at 13-41-48 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/9416e72b-ae1c-4365-b8b9-e77683ab6688)
![Screenshot 2025-05-07 at 13-47-21 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/e0bb63bb-53db-44d1-9179-a66874105026)
