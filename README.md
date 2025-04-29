<h1 align="center">🚨 Brute-Force Attack Report</h1>
<p align="center">
  Unauthorized login attempts detected targeting <strong>window-stiggy</strong>.<br>
  Analysis, Indicators of Compromise (IoCs), and defensive actions documented below.
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/af6fe8c4-d85e-4f35-9907-b771a3110e0d" alt="Brute-force Attacks Banner" width="100%">
</p>


---

## 📝 Summary

This report documents a series of **unauthorized brute-force login attempts** targeting a system named `window-stiggy`. A total of **16 failed login attempts** were detected across **12 unique external IP addresses**, with one IP (`95.214.55.202` from Poland) attempting access **86 times**, indicating a likely brute-force or credential stuffing attack.

The source IPs span multiple countries, with a notable cluster originating from Russian hosting provider **JSC Selectel**, a known source of malicious traffic. Indicators of compromise include repeated logon failures (`Event ID 4625`), abnormal remote IP connections, and logon attempts against common system accounts.

### 🛡️ Response Actions

- ✅ **Blocked all offending IPs** using Windows Firewall
- ✅ **Hardened login security** (strong passwords, account lockouts, MFA)
- ✅ **Enabled monitoring** for future failed logins and unauthorized TOR usage

> This report includes a PowerShell script to automate blocking of all identified malicious IPs and provides context for detection and incident response.


DeviceLogonEvents
| where DeviceName == "window-stiggy"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts

---




