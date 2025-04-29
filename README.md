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
![Screenshot 2025-04-28 at 23-54-25 Advanced hunting - Microsoft Defender](https://github.com/user-attachments/assets/c81bb33c-13a8-4084-ad8c-84ac7917b3ee)


---

## 🔧 Steps Taken

The following steps were carried out to respond to and mitigate the brute-force attack:

1. **Identified Unauthorized Login Attempts**
   - Detected 16 failed logon events on the system `window-stiggy`
   - Isolated 12 unique external IP addresses as the source
   - Noted abnormal volume from IP `95.214.55.202` (86 attempts)

2. **Performed IP Reputation Analysis**
   - Geo-located IPs using public IP lookup services
   - Identified multiple high-risk IPs from known hosting providers (e.g., JSC Selectel)

3. **Created Indicators of Compromise (IoCs)**
   - Documented all attacker IPs, attempt counts, ISPs, and threat levels
   - Mapped Event ID `4625` as the primary detection log

4. **Deployed Firewall Blocks**
   - Developed and executed a PowerShell script to block all malicious IPs via Windows Defender Firewall
   - Grouped rules under `Blocked Malicious IPs` for easy management

5. **Hardened Access Controls**
   - Reviewed and reinforced local security policies:
     - Strong password enforcement
     - Account lockout thresholds
     - Disabled unused or default accounts
     - Consideration of MFA implementation

6. **Enabled Monitoring and Alerting**
   - Enabled logging and alerting for repeated login failures
   - Began monitoring for future access attempts from foreign or known TOR exit nodes

7. **Documented the Incident**
   - Compiled full threat report in Markdown format
   - Included all IoCs, detection context, and remediation steps for audit/compliance

---




