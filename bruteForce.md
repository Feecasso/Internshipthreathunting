# Brute-Force Login Attempts: Threat Event Report


## ⚠️ Threat Event: External Brute-Force Login Attempts

- **System Targeted**: `window-stiggy`
- **Event Type**: Repeated `LogonFailed` attempts
- **Risk Level**: Moderate to High (depending on frequency & exposure)
- **Attack Pattern**: Distributed brute-force attempts from multiple external IPs

---

## 🧰 Summary of IP Addresses & Behavior

| IP Address        | Country      | City        | ISP / Organization             | Attempt Count | Threat Level |
|------------------|--------------|-------------|--------------------------------|---------------|--------------|
| **95.214.55.202** | Poland       | Warsaw      | MEVSPACE sp. z o.o.            | 86            | High         |
| 186.226.193.102   | Brazil       | São Paulo   | Locaweb Serviços de Internet   | 4             | Moderate     |
| 5.188.159.11      | Russia       | St. Petersburg | JSC Selectel               | 1             | High         |
| 94.26.228.232     | United Kingdom | London    | BT Group                       | 1             | Low          |
| 185.137.233.142   | Russia       | St. Petersburg | JSC Selectel               | 1             | High         |
| 5.182.5.43        | Russia       | St. Petersburg | JSC Selectel               | 1             | High         |
| 92.53.90.122      | Russia       | St. Petersburg | JSC Selectel               | 1             | High         |
| 95.143.191.159    | Russia       | St. Petersburg | JSC Selectel               | 1             | High         |
| 37.48.253.93      | Iraq         | Kirkuk      | EarthLink Telecommunications   | 1             | Moderate     |
| 172.59.146.68     | United States| Tracy, CA   | T-Mobile USA                   | 1             | Low          |
| 188.124.37.22     | Russia       | Moscow      | JSC Selectel                   | 1             | High         |
| 94.26.248.196     | United Kingdom | London    | BT Group                       | 1             | Low          |

---

## Related Queries:
```kql

DeviceLogonEvents
| where DeviceName == "window-stiggy"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts

## 🔍 Indicators of Compromise (IoCs)

### System Logs
- **Event ID**: `4625` (Logon Failure)
- **Logon Type**: Likely 3 or 10 (network/remote interactive)
- **Source IPs**: As listed above
- **Target Account**: Likely `Administrator` or other common accounts

### Behavioral Indicators
- High-frequency login attempts from one IP (e.g. `95.214.55.202`)
- Low-frequency spread across many IPs, indicating a possible distributed or botnet-based attack

---

## ✅ Recommended Actions

### Block & Monitor
- **Block All IPs** listed above (script provided earlier)
- **Monitor** for any new IPs with similar patterns

### Harden Target
- Enforce **strong password policies**
- Disable or rename default accounts (e.g., `Administrator`)
- Apply **Multi-Factor Authentication (MFA)** wherever possible
- Implement **account lockout policies** after multiple failed login attempts

### Network & Host Protections
- Use **Geo-blocking** (if all access is domestic)
- Enable **Endpoint Detection & Response (EDR)** or **Security Information & Event Management (SIEM)** alerts for future `4625` events from new IPs

---

## 🔧 PowerShell Script to Block IPs

```powershell
# List of IPs to block
$blockList = @(
    "95.214.55.202",     # Poland
    "186.226.193.102",   # Brazil
    "5.188.159.11",      # Russia (Selectel)
    "94.26.228.232",     # UK (BT Group)
    "185.137.233.142",   # Russia (Selectel)
    "5.182.5.43",        # Russia (Selectel)
    "92.53.90.122",      # Russia (Selectel)
    "95.143.191.159",    # Russia (Selectel)
    "37.48.253.93",      # Iraq
    "172.59.146.68",     # USA (T-Mobile)
    "188.124.37.22",     # Russia (Selectel)
    "94.26.248.196"      # UK (BT Group)
)

# Rule group name for easy reference
$ruleGroup = "Blocked Malicious IPs"

foreach ($ip in $blockList) {
    New-NetFirewallRule `
        -DisplayName "Block Malicious IP - $ip" `
        -Direction Inbound `
        -RemoteAddress $ip `
        -Action Block `
        -Profile Any `
        -Enabled True `
        -Group $ruleGroup
}

Write-Host "Firewall rules created to block the listed IPs."
