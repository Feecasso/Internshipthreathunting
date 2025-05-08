# 🛡️ Threat Hunting Report: Suspicious Download of TikTok Installer

![tt](https://github.com/user-attachments/assets/ff6c9ae1-45a1-4693-9777-6fb3132988cb)


**Report Date:** 2025-05-07  
**Device Name:** `window-cyber`  
**Detection Tool:** Microsoft Defender for Endpoint  
**Query Language:** Kusto Query Language (KQL)  

---

## 🎯 Objective

Investigate suspicious download activity on the `window-cyber` machine, specifically focusing on a file `tiktok installer.exe`, potentially indicating unauthorized installation or malware.

---

## 🔍 Key Findings

- **Suspicious Download:**  
  A file named `tiktok installer.exe` was downloaded from an image CDN (`https://store-images.s-microsoft.com`) at **2:44:43 PM** on May 7, 2025. This file is not typically associated with official TikTok installers, which raises concerns about its legitimacy.

  - **File Name:** `tiktok installer.exe`
  - **Download Source:** `https://store-images.s-microsoft.com`
  - **Associated Process:** `tiktok installer.exe`
  - **Timestamp:** `May 7, 2025 2:44:43 PM`
  - **Process Executed:** `tiktok installer.exe`
  
  **Risk Assessment:**  
  This download could be part of a social engineering or drive-by download attack, where users are tricked into downloading potentially malicious software masquerading as the TikTok installer. The origin from a generic image CDN increases suspicion.

---

## 🧪 Follow-Up Actions

### 1. **Verify the File on the System**
To ensure the downloaded file exists and has been properly logged, use the following query to check its presence on disk:

    DeviceFileEvents
    | where DeviceName == "window-cyber"
    | where FileName contains "tiktok"
    | project Timestamp, FileName, FolderPath, InitiatingProcessAccountName, SHA256
    | order by Timestamp desc

2. Check for Execution of the File

Determine if the downloaded file was executed on the system, indicating it could have been run as part of a larger attack chain.

    DeviceProcessEvents
    | where DeviceName == "window-cyber"
    | where FileName contains "tiktok"
    | project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
    | order by Timestamp desc

3. Block and Contain

    If the file is confirmed to be malicious, block the download source (store-images.s-microsoft.com) on firewalls and endpoint security solutions.

    Perform a full malware scan and isolate the window-cyber machine until confirmed clean.



🧩 Additional Context

    Source URL: https://store-images.s-microsoft.com
    This domain, though related to Microsoft, may be misused by attackers to distribute unauthorized or malicious files.

    File Analysis:
    If the file exists on disk, consider performing a hash analysis (SHA256) on the file and comparing it against threat intelligence databases to identify its reputation.

⚠️ Risk Assessment

    Attack Type: Unauthorized download and potential malware

    Source: Download via web browser or potentially manipulated Microsoft Store mechanism

    Indicators of Risk:

        Suspicious executable downloaded from a generic CDN URL

        File name (tiktok installer.exe) which could be impersonating a legitimate application

Potential Impact:

    Malware execution

    Data exfiltration

    Privilege escalation

🚨 Summary

A suspicious download activity was detected on the window-cyber machine, where an installer for TikTok (tiktok installer.exe) was retrieved from an image CDN (store-images.s-microsoft.com). Immediate actions include verifying the existence and execution of the file, blocking the source, and running a malware scan.

    Status: 🚨 Active Threat

    Action Required: Isolate the machine, verify file integrity, perform malware scanning, and block the associated URL.

🛠️ Recommended Actions

    File Verification: Use KQL queries to confirm file presence and execution.

    Network Isolation: Block the malicious URL in the security stack.

    Further Investigation: Check for other potentially malicious files or unusual activity originating from this machine.

    Enhance Defense Posture: Implement tighter restrictions on downloading executable files, especially from unknown sources.

Threat Intelligence Tags:

    Malicious Download

    Unauthorized Installer

    TikTok Impersonation

    Endpoint Detection
