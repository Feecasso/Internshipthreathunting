# 🛡️ Threat Hunting Report: Suspicious Download of "Corn Photos"

**Report Date:** 2025-05-07  
**Device Name:** `window-cyber`  
**Detection Tool:** Microsoft Defender for Endpoint  
**Query Language:** Kusto Query Language (KQL)  

---

## 🎯 Objective

Investigate suspicious download activity on the `window-cyber` machine, specifically focusing on the download of files with names or extensions related to "corn photos," which may indicate either benign or malicious activity depending on the source.

---

## 🔍 Key Findings

- **Suspicious Download:**  
  Several image files related to "corn photos" have been downloaded to the system. These could indicate possible phishing or data exfiltration activities disguised as harmless media files.

  - **File Names:**  
    - `corn_photo_1.jpg`
    - `corn_images.zip`
    - `corn_collection.png`
  - **Download Source:**  
    Multiple downloads from suspicious domains, potentially malicious in nature.
  - **Timestamp:**  
    Various timestamps throughout May 7, 2025, showing an unusual frequency of downloads.
  - **Associated Process:**  
    The files were downloaded using **web browsers** such as `chrome.exe` and `msedge.exe`.

---

## 🧪 Follow-Up Actions

### 1. **Verify the Files on the System**
To ensure the downloaded files exist and are properly logged, run the following query to check their presence:


DeviceFileEvents
| where DeviceName == "window-cyber"
| where FileName contains "corn"
| project Timestamp, FileName, FolderPath, InitiatingProcessAccountName, SHA256
| order by Timestamp desc

2. Check for Execution of the Files

Determine if any of the downloaded files were executed, which could indicate that they contain embedded scripts or payloads.

DeviceProcessEvents
| where DeviceName == "window-cyber"
| where FileName contains "corn"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

3. Check Source Domains for Suspicious Behavior

Identify the domains from which the images or archives were downloaded to confirm if they are known malicious or hosting suspicious content.

DeviceNetworkEvents
| where DeviceName == "window-cyber"
| where RemoteUrl contains "corn" or RemoteUrl endswith ".zip" or RemoteUrl endswith ".jpg" or RemoteUrl endswith ".png"
| project Timestamp, RemoteUrl, InitiatingProcessFileName, RemoteIP, Protocol
| order by Timestamp desc

4. Contain and Block Malicious Sources

If the downloads are confirmed to be malicious, block the URLs and IP addresses involved on the firewall and endpoint security tools. Perform a full malware scan.
🧩 Additional Context

    Source URLs:
    Unusual or suspicious URLs related to the "corn photos" might indicate an attacker's attempt to distribute malware under the guise of benign images.

    File Analysis:

        If downloaded archives (like .zip) are found, inspect their contents for executable files, which could be disguised as images.

        Perform hash analysis (SHA256) on the files to compare them against threat intelligence databases.

⚠️ Risk Assessment

    Attack Type: Suspicious download of images, possibly containing malware

    Source: Potential phishing or malware distribution via social engineering

    Indicators of Risk:

        Repeated downloads of image files with themes like "corn photos"

        Suspicious URLs or domains

        Archives containing images with potential hidden payloads

Potential Impact:

    Malware execution

    Data exfiltration

    Social engineering for future attacks

🚨 Summary

Multiple suspicious downloads related to "corn photos" were detected on the window-cyber machine, possibly indicating an attempt to disguise malicious files. Immediate actions include verifying the files, inspecting the download source, and performing a malware scan.

    Status: 🚨 Active Threat

    Action Required: Isolate the machine, verify file integrity, perform malware scanning, and block any malicious sources.

🛠️ Recommended Actions

    File Verification: Use KQL queries to confirm file presence and execution.

    Network Isolation: Block the suspicious URLs or IPs from which the files were downloaded.

    Full System Scan: Run a full antivirus and anti-malware scan on window-cyber to detect potential threats.

    Enhance Defense Posture: Implement controls to restrict the download of files from untrusted or unknown sources.

Threat Intelligence Tags:

    Malicious Download

    Phishing

    Malware Distribution via Images

    Suspicious File Behavior
