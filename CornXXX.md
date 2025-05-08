🛡️ Threat Hunting Report: Suspicious Download Activity – "Corn Photos"

Report Date: 2025-05-07
Device Name: window-cyber
Detection Tool: Microsoft Defender for Endpoint
Query Language: Kusto Query Language (KQL)
🎯 Objective

Investigate potentially suspicious download activity involving files with names or extensions referencing "corn photos" on the window-cyber machine. These downloads may be benign or could indicate attempted malware delivery or phishing via deceptive media files.
🔍 Key Findings

    Suspicious Downloads Identified
    Multiple image and archive files related to "corn" were downloaded. These may represent attempts to obfuscate malicious payloads behind harmless file types.

    Screenshot: Advanced Hunting Console

    Downloaded File Names:

        corn_photo_1.jpg

        corn_images.zip

        corn_collection.png

    Notable Details:

        Timestamps: Several downloads on May 7, 2025, at irregular but clustered intervals.

        Associated Processes:

            chrome.exe

            msedge.exe

        Download Sources:
        Involve unfamiliar or potentially malicious domains.

🧪 Follow-Up Actions
1. Confirm File Presence on Endpoint

Use the following query to identify file creation events:

DeviceFileEvents
| where DeviceName == "window-cyber"
| where FileName contains "corn"
| project Timestamp, FileName, FolderPath, InitiatingProcessAccountName, SHA256
| order by Timestamp desc

2. Check for File Execution

Determine whether the files were opened or executed, indicating possible compromise:

DeviceProcessEvents
| where DeviceName == "window-cyber"
| where FileName contains "corn"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

3. Inspect Network Connections for Malicious Domains

Identify download sources and their IPs to assess risk:

DeviceNetworkEvents
| where DeviceName == "window-cyber"
| where RemoteUrl has_any ("corn") or RemoteUrl endswith ".zip" or RemoteUrl endswith ".jpg" or RemoteUrl endswith ".png"
| project Timestamp, RemoteUrl, InitiatingProcessFileName, RemoteIP, Protocol
| order by Timestamp desc

4. Contain and Block Malicious Sources

If threat indicators are validated:

    Add suspicious domains and IPs to blocklists.

    Isolate the endpoint from the network.

    Initiate a full malware scan via Defender for Endpoint.

⚠️ Risk Assessment
Category	Details
Attack Type	Potential malware distribution disguised as image downloads
Source	Possibly phishing or drive-by download campaign
Risk Indicators	Repeated downloads, uncommon file sources, archive files posing as images
Potential Impact	Malware execution, system compromise, data exfiltration
🚨 Summary

The window-cyber system shows multiple downloads of image and archive files labeled as "corn photos." While some may be harmless, others may disguise malicious content. Continued analysis and immediate remediation are recommended.

Status: 🚨 Active Threat
Immediate Actions:

    Isolate host

    Verify file contents and hashes

    Scan for malware

    Block malicious URLs/IPs

🛠️ Recommended Actions

    File Verification: Confirm presence and examine file hashes using Defender or KQL.

    Network Isolation: Block involved domains and restrict outbound traffic from the host.

    Threat Scan: Initiate antivirus/anti-malware scan.

    Policy Review: Implement restrictions on downloading files from unknown sources.

🧠 Threat Intelligence Tags

    Malicious Download

    Phishing via Media Files

    Image-based Malware Delivery

    Suspicious Archive File Behavior
