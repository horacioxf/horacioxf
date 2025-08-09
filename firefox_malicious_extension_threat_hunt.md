# Threat Event (Malicious Firefox Extension)
**Suspicious Firefox Add-on Installation and Use for Data Exfiltration**

---

## Reason for Hunt
**Cybersecurity News Alert** – A recent report from a reputable threat intelligence feed warned about a malicious Firefox extension masquerading as a productivity tool (“PDF Converter Pro”) being used to exfiltrate clipboard data and browser-stored credentials to attacker-controlled servers.

---

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Open Firefox and navigate to the malicious add-on download page:  
   `https://malicious-addons.example/fakepdfconverter.xpi`
2. Download and install the add-on manually via:  
   `about:addons` → “Install Add-on From File…”
3. Grant the extension permissions to “Read and change all your data on all websites.”
4. The extension silently logs visited URLs, keystrokes from certain web forms, and clipboard contents.
5. Data is exfiltrated to attacker’s server via HTTPS POST requests to:  
   `https://stealdata.badactorsite.com/upload`
6. Firefox periodically launches in the background via scheduled tasks to ensure the extension remains active.
7. User also downloads a suspicious PDF from the attacker’s site, creating a local artifact: `~/Downloads/invoice-details.pdf`.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| Detect malicious `.xpi` file downloads and suspicious PDF artifacts. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Identify manual add-on installation and unusual Firefox process launches outside normal working hours. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose**| Track suspicious HTTPS POST requests from firefox.exe to non-whitelisted domains. |

---

## Related Queries:
\`\`\`kql
// Detect malicious .xpi downloads
DeviceFileEvents
| where FileName endswith ".xpi"
| where InitiatingProcessFileName =~ "firefox.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine

// Suspicious manual installation process
DeviceProcessEvents
| where ProcessCommandLine contains "about:addons"
  or ProcessCommandLine contains "Install Add-on From File"
| where InitiatingProcessFileName =~ "firefox.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Unusual Firefox launches outside of work hours
DeviceProcessEvents
| where InitiatingProcessFileName =~ "firefox.exe"
| where hour(Timestamp) < 6 or hour(Timestamp) > 22
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Network connections to known malicious domain
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "firefox.exe"
| where RemoteUrl contains "stealdata.badactorsite.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort

// Suspicious PDF artifacts
DeviceFileEvents
| where FileName endswith ".pdf"
| where FolderPath contains "Downloads"
| where InitiatingProcessFileName =~ "firefox.exe"
\`\`\`

---

## Created By:
- **Author Name**: Horacio Flores
- **Author Contact**: [https://www.linkedin.com/in/horacioxf/](https://www.linkedin.com/in/horacioxf/)  
- **Date**: August 9, 2025

## Validated By:
- **Reviewer Name**:  
- **Reviewer Contact**:  
- **Validation Date**:  

---

## Additional Notes:
- Monitor Firefox extension installations via enterprise policy if possible.
- Consider blocking manual `.xpi` installation in managed environments.

---

## Revision History:
| **Version** | **Changes**            | **Date**         | **Modified By**            |
|-------------|------------------------|------------------|----------------------------|
| 1.0         | Initial draft           | `August 9, 2025` | `Horacio Flores`    |
