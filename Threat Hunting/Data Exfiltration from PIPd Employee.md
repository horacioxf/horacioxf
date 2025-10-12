# Threat Hunt Report: Suspect Data Exfiltration from PIPd Employee

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

An employee named John Doe, working in a sensitive department, has recently been placed on a performance improvement plan (PIP). After John threw a fit, management raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

### High-Level IoC Discovery Plan

- **Check `DeviceFileEvents`** to search for file activities.
- **Check `DeviceProcessEvents`** to look for archiving activity.
- **Check `DeviceNetworkEvents`** to look for network activities based on process or file activities.
  
---

## Steps Taken

### 1. Searched the DeviceFileEvents Table

Searched file events where the filename ends with `.zip` to identify file archived events. At Sep 26, 2025 7:49:18 PM, there was a file created named `employee-data-20250927004908.zip`.

**Query used to locate events:**

```kql

DeviceFileEvents
| where DeviceName == "windows-target-1"
| where FileName endswith ".zip"


```
<img width="590" height="125" alt="image" src="https://github.com/user-attachments/assets/1586376a-5dff-4bba-9c36-e633245a5f82" />

Looking for process events around that time frame, at 7:49:07 PM, there was a process created using PowerShell using a script named “exfiltratedata.ps1”. Upon further investigation after the PowerShell process, there was a silent install for 7-Zip using the command line `"7z2408-x64.exe" /S` with the initial process command line `“powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1”`. It can be assumed that the silent installation was a result of the script being executed. 

**Query used to locate event:**

```kql

let specificTime = datetime(2025-09-27T00:49:18.9139781Z);
let VMName = "windows-target-1";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc

```
<img width="589" height="246" alt="image" src="https://github.com/user-attachments/assets/7d393f37-1fbc-46d1-880f-0d84a60f2746" />

---

### 2. Search DeviceNetworkEvents

I investigated for any outbound connections for proof of exfiltration. However, there were no logs indicating that an outbound connection was attempted. 

**Query used to locate events:**

```kql

let VMName = "windows-target-1";
let specificTime = datetime(2025-09-27T00:49:18.9139781Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by Timestamp desc 

```
<img width="589" height="226" alt="image" src="https://github.com/user-attachments/assets/b2feb7cd-0795-45ba-96f8-17f300fc996a" />

---

## Chronological Event Timeline 

### 1. PowerShell Script Execution

- **Timestamp:** 2025-09-27T00:49:07Z
- **Event:** PowerShell executed with -ExecutionPolicy Bypass to run C:\programdata\exfiltratedata.ps1.

## 2. Silent Installation of 7-Zip

- **Timestamp:** 2025-09-27T00:49:08Z
- **Event:** Script initiated a silent install of 7-Zip using 7z2408-x64.exe /S.

## 3. Data Archiving Detected

- **Timestamp:** 2025-09-27T00:49:18Z
- **Event:** File employee-data-20250927004908.zip created in the user’s Documents directory.

## 4. File System Activity

- **Timestamp:** 2025-09-27T00:49:18Z – 2025-09-27T00:49:20Z
- **Event:** Multiple file read/write operations associated with ZIP creation.

## 5. Network Traffic Review

- **Timestamp:** 2025-09-27T00:49:20Z – 2025-09-27T00:49:22Z
- **Event:** No outbound network connections detected from windows-target-1.

## 6. Script and Process Termination

- **Timestamp:** 2025-09-27T00:50Z+
- **Event:** PowerShell and 7-Zip processes terminated; no persistence observed.

## 7. Analyst Investigation Initiated

- **Timestamp:** 2025-09-27T00:55Z+
- **Event:** SOC analyst correlated process, file, and network telemetry confirming compression activity without exfiltration.

## 8. Post-Incident Actions

- **Timestamp:** 2025-09-27
- **Event:** Findings reported to management; script removed, endpoint isolated, and admin privileges reviewed.

---

## Summary

On September 27, 2025, a PowerShell script (exfiltratedata.ps1) was executed on device windows-target-1, installing 7-Zip and creating a ZIP archive containing company data. The activity indicated potential data staging for exfiltration; however, no outbound network connections or data transfers were detected. The script and related files were removed, the device was isolated, and the user’s administrative privileges were reviewed to prevent future misuse.

Relevant MITRE ATT&CK TTPs:

- **T10.59.001:** Command and Scripting Interpreter: PowerShell

- **T1071.001:** Application Layer Protocol: Web Traffic

- **T1560.001:** Archive Collected Data: Archive via Utility

- **T1070.004:** Indicator Removal on Host: File Deletion

- **T1105:** Ingress Tool Transfer

- **T1055.11:** Process Injection: Extra Window Memory Injection

- **T1027:** Obfuscated Files or Information

- **T1047:** Windows Management Instrumentation

---

## Response Taken

The information was communicated with the employee’s manager, including everything with the archives being created at regular intervals via the powershell script. There didn’t appear to be any evidence of exfiltration. 

---
