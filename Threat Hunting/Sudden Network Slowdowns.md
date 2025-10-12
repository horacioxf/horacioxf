# Threat Hunt Report: Sudden Network Slowdowns

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario

The server team has noticed a significant degradation in network performance on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

## High-Level IoC Discovery Plan
- **Check `DeviceNetworkEvents`** for connection attempts.
- **Check `DeviceProcessEvents`** to identify unusual activity.

---

## Steps Taken

### 1. Search the DeviceNetworkEvents Table

Queried for failed network connections within the same subnet. Confirmed that `windows-target-1` had 161 failed connections against itself. Other devices had 
failed connections. Further investigation was conducted on the high failed connection attempts which was `Windows-target-1`.

**Query used:**

```kql

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionAttempts desc

```
<img width="586" height="104" alt="image" src="https://github.com/user-attachments/assets/830e7c20-06f9-481e-8af2-a812204a1ca7" />

After investigating `windows-target-1`, it was discovered that there was a port scan taking place due to the order of ports that were scanned.
These scans were happening at nearly the exact same times. 

**Query used:**

```kql

let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| where RemoteIP == IPInQuestion
| order by Timestamp desc

```
<img width="589" height="145" alt="image" src="https://github.com/user-attachments/assets/a60586b5-b162-4226-a173-35a323da1f4f" />
---

### 2. Search the DeviceProcessEvents Table

After identifying that the port scan started around Sep 29, 2025 3:37:16 AM, I began to investigate the DeviceProcessEvents
around that same time frame and discovered a command executed on PowerShell named "portscan.ps1" at Sep 29, 2025, 3:36:37 AM by the account name "system":

**Query used:** 

```kql

let VMName = "windows-target-1";
let specificTime = datetime(2025-09-29T08:37:16.4674091Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

```

<img width="586" height="40" alt="image" src="https://github.com/user-attachments/assets/1a6a2c7d-5a25-481a-868b-eec4c4dbcd2d" />
---

## Chronological Event Timeline

### 1. PowerShell script deployed/executed

- **Timestamp:** `2025-09-29T08:36:37.4674091Z`
- **Event:** PowerShell script `portscan.ps1` was executed.

### 2. Portscanning activity

- **Timestamp:** `2025-09-29T08:37:16.4674091Z`
- **Event:** Numerous failed connection attempts appeared in `DeviceNetworkEvents` from `10.0.0.5/windows-target-1`
- scanning ports in order.

### 3. High volume of failed connections

- **Timestamp:** `2025-09-29T08:37:16.4674091Z`
- **Event:** Device `windows-target-1` showed 161 failed connections (along with other hosts).

---

## Summary
`windows-target-1` had a PowerShell script named `portscan.ps` delivered onto the system and executed by the `SYSTEM` account, the script
then started to scan ports sequentially on the network and resulted in numerous failed connection attempts, causing a sudden network slowdown. 

Relevant MITRE ATT&CK TTPs:

- **T1059.001:** Command and Scripting Interpreter: PowerShell
- **T1078.003:** Valid Accounts: Local Accounts
- **T1046:** Network Service Discovery
- **T1049:** System Network Connections Discovery
- **T1021:** Remote Services

---

## Reponse Taken

- Isolate device and perform malware scan.
- If no malware is discovered, reimage/rebuild the device.
