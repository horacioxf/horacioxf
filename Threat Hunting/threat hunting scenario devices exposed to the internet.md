# Threat Hunt Report: Devices Exposed to the Internet

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

During routine maintenance, the security team was tasked with investigating VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that may have been mistakenly exposed to the public internet. Management is concerned about brute-force login attempts against these devices since some older systems lack account lockout policies. The goal is to detect brute-force activity, determine whether any attempts succeeded, and assess the potential impact.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceInfo`** to confirm which VMs were internet-facing.
- **Check `DeviceLogonEvents`** for any login attemps.
  
---

## Steps Taken

### 1. Searched the DeviceInfo Table

Queried for internet-facing devices. Confirmed that `windows-target-1` had been exposed publicly as of **2025-09-15T14:38:47.4304601Z**.

**Query used to locate events:**

```kql

DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc

```
<img width="1709" height="457" alt="image" src="https://github.com/user-attachments/assets/51e26918-f47e-41e9-97ed-8d0440555bdb" />

---

### 2. Searched the `DeviceLogonEvents` Table for Failed Logons

Several bad actors have been discovered attempting to log into the target machine `windows-target-1`.

**Query used to locate event:**

```kql

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonFailed"
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts

```
<img width="662" height="411" alt="image" src="https://github.com/user-attachments/assets/176b2853-4d19-4816-a90d-ab5e916b3716" />

---

### 3. Top IP Address Analysis

The top 10 IPs responsible for the most failed attempts were identified. None had corresponding successful logins.

**Query used to locate events:**

```kql

let RemoteIPsInQuestion = dynamic(["147.93.150.115","178.22.24.78", "194.180.49.61", "45.134.26.142", "178.22.24.45", "57.129.140.32", "36.156.152.109", "193.24.211.48", "5.249.148.202", "109.205.213.170"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)



```
<img width="661" height="251" alt="image" src="https://github.com/user-attachments/assets/446dec41-1ac2-41cb-a809-51cff69d465c" />

---

### 4. Any Remote IP Address Analysis

Any remote IP address was investigated to determine a successful or failed attempt on the target. There were 700 failed login attempts for `windows-target-1` within the last 7 days.

**Query used to locate events:**

```kql

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonSuccess" and LogonType == "Network" and DeviceName == "windows-target-1"
| summarize count()

```
<img width="662" height="210" alt="image" src="https://github.com/user-attachments/assets/2beb9c06-88f7-478e-8641-254706195f6d" />

```kql

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonFailed" and LogonType == "Network" and DeviceName == "windows-target-1"
| summarize count()

```
<img width="660" height="203" alt="image" src="https://github.com/user-attachments/assets/da53a97e-7140-4d0e-b10a-70ab3aa3ab1c" />

---

## Chronological Event Timeline 

### 1. Internet Exposure

- **Timestamp:** `2025-09-15T14:38:47.4304601Z`
- **Event:** Device `windows-target-1` confirmed as internet-facing.

### 2. Failed Login Attempts

- **Timestamp:** Ongoing across the past 7 days.
- **Event:** 700 failed login attempts detected from multiple IPs to target `windows-target-1`.

### 3. Successful Intrusions

- No evidence of successful logons tied to brute-force sources on target `windows-target-1`.


---

## Summary

Although `windows-target-1` is exposed to the internet and has had numerous brute force attempts, there is no evidence of successful or unauthorized access from a bad actor or a legitimate account.

Relevant MITRE ATT&CK TTPs:

- **T1190:** Exploit Public-Facing Application
- **T1110:** Brute Force

---

## Response Taken

- Hardened NSG for windows-target-1 — now only allows RDP from trusted endpoints.

- Implemented account lockout policies to deter brute-force attacks.

- Enforced MFA on administrative accounts.
---
