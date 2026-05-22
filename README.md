# SOC Home Lab - Microsoft Sentinel

## Overview

This project demonstrates a cloud-based SOC Home Lab built using Microsoft Sentinel in Microsoft Azure. The lab was designed to simulate real-world attack detections, log monitoring, incident analysis, and SIEM operations using custom analytics rules and KQL queries.

The project includes multiple detection use cases mapped with the MITRE ATT&CK Framework.

---

## Technologies Used

- Microsoft Sentinel
- Azure Log Analytics
- Kusto Query Language (KQL)
- Windows Security Events
- MITRE ATT&CK Framework

---

## Detection Use Cases

### 1. Brute Force Detection
- Detects multiple failed login attempts
- MITRE Technique: T1110

### Rule Overview
![image](Screenshots/bruteforce-general.png)

### Detection Query
![image](Screenshots/bruteforce-query.png)

---

### 2. Credential Dumping Detection
- Detects suspicious LSASS access activity
- MITRE Technique: T1003

### Rule Overview
![image](Screenshots/credential-dumping-general.png)

### Detection Query
![image](Screenshots/credential-dumping-query.png)

---

### 3. Encoded PowerShell Detection
- Detects Base64 encoded PowerShell commands
- MITRE Technique: T1059.001

### Rule Overview
![image](Screenshots/encoded-powershell-general.png)

### Detection Query
![image](Screenshots/encoded-powershell-query.png)

---

### 4. Registry Persistence Detection
- Detects suspicious registry modifications
- MITRE Technique: T1547

### Rule Overview
![image](Screenshots/registry-persistence-general.png)

### Detection Query
![image](Screenshots/registry-persistence-query.png)

---

### 5. Scheduled Task Persistence Detection
- Detects malicious scheduled task creation
- MITRE Technique: T1053

### Rule Overview
![image](Screenshots/scheduled-task-general.png)

### Detection Query
![image](Screenshots/scheduled-task-query.png)

---

### 6. Suspicious Local Admin Account Creation
- Detects unauthorized local administrator creation
- MITRE Technique: T1136

### Rule Overview
![image](Screenshots/suspicious-local-admin-creation-general.png)

### Detection Query
![image](Screenshots/suspicious-local-admin-creation-query.png)

---

### 7. LOLBins Execution Detection
- Detects abuse of legitimate Windows binaries
- MITRE Technique: T1218

### Rule Overview
![image](Screenshots/LOLBins-execution-general.png)

### Detection Query
![image](Screenshots/LOLBins-execution-query.png)

---

### 8. Suspicious Parent Process Spawning PowerShell
- Detects suspicious PowerShell spawning behavior
- MITRE Technique: T1059.001

### Rule Overview
![image](Screenshots/suspicious-parent-process-general.png)

### Detection Query
![image](Screenshots/suspicious-parent-process-query.png)

---

### 9. Ransomware Shadow Deletion Detection
- Detects shadow copy deletion activity
- MITRE Technique: T1490

### Rule Overview
![image](Screenshots/ransomware-general.png)

### Detection Query
![image](Screenshots/ransomware-query.png)

---

## Additional Screenshots

### Active Analytics Rules
![image](Screenshots/active-rules.png)

### Alerts and Incidents
![image](Screenshots/alerts.png)

---

## Key Skills Demonstrated

- SIEM Monitoring
- Threat Detection and Analysis
- KQL Query Development
- Incident Investigation
- Log Analysis
- MITRE ATT&CK Mapping
- SOC Operations
- Security Event Correlation
- Alert Triage

---

## Sample Detection Query

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account, IPAddress
| where FailedAttempts > 5
```

---

## Author

Chandan G

LinkedIn:
https://linkedin.com/in/chandan-g-7749573a6

GitHub:
https://github.com/Chandan-G-04
