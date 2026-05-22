# SOC Analyst Home Lab using Microsoft Sentinel

## Overview
This project demonstrates a cloud-based SOC lab built using Microsoft Sentinel in Azure.

The lab was created to simulate real-world cyber attack detections and SOC monitoring activities.

---

# Technologies Used

- Microsoft Sentinel
- Azure Log Analytics
- KQL (Kusto Query Language)
- Windows Event Logs
- MITRE ATT&CK Framework

---

# Detection Use Cases Implemented

## 1. Brute Force Detection
Technique: T1110

## 2. Credential Dumping Detection
Technique: T1003

## 3. Encoded PowerShell Detection
Technique: T1059.001

## 4. Registry Persistence Detection
Technique: T1547

## 5. Scheduled Task Persistence Detection
Technique: T1053

## 6. Suspicious Local Admin Account Creation
Technique: T1136

## 7. LOLBins Execution Detection
Technique: T1218

## 8. Suspicious Parent Process Spawning PowerShell
Technique: T1059.001

## 9. Ransomware Shadow Deletion Detection
Technique: T1490

---

# Skills Demonstrated

- SIEM Monitoring
- Threat Detection
- KQL Query Writing
- Incident Investigation
- Log Analysis
- MITRE ATT&CK Mapping

---

# Sample KQL Query

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account
| where FailedAttempts > 5
```

---

# Screenshots

Project screenshots are available in the Screenshots folder.

---

# Author

Chandan G

LinkedIn:
https://linkedin.com/in/chandan-g-7749573a6

GitHub:
https://github.com/Chandan-G-04