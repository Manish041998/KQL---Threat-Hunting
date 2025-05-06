# KQL Threat Hunting

This repository contains a curated set of **Kusto Query Language (KQL)** queries designed to support threat hunting, incident response, and security investigations using Microsoft Sentinel and Microsoft Defender data sources.

## 📌 Purpose

- Support blue teams in detecting suspicious activity
- Map queries to **MITRE ATT&CK** techniques
- Investigate alerts, anomalies, and real-world attack patterns
- Provide reusable hunting templates for SOC analysts and security engineers

## 📁 Folder Structure

```

├── Mitre/                  # Queries mapped to MITRE ATT\&CK TTPs
├── $tables/                 # Queries organized by Microsoft Defender table name
├── Activity/               # Queries categorized by type of attack or behavior
└── README.md               # This file

````

## ✅ Sample Use Cases

- Detect use of `mshta.exe` for living-off-the-land execution (`T1218.005`)
- Investigate unusual inbound connections to a compromised device
- Identify credential dumping via browser data (`T1555.003`)
- Trace lateral movement via RDP or SMB sessions

## 🧠 How to Use

1. Clone the repository:
   ```bash
   git clone https://github.com/Manish041998/KQL---Threat-Hunting
   
2. Open the `.kql` files in Azure Sentinel or Microsoft Defender Advanced Hunting
3. Modify variables like `DeviceName`, `TimeRange`, or `AccountName` as needed
4. Run and pivot your investigation

## 📚 MITRE Mapping

Each query in the `mitre/` folder includes the associated MITRE ATT\&CK technique ID in the filename and within the query comments.

## 📬 Contributions

Feel free to fork, modify, and raise a pull request if you have improvements or new queries to share!

**Created by:** Sai Manish
**License:** MIT
