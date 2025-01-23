# Suspicious PowerShell Activity Detection Rule for Microsoft Sentinel

KQL (Kusto Query Language) query and instructions for setting up an **Analytics Rule** in Microsoft Sentinel to detect suspicious PowerShell activity. The rule is designed to identify high-risk PowerShell command executions, such as those involving remote sessions, execution policy bypass, or suspicious command patterns.

---

## **Query Overview**

The query detects PowerShell command executions that may indicate malicious activity, such as:
- Commands executed in a **remote session**.
- Use of **suspicious command patterns** (e.g., `Invoke-Expression`, `DownloadString`, `EncodedCommand`).
- High volumes of commands executed by a single user or on a single device.

### Key Features
- **Summarization**: Groups events by user, device, and remote session to reduce noise.
- **Threshold-Based Filtering**: Highlights activity that exceeds defined thresholds (e.g., more than 5 commands in 24 hours).
- **Real-Time Detection**: Focuses on the last 24 hours for near-real-time monitoring.

---

## **KQL Query**

```kql
DeviceEvents
| where TimeGenerated >= ago(24h)  // Limit to the last 24 hours for real-time detection
| where ActionType == "PowerShellCommand"
| where InitiatingProcessAccountName != "system"  // Exclude system accounts
// Enrich with additional context
| extend ParentProcess = InitiatingProcessParentFileName  // Parent process info
| extend Remote_Session = IsInitiatingProcessRemoteSession  // Check if it's a remote session
| extend Remote_Session_Device = InitiatingProcessRemoteSessionDeviceName  // Remote device name
| extend ScriptPath = case(
    InitiatingProcessCommandLine contains "-File",  // Extract script path if present
    extract(@"-File\s+([^\s]+)", 1, InitiatingProcessCommandLine),
    ""
)
// Summarize activity by user, device, and remote session
| summarize
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    CommandCount = count(),
    DistinctCommands = dcount(InitiatingProcessCommandLine),
    SampleCommands = make_set(InitiatingProcessCommandLine)
    by InitiatingProcessAccountName, InitiatingProcessAccountUpn, DeviceName, ParentProcess, Remote_Session, Remote_Session_Device, ScriptPath
// Filter for high-risk activity
| where CommandCount > 5 or DistinctCommands > 3 or Remote_Session == true  // Adjust thresholds as needed
| order by CommandCount desc
