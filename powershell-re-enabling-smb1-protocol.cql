// Author: detections.ai
// Date: 2026-04-21
// References: https://research.checkpoint.com/2026/dfir-report-the-gentlemen/

// Target Windows process creation events
(#event_simpleName = ProcessRollup2 OR #event_simpleName = SyntheticProcessRollup2)
| event_platform = Win

// Identify the PowerShell cmdlet used to re-enable the deprecated SMB1 protocol
// Using regex to ensure case-insensitive matching regardless of argument order
| CommandLine = /Enable-WindowsOptionalFeature/i
| CommandLine = /SMB1Protocol/i

// TUNING SUGGESTIONS:
// Enabling SMB1 is rare but may occur in environments supporting legacy systems.
// If false positives occur from authorized IT activity, filter by expected deployment processes or admin users:
// | UserName != "IT_Deployment_Account"
// | ParentBaseFileName != "SCCM_Agent.exe"

// Extract context for analyst triage
| select([@timestamp, aid, ComputerName, UserName, ImageFileName, ParentBaseFileName, CommandLine])
