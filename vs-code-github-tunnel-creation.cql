/*
Title: VS Code GitHub Tunnel Creation
Author: detections.ai
Date: 2026-04-27
Description: Detects the command line execution of VS Code initiating a tunnel using a GitHub provider. Tropic Trooper uses this technique to establish interactive remote access while blending in with legitimate developer activity.
References: 
  - https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener
MITRE TTPs: TA0011, T1219
*/

// Focus on process creation events for Windows systems
#event_simpleName = ProcessRollup2 
event_platform = Win

// Identify VS Code executable executions
(FileName = "code.exe" OR ImageFileName = /\\code\.exe$/i)

// Look for command line arguments initiating a GitHub tunnel
// Tuning Recommendation: Developers may use this feature legitimately. If false positives occur, consider filtering by specific Developer user groups, organizational units, or expected ParentBaseFileName.
CommandLine = /tunnel\s+user\s+login\s+--provider\s+github/i

// Present relevant contextual fields for triage
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine])
