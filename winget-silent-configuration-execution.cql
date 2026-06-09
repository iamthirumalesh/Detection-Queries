/*
Title: WinGet Silent Configuration Execution
Description: Detects the command-line usage of WinGet invoking a configuration file, specifically targeting switches designed for silent, non-interactive execution.
Author: detections.ai
Date: 2026-06-09
References:
  - https://ipurple.team/2026/06/09/winget/
MITRE TTPs: TA0002, T1218
*/

// Filter for Windows process execution events involving WinGet
#event_simpleName = ProcessRollup2
| event_platform = Win
| ImageFileName = /\\winget\.exe$/i

// Match command-line switches indicating silent configuration execution
| CommandLine = *configure* 
  AND CommandLine = *--accept-configuration-agreements* 
  AND CommandLine = *--disable-interactivity* 
  AND CommandLine = *-f*

// FP Tuning: WinGet is often used legitimately for automated software provisioning and DSC application.
// If your environment uses WinGet for administration, consider tuning out known management 
// service accounts, specific expected parent processes, or approved configuration file paths.
// Example tuning: | UserName != "AuthorizedDeploymentService"

// Display relevant details for investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
