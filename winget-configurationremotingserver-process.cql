/*
Title: WinGet ConfigurationRemotingServer Process
Description: Detects process creation where ConfigurationRemotingServer.exe is spawned by winget.exe or WindowsPackageManagerServer.exe, indicating WinGet DSC execution or COM API abuse.
Author: detections.ai
Date: 2026-06-09
References:
  - https://ipurple.team/2026/06/09/winget/
MITRE TTPs: TA0005, T1218
*/

// Filter for Windows process creation events
#event_simpleName = ProcessRollup2
| event_platform = Win

// Match the specific child process executed during WinGet DSC payload application
| ImageFileName = /\\ConfigurationRemotingServer\.exe$/i

// Match parent processes associated with standard WinGet execution or direct COM API invocation
| ParentImageFileName = /\\(winget|windowspackagemanagerserver)\.exe$/i

// FP Tuning: Legitimate administrative use of WinGet configuration and DSC may trigger this rule.
// Consider tuning out authorized software deployment solutions, specific administrative accounts, 
// or known benign CommandLines if false positives occur in your environment.
// Example tuning: | UserName != "AuthorizedAdmin"
| table([aid, ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine, @timestamp])
