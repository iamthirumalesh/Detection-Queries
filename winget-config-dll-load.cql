/*
Title: WinGet Config DLL Load
Description: Detects the loading of the Microsoft.Management.Configuration.dll image within ConfigurationRemotingServer.exe, indicating active DSC processing. This is a strong indicator of WinGet DSC execution, which is abused by tools like DSCourier.
Author: detections.ai
Date: 2026-06-09
References:
  - https://ipurple.team/2026/06/09/winget/
MITRE TTPs: TA0005, T1218
*/

// Filter for Windows image/DLL load events
#event_simpleName = ImageLoad
| event_platform = Win

// Target the specific WinGet Remoting Server process
| ContextImageFileName = /\\ConfigurationRemotingServer\.exe$/i

// Match the loading of the WinGet configuration management DLL
| ImageFileName = /\\Microsoft\.Management\.Configuration\.dll$/i

// FP Tuning: WinGet DSC is a legitimate feature for administrative software deployment. 
// If this DLL load occurs legitimately in your environment, consider tuning by 
// expected parent process, service accounts, or specific device groups.
// Example tuning: | UserName != "AuthorizedDeploymentService"

// Display relevant details for investigation
| table([aid, ComputerName, UserName, ContextImageFileName, ImageFileName, @timestamp])
