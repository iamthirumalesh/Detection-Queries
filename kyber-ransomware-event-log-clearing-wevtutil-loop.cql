/*
Title: Kyber Ransomware Event Log Clearing (wevtutil loop)
Author: detections.ai
Date: 2026-04-22
Description: Detects the systemic deletion of Windows event logs using a tight loop with wevtutil.exe, a defense evasion tactic used by Kyber ransomware to impair investigations.
References: 
  - https://www.rapid7.com/blog/post/tr-kyber-ransomware-double-trouble-windows-esxi-attacks-explained/
*/

// Filter for Windows process execution events
#event_simpleName = ProcessRollup2
| event_platform = Win

// Detect the specific 'for' loop command leveraging wevtutil to enumerate and clear all event logs
| CommandLine = /for\s+\/F\s+"tokens=\*".*wevtutil\s+el.*wevtutil\s+cl/i

// FP Mitigation: This exact command structure is highly indicative of malicious activity. 
// However, if automated maintenance scripts legitimately clear logs this way, filter them out by user or parent process here.
// | !in(field=UserName, values=["AuthorizedAdmin", "System_Maintenance"])
// | ParentBaseFileName != "legit_maintenance_script.exe"

// Output relevant fields for triage
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
