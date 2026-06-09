/*
Title: PowerShell QoS Throttling Policy (EDRChoker evasion technique)
Author: Thiru
Date: 2026-06-09
Description: Detects the use of the New-NetQosPolicy PowerShell cmdlet with parameters designed to aggressively throttle application bandwidth, indicative of manual EDR telemetry disruption.
References:
  - https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html
MITRE TTPs: T1562.001, T1059.001
*/

// Target Windows process creation events
#event_simpleName = ProcessRollup2
| event_platform = Win

// Identify commands creating QoS policies with specific throttling rates
| CommandLine = /New-NetQosPolicy/i
| CommandLine = /-ThrottleRateActionBitsPerSecond/i

// FP Tuning: Network administrators may occasionally use these cmdlets for legitimate traffic shaping.
// Uncomment and populate the lines below to filter out known good administrative users or scripts.
// | !in(field=UserName, values=["DOMAIN\\NetAdmin", "DOMAIN\\System"])
// | TargetFileName != /(?i)\\Path\\To\\Authorized\\Script\.ps1$/

// Output relevant fields for analysis
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
