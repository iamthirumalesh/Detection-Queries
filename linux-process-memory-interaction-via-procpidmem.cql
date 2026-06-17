/*
Author: detections.ai
Date: 2026-05-13
References: 
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
Description: Detects process executions interacting with process memory via '/proc/<pid>/mem', a technique used by the attacker in the TeamPCP supply chain attack to extract OIDC tokens from GitHub Actions runners.
*/

// Target process execution events on Linux
#event_simpleName = ProcessRollup2
| event_platform = Lin

// Match command lines referencing the memory of a process
| CommandLine = /\/proc\/\d+\/mem/i

// FP Tuning: Certain debugging, monitoring, or security tools (e.g., gdb, strace) might legitimately access process memory. 
// Filter out known authorized processes or administrative actions here to reduce noise.
// | ImageFileName !=~ in(values=["/usr/bin/gdb", "/usr/bin/strace"])

// Output relevant contextual fields for investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
