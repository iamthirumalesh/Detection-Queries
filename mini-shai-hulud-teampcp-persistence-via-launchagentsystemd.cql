/*
Author: detections.ai
Date: 2026-05-13
References: 
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
Description: Detects the creation of the persistent macOS LaunchAgent or Linux systemd service named 'gh-token-monitor', used by the Mini Shai-Hulud (TeamPCP) malware to monitor GitHub tokens.
*/

// Target file creation and access events
#event_simpleName =~ in(values=["NewExecutableWritten", "NewScriptWritten", "FileOpenInfo"])
// Restrict to Mac and Linux platforms where LaunchAgents and systemd services are utilized
| event_platform =~ in(values=["Mac", "Lin"])
// Match the specific persistence files created by the TeamPCP payload
// FP Tuning: These specific file names are highly indicative of the malware. However, if legitimate internal tools use similar naming conventions, exclude them here (e.g., adding: | TargetFileName !=~ wildcard(*internal_tool_path*))
| TargetFileName = /(com\.user\.gh-token-monitor\.plist|gh-token-monitor\.service)$/i
// Output relevant contextual fields for the detection
| table([aid, ComputerName, event_platform, TargetFileName, @timestamp])
