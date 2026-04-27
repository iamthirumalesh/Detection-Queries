/*
Title: Malicious Bitwarden CLI npm Install
Description: Catches the initial access vector where developers unwittingly install the poisoned bitwarden/cli package (version 2026.4.0) via npm.
Author: 
Date: 2026-04-27
MITRE TTPs: TA0001, T1195.002
*/

// Target process execution events 
#event_simpleName =~ in(values=[ProcessRollup2, SyntheticProcessRollup2])

// Filter for npm executable paths across Windows, Linux, and macOS
| ImageFileName = /[\/\\](npm\.cmd|npm|npm\.exe)$/i

// Identify install commands referencing the specific compromised package version
// Note: False positives may occur from security scanners, audit tools, or IR scripts testing for this package.
| CommandLine = /\b(i|install|add)\b/i
| CommandLine = /bitwarden[\\\/]cli/i
| CommandLine = /2026\.4\.0/

// [Tuning Placeholder] Exclude known security scanners or audit processes if they generate false alerts
// | ParentBaseFileName != "VulnerabilityScanner.exe"
// | CommandLine != /audit/i

// Display relevant context for investigation
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
