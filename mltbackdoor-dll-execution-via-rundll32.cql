cql
/*
Title: MLTBackdoor DLL Execution
Description: Detects the execution of the initial stage DLL payload (endpointdlp.dll) via rundll32.exe calling a specific ordinal to decrypt and load the final MLTBackdoor payload.
Author: detections.ai
Date: 2026-06-09
References:
  - https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor
*/

// Target Windows process execution events
#event_simpleName = ProcessRollup2
| event_platform = Win

// Filter for rundll32.exe executions
| ImageFileName = /\\rundll32\.exe$/i

// Match the specific MLTBackdoor DLL and ordinal execution
// Note (FP Sensitivity: Medium): The filename "endpointdlp.dll" combined with ordinal #2 is highly specific to this threat. 
// If false positives occur from legitimate software mimicking this pattern, tune by excluding specific known-safe parent processes or execution paths.
| CommandLine = /endpointdlp\.dll[,\s"']*#2/i

// Output relevant fields for triage
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
