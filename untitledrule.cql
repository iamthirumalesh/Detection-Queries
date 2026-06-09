/*
Title: MLTBackdoor File Creation
Description: Detects the writing of specific filenames (endpointdlp.dll and data.bin) associated with the MLTBackdoor payload and its encrypted data blob prior to sideloading.
Author: detections.ai
Date: 2026-06-09
References:
  - https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor
*/

// Target file creation and file open events for Windows platforms
(#event_simpleName = NewExecutableWritten OR #event_simpleName = FileOpenInfo)
| event_platform = Win

// Match the specific filenames used by the MLTBackdoor dropper
// Note (FP Sensitivity: Medium): The filename "data.bin" is fairly generic and may cause false positives. 
// "endpointdlp.dll" is more specific. If legitimate applications (like an actual DLP tool) drop these files, 
// consider tuning by restricting the TargetFileName to expected malicious paths (e.g., | TargetFileName = /\\AppData\\Local\\Temp\\[^\\]+\\/i) 
// or excluding known safe parent processes.
| TargetFileName = /\\(endpointdlp\.dll|data\.bin)$/i

// Output relevant fields for triage
| table([aid, ComputerName, TargetFileName, @timestamp])
