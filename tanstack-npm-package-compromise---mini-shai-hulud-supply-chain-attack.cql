// Author: detections.ai
// Date: 2026-05-13
// References: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack

// Filter for primary process execution events
#event_simpleName = ProcessRollup2

// Identify the malware's daemonization re-entrancy guard or specific payload filenames
| CommandLine = /(__DAEMONIZED|tanstack_runner\.js|router_init\.js|router_runtime\.js)/i

// Tuning Suggestion (Medium FP Sensitivity): 
// If generic filenames like 'router_init.js' or 'router_runtime.js' trigger false positives 
// in legitimate web development environments, consider restricting the executing process 
// to known JavaScript runtimes by uncommenting the line below:
// | ImageFileName = /(node|bun)(\.exe)?$/i

// Format the output for triage and investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
