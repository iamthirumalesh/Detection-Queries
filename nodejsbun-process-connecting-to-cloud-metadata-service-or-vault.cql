
// Author: detections.ai
// Date: 2026-05-13
// References: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack

// Filter for network connections targeting known cloud metadata IPs or internal Vault port
#event_simpleName = NetworkConnectIP4
| (RemoteAddressIP4 = "169.254.169.254" OR RemoteAddressIP4 = "169.254.170.2" OR RemotePort = 8200)

// Join with process execution events to correlate the activity to Node.js or Bun runtimes
// Note: Uses a cross-platform regex to capture node/bun binaries on Windows, Linux, and macOS
| join(field=aid, query={
    #event_simpleName = ProcessRollup2 
    | ImageFileName = /[\/\\](node|bun)(\.exe)?$/i 
    | select([aid, ImageFileName, CommandLine, UserName])
})

// Tuning Suggestion (Medium FP Sensitivity): 
// Legitimate Node.js applications hosted in AWS may naturally query IMDS for instance roles (e.g., via AWS SDK).
// Consider excluding known production server paths or specific expected CommandLines.
// Additionally, joining strictly on `aid` may cause false correlations if multiple Node processes are active 
// on the same host. If your schema supports it, change the join configuration to use process IDs 
// (e.g., `field=ContextProcessId_decimal` or `TargetProcessId_decimal`) to strictly map the network 
// connection to the exact originating process.

// Format the output for triage and investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, RemoteAddressIP4, RemotePort, @timestamp])
