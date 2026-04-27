// Author: detections.ai
// Date: 2026-04-27
// Threat: AMOS Stealer C2 IP Activity
// Description: Identifies active command and control or exfiltration connections associated with the recent AMOS Stealer campaign delivered via AI agents.
// MITRE TTPs: TA0011, T1071.001

// Filter for IPv4 network connection events
#event_simpleName = NetworkConnectIP4
// Check if the destination IP matches known AMOS Stealer C2 infrastructure
// Tuning Note: These are direct IOC matches. If false positives occur due to IP reassignment or shared hosting, consider correlating with ProcessRollup2 events for 'osascript' or 'Cursor/Claude'.
| RemoteAddressIP4 =~ in(values=["45.94.47.204", "92.246.136.14"])
| table([aid, ComputerName, RemoteAddressIP4, RemotePort, @timestamp])
