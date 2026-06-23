/*
Author: detections.ai
Date: 2026-05-13
References: 
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
Description: Detects outbound network connections to the IP address used by the Python variant of the TeamPCP payload for credential exfiltration.
*/

// Target network connection events
#event_simpleName = NetworkConnectIP4

// Match the specific C2 IP address used for exfiltration by the PyPI variant
| RemoteAddressIP4 = "83.142.209.194"

// FP Tuning: As this is a highly specific malicious IP, false positives are extremely unlikely.
// However, if this IP is reassigned to a legitimate service in the future, exclude known authorized processes or hosts here.
// | ImageFileName !=~ wildcard(*authorized_app*)

// Output relevant contextual fields for investigation
| table([aid, ComputerName, UserName, ImageFileName, LocalAddressIP4, RemoteAddressIP4, RemotePort, @timestamp])
