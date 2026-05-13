// Author: detections.ai
// Date: 2026-05-13
// References: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack

// Filter for DNS requests or IPv4 network connections
(#event_simpleName = DnsRequest OR #event_simpleName = NetworkConnectIP4)

// Match on the Session P2P network domain (e.g., filev2.getsession.org) or known service node IPs
| (DomainName = /getsession\.org$/i OR RemoteAddressIP4 = ?SessionNetworkIPs)

// Tuning Suggestion (Medium FP Sensitivity): 
// Session is a legitimate decentralized encrypted messaging application. If Session is approved 
// for use in your enterprise, this rule will generate false positives from legitimate client traffic. 
// Consider tuning by excluding specific approved user machines or restricting the detection 
// strictly to CI/CD runner environments and production servers where messaging apps are unexpected.

// Format the output for triage and investigation
| table([aid, ComputerName, #event_simpleName, DomainName, RemoteAddressIP4, RemotePort, @timestamp])
