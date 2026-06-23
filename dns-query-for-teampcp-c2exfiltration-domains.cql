/*
Author: detections.ai
Date: 2026-05-13
References: 
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
Description: Detects DNS resolution requests for known C2 and exfiltration domains associated with the TeamPCP campaign, including the git-tanstack typosquat domain and Session messenger network infrastructure.
*/

// Target DNS resolution events
#event_simpleName = DnsRequest

// Match the specific typosquat domain and Session decentralized network domains used for exfiltration
| DomainName = /(^|\.)(git-tanstack\.com|getsession\.org)$/i

// FP Tuning: While git-tanstack.com is purely malicious, getsession.org is the legitimate domain for the Session messenger app. 
// If Session is sanctioned in your environment, consider excluding specific authorized endpoints or subnets.
// | ComputerName !=~ wildcard(?ApprovedSessionHosts)

// Output relevant contextual fields for investigation
| table([aid, ComputerName, DomainName, @timestamp])
