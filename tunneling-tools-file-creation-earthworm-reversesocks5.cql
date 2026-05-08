/*
Detection Name: CL-STA-1132 Tunneling Tools (CVE-2026-0300)
Author: T
Date: 2026-05-08
References: 
  - https://unit42.paloaltonetworks.com/captive-portal-zero-day/
  - https://www.wiz.io/blog/critical-vulnerability-in-pan-os-exploited-in-the-wild-cve-2026-0300
Description: Detects the creation of specific file names used by CL-STA-1132 for EarthWorm and ReverseSocks5 tunneling tools in /tmp/ and /var/tmp/.
Tags: #attack.command-and-control, #attack.t1090, #attack.t1572
*/

// Target file creation and modification events (indexed tag fields placed first for performance)
#event_simpleName = /Written$/

// Match specific file paths used by CL-STA-1132 for EarthWorm and ReverseSocks5
// Note: The file name "/tmp/.c" might occasionally trigger false positives on developer 
// systems or servers compiling code. If false positives occur, consider filtering out 
// legitimate compiler processes or restricting the query to specific network appliances.

| event_platform = Lin
| TargetFileName = /(\/var)?\/tmp\/linux(ap|da|update)$|\/tmp\/\.c$|(\/var|\/tmp)\/R5$/i


// Display the results for review and triage
| table([@timestamp, #repo, aid, ComputerName, TargetFileName, #event_simpleName])
