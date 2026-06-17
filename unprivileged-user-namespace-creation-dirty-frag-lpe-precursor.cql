/*
Title: Unprivileged User Namespace Creation (Dirty Frag LPE Precursor)
Author: T
Date: 2026-05-08
References:
  - https://cybersecuritynews.com/dirty-frag-linux-vulnerability/
  - https://thehackernews.com/2026/05/linux-kernel-dirty-frag-lpe-exploit.html
*/

// Target Linux process execution events
#event_simpleName = ProcessRollup2
| event_platform = Lin

// Identify executions of the unshare utility attempting to create a new user namespace (-U or --user)
// This is a prerequisite for the ESP variant of the Dirty Frag Linux kernel LPE
| CommandLine = /unshare\s+.*(--user|-U)(\s|$)/i

// [TUNING] False Positive Sensitivity is Medium. 
// Legitimate container runtimes or administrative tools may generate noise.
// Uncomment and adjust the lines below to filter out expected activity.
// | !in(field=ParentBaseFileName, values=["dockerd", "containerd", "kubelet", "crio"])
// | UserName != "root"

// Present relevant data for triage and investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, @timestamp])
