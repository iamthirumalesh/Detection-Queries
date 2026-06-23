/*
Title: Dirty Frag Modprobe Mitigation Applied
Author: T
Date: 2026-05-08
References:
  - https://cybersecuritynews.com/dirty-frag-linux-vulnerability/
*/

// Target Linux process execution events
#event_simpleName = ProcessRollup2
| event_platform = Lin

// Look for references to the Dirty Frag mitigation configuration file being written or referenced
// Note: Tune this by excluding authorized admin users or configuration management tools (e.g., Ansible, Puppet) if expected in your environment
| CommandLine = /dirtyfrag\.conf/i

// Present relevant data for triage and investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
