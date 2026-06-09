/*
Title: MLTBackdoor C2 Domain Resolution
Description: Detects DNS requests to known MLTBackdoor command and control and DGA domains.
Author: detections.ai
Date: 2026-06-09
References:
  - https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor
*/

// Target DNS request events
#event_simpleName = DnsRequest

// Match known MLTBackdoor C2 and DGA domains
// Note (FP Sensitivity: Medium): Detection of these specific domains is usually high fidelity. 
// If false positives occur due to security scanners or sandboxes resolving the domains, consider excluding those specific source IPs or hosts.
| DomainName =~ in(values=["hrs2y15sungu.com", "carrolc.com", "cwrtwright.com", "thomphon.com", "powwowski.com"])

// Select relevant fields for triage
| table([aid, ComputerName, DomainName, @timestamp])
