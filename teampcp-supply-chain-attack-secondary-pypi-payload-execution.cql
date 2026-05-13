/*
Author: detections.ai
Date: 2026-05-13
References: 
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
Description: Detects the download or execution of the secondary PyPI payload 'transformers.pyz', deployed by the compromised guardrails-ai and mistralai packages associated with the TeamPCP supply chain attack.
*/

// Target process execution events on Linux
#event_simpleName = ProcessRollup2
| event_platform = Lin

// Match command lines referencing the specific python zipped executable payload
| CommandLine = /transformers\.pyz/i

// FP Tuning: 'transformers' is a common machine learning library, although the .pyz extension makes this indicator highly specific to this campaign.
// If your environment builds or tests similar custom .pyz files, exclude the known authorized paths or users here.
// | ImageFileName !=~ in(values=["/opt/authorized/bin/python", "/usr/local/bin/custom_runner"])

// Output relevant contextual fields for investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
