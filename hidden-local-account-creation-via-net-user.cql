/**
 * Title: Hidden Local Account Creation
 * Author: detections.ai
 * Date: 2026-04-24
 * References: https://asec.ahnlab.com/en/85942
 *
 * Description: Detects the creation of hidden local accounts using the 'net user' 
 * command where the username ends with a '$' symbol. This technique is used by 
 * the Andariel group for RID hijacking attacks to maintain stealthy persistence.
 */

// Target process execution events on Windows
#event_simpleName = ProcessRollup2 
event_platform = Win 

// Filter for net.exe or net1.exe
| ImageFileName = /\\net1?\.exe$/i 

// Match 'user <name>$ /add' pattern indicating hidden account creation
// FP Tuning: Legitimate administrative automation scripts might occasionally create 
// machine or service accounts ending in $. Tune by excluding known safe parent 
// processes or administrative UserNames below.
// | ParentBaseFileName != "known_admin_tool.exe"
| CommandLine = /\buser\s+[^\s]+\$\s+\/add/i 

// Select relevant context for incident review
| select([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine])
