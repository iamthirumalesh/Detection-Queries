/*
 * Author: Thiru &  detections.ai
 * Date: 2026-06-17
 * References: 
 *   - https://socket.dev/blog/mastra-npm-packages-compromised
 */

// Filter for process execution events
(#event_simpleName = ProcessRollup2 OR #event_simpleName = SyntheticProcessRollup2)

// Identify Node.js process executions across Windows, macOS, and Linux
| ImageFileName = /(\\|/)node(\.exe)?$/i

// Detect the specific scripts associated with the Mastra npm supply chain attack
// FP Tuning: 'setup.cjs' may potentially overlap with legitimate package scripts.
// If false positives occur, consider tightening the regex to match the specific flag used in the campaign:
// CommandLine = /(setup\.cjs\s+--no-warnings|protocal\.cjs)/i
| CommandLine = /(setup|protocal)\.cjs/i

// Present the results in a table for investigation
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, @timestamp])
