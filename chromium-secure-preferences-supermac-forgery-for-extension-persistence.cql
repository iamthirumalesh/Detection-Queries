#event_simpleName in (ProcessRollup2, FileWritten, FileOpenInfo)
| event_platform = Win
| (TargetFileName = /\\Secure Preferences$/i OR CommandLine = /Secure Preferences/i)
| (CommandLine = /super_mac/i OR CommandLine = /protection\.macs/i OR TargetFileName = /\\Secure Preferences$/i)
| table([aid, ComputerName, UserName, ImageFileName, TargetFileName, CommandLine, @timestamp])
| sort(@timestamp, order=desc)

// Companion detection: browser process termination immediately followed by relaunch with --restore-last-session, bracketing a Secure Preferences rewrite (msgbox.exe installer behavior used by TA412 to forge super_mac and bypass extension integrity checks)
correlate(
  KillBrowser: {#event_simpleName=ProcessRollup2 | ImageFileName = /\\(chrome|msedge)\.exe$/i | event_platform = Win} include: [aid, ComputerName],
  PrefRewrite: {#event_simpleName=FileWritten | TargetFileName = /\\Secure Preferences$/i | aid <=> KillBrowser.aid} include: *,
  RelaunchBrowser: {#event_simpleName=ProcessRollup2 | ImageFileName = /\\(chrome|msedge)\.exe$/i | CommandLine = /--restore-last-session/i | aid <=> KillBrowser.aid} include: *,
  within=2m
)