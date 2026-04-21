# Handala Detection

This rule detects the execution of specific suspicious scripts, 'dra.ps1' or 'handala.bat', via common Windows command shells such as PowerShell (powershell.exe, pwsh.exe) or Command Prompt (cmd.exe). This activity could indicate malicious execution of known adversary scripts.

## TA002 - Execution

```
#event_simpleName="ProcessRollup2"
| #Vendor="crowdstrike"
| event_platform="Win"
| FileName =/powershell\.exe|pwsh\.exe|cmd\.exe|/
| CommandLine=/dra\.ps1/ 
  OR CommandLine=/handala\.bat/
| table([ComputerName, UserName, ContextTimeStamp])

```


