#repo="base_sensor"
| #event_simpleName =~ in(values=["*ProcessRollup2", "*FileWritten"])
| case {
  // Look for the curl install method
  CommandLine=/openclaw\.ai\/install\.sh/
    | Action := "openclaw installed";

  CommandLine=/openclaw\.ai\/install\.ps1/
    | Action := "openclaw installed";
  // Look for node package install methods
  CommandLine =~ in(values=["* openclaw*", "* clawdbot*", "* moltbot*"])
    | CommandLine =~ in(values=["*npm*", "*npx*", "*brew*"])
    | CommandLine="* install *"
    | Action := "openclaw installed";

  // Look for files being written to user home directories
  FilePath =~ in(values=["*/.openclaw/*", "*/.clawdbot/*", "*/.moltbot/*"])
    | Action := "openclaw user configuration updated";

  // Look for the clawdbot service being started on port tcp/18789
  CommandLine =~ in(values=["*openclaw*", "*clawdbot*", "*moltbot*"])
    | ImageFileName=/node/i
    | CommandLine=/gateway --port 18789/i
    | Action := "openclaw service started";
    
  // Look for the clawdbot service being started
  CommandLine =~ in(values=["*openclaw*", "*clawdbot*", "*moltbot*"])
    | FileName=/node/i
    | CommandLine=/gateway/i
    | Action := "openclaw service started";
}
| groupby(
  aid, 
  ComputerName, 
  UserName, 
  function=[
    collect(Action), 
    selectLast([CommandLine, ImageFileName, #event_simpleName])
  ]
)
