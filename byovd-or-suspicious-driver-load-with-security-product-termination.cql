/* Phase 1 — Detect BYOVD: known-vulnerable or out-of-place signed drivers */
#event_simpleName = DriverLoad OR #event_simpleName = ClassifiedModuleLoad
| case {
    in(field=FileName, values=[
      "gdrv.sys", "msio64.sys", "ntiolib.sys", "kprocesshacker.sys",
      "physmem.sys", "dbk64.sys", "procexp152.sys", "NSSM.sys",
      "wantd.sys", "AsrDrv104.sys", "mhyprot2.sys"
    ]) | BYOVDIndicator := "Known vulnerable driver loaded";
    FilePath = /AppData|Temp|ProgramData|Users\\.*\\Desktop/i
      FileName = /\.sys$/i
      | BYOVDIndicator := "Driver loaded from suspicious user-writable path";
    * | BYOVDIndicator := "none";
  }
| BYOVDIndicator != "none"
| join(
    {
      #event_simpleName = TerminateProcess
      | ImageFileName = /(MsMpEng|CsAgent|CsFalconService|csshell|SentinelAgent|cbdefense|MBAMService|avp\.exe|fmon|avgnt|bdservicehost|mcshield|ekrn)\.exe$/i
      | rename(field=ImageFileName, as=TerminatedSecurity)
    },
    field=aid, key=aid
  )
| TerminatedSecurity = *
