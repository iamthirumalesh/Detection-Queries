#event_simpleName = InjectedThread
| TargetProcessName = /wmpnetwk\.exe$/i
| ModuleName =~ in(values=["ws2_32.dll", "mswsock.dll", "wininet.dll", "winhttp.dll", "nsi.dll", "iphlpapi.dll", "ntdll.dll"])
| table([aid, ComputerName, SourceProcessId, TargetProcessId, TargetProcessName, ModuleName, InjectedThreadStartAddress, @timestamp])