// Target Windows process execution events
#event_simpleName = ProcessRollup2
| event_platform = Win

// Look for plink.exe or plink64.exe
| ImageFileName = /\\plink(64)?\.exe$/i

// Match command line arguments for Remote (-R) or Local (-L) port forwarding targeting RDP port 3389
| CommandLine = /\s-(R|L).*:3389/i

// [Tuning Placeholder] Legitimate IT administrators might use Plink for RDP tunneling.
// Uncomment and modify the lines below to exclude authorized users or admin workstations to reduce false positives.
// | UserName != "authorized_admin"
// | ComputerName != *admin_workstation*

// Select relevant fields for triage and analysis
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, @timestamp])

// Sort by latest events first
| sort(field=@timestamp, order=desc)
