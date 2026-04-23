// Filter for process execution events on Linux
#event_simpleName = ProcessRollup2
| event_platform = Lin

// Target the execution of the crontab binary
| ImageFileName = /\/crontab$/i

// Filter for executions by common web server service accounts
// Note: Attackers often leverage RCE in web apps to establish persistence via cron
| in(field=UserName, values=["www-data", "apache", "httpd", "nginx", "www", "http"])

// FP Tuning: While rare, some misconfigured web applications or configuration 
// management scripts might legitimately require cron access. Tune those out by
// filtering specific parent processes or expected command line arguments below.
// | ParentBaseFileName != "legitimate_script"
// | CommandLine != "crontab -l" // Example: allow listing but alert on editing

// Select relevant fields for investigation
| select([aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, @timestamp])
