// Target network share creation events
#event_simpleName="NetShareAdd"

// Exclude common printer shares (print$) and spool directories to reduce false positives
| ShareName != /print\$/i
| SharePath != /\\spool\\printers/i

// Placeholder to tune out specific expected print server shares or benign admin activity
// | ShareName != /<INSERT_EXPECTED_PRINTER_NAME>/i
// | UserName != /<INSERT_KNOWN_ADMIN_ACCOUNT>/i

// Apply user-defined parameter filters
| wildcard(field=UserName, pattern=?UserName, ignoreCase=true)
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)

// Group relevant share creation details together
| groupBy([ComputerName, UserName, ShareName, SharePath, ShareData, @timestamp])
