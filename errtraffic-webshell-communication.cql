// Title: ErrTraffic Payload Path Retrieval
// Author: detections.ai
// Date: 2026-06-17
// References: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework/

// Fast free-text search for the specific payload delivery script names
"css.js" OR "cf.js"

// Match the specific URI paths used by ErrTraffic for TDS and ClickFix payload delivery
// Using regex to accommodate forward slashes and optional query parameters commonly seen in web/proxy logs
| (url = /\/api\/css\.js(\?.*)?$/i OR url = /\/cf\.js(\?.*)?$/i OR csUriStem = /\/api