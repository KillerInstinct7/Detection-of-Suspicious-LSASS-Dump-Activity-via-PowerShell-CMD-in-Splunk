# Detection-of-Suspicious-LSASS-Dump-Activity-via-PowerShell-CMD-in-Splunk
Built and validated a Splunk detection for PowerShell or cmd activity executing from or referencing a temporary directory where the command line references an LSASS dump file (lsass.DMP).  This behavior may indicate credential dumping or unauthorized access to sensitive system memory artifacts.
