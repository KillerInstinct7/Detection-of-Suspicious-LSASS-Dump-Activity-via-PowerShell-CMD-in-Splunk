# Splunk-Credential-Dump-Detection
Built and validated a Splunk detection for PowerShell or cmd activity executing from or referencing a temporary directory where the command line references an LSASS dump file (lsass.DMP).  This behavior may indicate credential dumping or unauthorized access to sensitive system memory artifacts.
