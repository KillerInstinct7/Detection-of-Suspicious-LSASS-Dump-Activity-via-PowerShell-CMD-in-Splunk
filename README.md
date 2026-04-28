# Detection-of-Suspicious-LSASS-Dump-Activity-via-PowerShell-CMD-in-Splunk
Built and validated a Splunk detection for PowerShell or cmd activity executing from or referencing a temporary directory where the command line references an LSASS dump file (lsass.DMP).  This behavior may indicate credential dumping or unauthorized access to sensitive system memory artifacts.


# Detection Logic:
- Detect PowerShell or cmd activity from a temporary directory where the command line references lsass.DMP.


# Investigation Summary:
- Observed PowerShell executing from a temporary directory
- Identified command line references to lsass.DMP
- Noted file creation activity consistent with dump artifacts
- Obeserved optional error suppression behavior (-ErrorAction SilentlyContinue)
- Correlated activity within a short time window


# SPL Query:
- index="detection_lab2" (Image="*powershell.exe" OR Image="*cmd.exe") CurrentDirectory="*\\temp\\" CommandLine="*lsass.DMP*"


# Alert Configuration:
- Runs every hour
- Triggers when results > 0
- Logs events to Splunk alerts


# Limitations:
- No reliable Sysmon Event ID 10 (ProcessAccess) telemetry observed
- Detection relies on command-line artifacts and process behavior
- May not detect fileless credential dumping techniques


# Future Improvements:
- Enable and tune ProcessAccess (Event ID 10) logging
- Correlate LSASS access with parent-child process relationships
- Exapnd detection to additional credential dumping tools/techniques
