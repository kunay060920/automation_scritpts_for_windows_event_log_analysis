Execute PowerShell Script using cmd: "Collect-WinEventLogs.ps1"

Now provide the collection log database as runtime parameter and execute python script to parse and normalise the collected data using 
cmd: python .\parse_eventlogs.py .\EventLogCollection\LAPTOP-8SM7PKPU_20260802-123055

Now provide the collection log database as runtime parameter and execute python script to detect and perform analysis on the logs data using
cmd: python .\detect.py .\EventLogCollection\LAPTOP-8SM7PKPU_20260802-123055

Now execute the below command to generate the report based on the analysis performed using 
cmd: python report.py
