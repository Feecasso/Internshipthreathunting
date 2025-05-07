let TargetDevice = "window-cyber";
DeviceLogonEvents
| where DeviceName == TargetDevice
| where ActionType == "LogonFailed"
| project Timestamp, ActionType, DeviceName, AccountName, RemoteIP
| summarize FailedAttempts = count() by RemoteIP
| sort by FailedAttempts desc 
