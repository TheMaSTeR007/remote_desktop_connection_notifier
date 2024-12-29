# Event ID for successful logon
$EventID = 4624

# Log file to store IPs (optional)
$LogFile = "C:\Quick_Commerce_Mail\rdc_connect_logs.txt"

# Get remote login events
$RemoteLoginEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$EventID} |
                     Where-Object {$_.Properties[18].Value -eq '10'}  # 10 = Remote Interactive

# Function to get the local IP address of the current PC
function Get-LocalIPAddress {
    $LocalIP = (Test-Connection -ComputerName (hostname) -Count 1).Address
    return $LocalIP
}

# Fetch local IP
$LocalIPAddress = Get-LocalIPAddress

# Iterate over remote login events
foreach ($event in $RemoteLoginEvents) {
    $RemoteIPAddress = $event.Properties[18].Value  # Extract remote IP address

    # Log remote and local IP addresses to a file (optional)
    Add-Content $LogFile "Remote Connection from: $RemoteIPAddress to Local IP: $LocalIPAddress"

    # Call Python script to notify Slack
    & python "C:\Quick_Commerce_Mail\rdc_connect_notifier.py" $RemoteIPAddress $LocalIPAddress
}
