# Get the computer name
$deviceName = (Get-ComputerInfo).CsName

# Define the output file path including the device name
# The report will be saved in C:\IT\YourDeviceName.html
$outputPath = "C:\IT\$deviceName.html"

# --- Gather System Information ---
# General computer details
$computerInfo = Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, CsManufacturer, CsModel, CsSystemType, WindowsProductName, WindowsEditionId, OsLastBootUpTime

# Processor (CPU) details
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Manufacturer

# Physical Memory (RAM) module details
$memoryInfo = Get-CimInstance Win32_PhysicalMemory |
    Select-Object DeviceLocator, Manufacturer, PartNumber, SerialNumber, @{Name="Capacity (GB)";Expression={[math]::Round($_.Capacity / 1GB, 2)}}, Speed

# Logical Disk (C:, D: drives) information for fixed local disks (DriveType 3)
$diskInfo = Get-CimInstance Win32_LogicalDisk |
    Where-Object {$_.DriveType -eq 3} |
    Select-Object DeviceID, FileSystem, VolumeName, @{Name="Size (GB)";Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="Free Space (GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}

# Physical Disk (actual SSDs/HDDs) information
$physicalDiskInfo = Get-CimInstance Win32_DiskDrive |
    Select-Object Model, Caption, Size, MediaType, Partitions, SerialNumber

# Network Adapter details (excluding disconnected or virtual adapters without connection IDs)
$networkAdapters = Get-CimInstance Win32_NetworkAdapter |
    Where-Object {$_.NetConnectionID -ne $null} |
    Select-Object Description, MACAddress, NetConnectionID, @{Name="Connection Status";Expression={if ($_.NetConnectionStatus -eq 2) {"Connected"} else {"Disconnected"}}}

# Mapped Network Drives (shared drives connected to this computer with a drive letter)
# This uses the method you confirmed was working for mapped drives.
$sharedDrives = Get-PSDrive -PSProvider FileSystem | Select-Object -Property Root, DisplayRoot | Where-Object {$_.DisplayRoot -like '\\*'}

# Add a message if no mapped network drives are found
if ($sharedDrives.Count -eq 0) {
    $sharedDrives = @([PSCustomObject]@{
        Root        = "N/A"
        DisplayRoot = "No mapped network drives available."
    })
}

# Installed Hotfixes (Windows Updates)
$hotfixes = Get-HotFix | Select-Object Description, HotFixID, InstalledBy, InstallDate

# BitLocker Information (requires BitLocker module and often admin rights for full details)
# This command gets the encryption status of volumes.
#$bitlockerInfo = Get-BitLockerVolume |
    #Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus, KeyProtector

# Add a message if no BitLocker information is found
if ($bitlockerInfo.Count -eq 0) {
    $bitlockerInfo = @([PSCustomObject]@{
        MountPoint           = "N/A"
        VolumeStatus         = "No BitLocker information available."
        EncryptionPercentage = "N/A"
        ProtectionStatus     = "N/A"
        KeyProtector         = "N/A"
    })
}

# Installed Applications (excluding system updates)
$installedPrograms = @()

# Query 64-bit applications from the registry
$installedPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -ne $null -and # Ensure it has a display name
        $_.SystemComponent -ne 1 -and # Exclude system components
        $_.ReleaseType -ne "Update" -and # Exclude updates
        $_.ParentKeyName -eq $null # Exclude sub-components of other programs
    } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Query 32-bit applications on 64-bit systems from the registry
$installedPrograms += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -ne $null -and # Ensure it has a display name
        $_.SystemComponent -ne 1 -and # Exclude system components
        $_.ReleaseType -ne "Update" -and # Exclude updates
        $_.ParentKeyName -eq $null # Exclude sub-components of other programs
    } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Sort and get unique entries (in case of duplicates from different registry views)
$installedPrograms = $installedPrograms | Sort-Object DisplayName | Select-Object -Unique DisplayName, DisplayVersion, Publisher, InstallDate

# Add a message if no installed programs are found
if ($installedPrograms.Count -eq 0) {
    $installedPrograms = @([PSCustomObject]@{
        DisplayName    = "N/A"
        DisplayVersion = "No installed applications found."
        Publisher      = "N/A"
        InstallDate    = "N/A"
    })
}

# IP Configuration Information
$ipConfigInfo = Get-NetIPConfiguration | Select-Object InterfaceAlias,
    @{Name="IPv4 Address(es)"; Expression={$_.IPv4Address.IPAddress -join ", "}},
    @{Name="IPv4 Default Gateway(s)"; Expression={$_.IPv4DefaultGateway.NextHop -join ", "}},
    @{Name="DNS Server(s)"; Expression={$_.DNSServer.ServerAddresses -join ", "}}

# Add a message if no IP configuration information is found
if ($ipConfigInfo.Count -eq 0) {
    $ipConfigInfo = @([PSCustomObject]@{
        "InterfaceAlias"         = "N/A"
        "IPv4 Address(es)"       = "No IP configuration information available."
        "IPv4 Default Gateway(s)" = "N/A"
        "DNS Server(s)"          = "N/A"
    })
}

# Video Controller Information
$videoControllerInfo = Get-CimInstance Win32_VideoController | Select-Object Name, CurrentHorizontalResolution, CurrentVerticalResolution, @{Name="AdapterRAM_GB";Expression={[math]::Round($_.AdapterRAM / 1GB, 2)}}

# Add a message if no video controller information is found
if ($videoControllerInfo.Count -eq 0) {
    $videoControllerInfo = @([PSCustomObject]@{
        Name                      = "N/A"
        CurrentHorizontalResolution = "N/A"
        CurrentVerticalResolution = "N/A"
        AdapterRAM_GB             = "No video controller information available."
    })
}

# Current Wi-Fi Details (Non-Sensitive - BSSID and Cipher removed)
$wifiDetails = @()
$netshOutput = (netsh wlan show interfaces) -join "`n"

# Regex to capture blocks for each interface
$interfaceBlocks = [regex]::Matches($netshOutput, '(?s)(Name\s*:\s*.+?)(?=Name\s*:|\Z)')

foreach ($block in $interfaceBlocks) {
    $currentBlock = $block.Groups[1].Value
    $name = ($currentBlock | Select-String -Pattern 'Name\s*:\s*(.+)' | ForEach-Object {$_.Matches[0].Groups[1].Value}).Trim()
    $state = ($currentBlock | Select-String -Pattern 'State\s*:\s*(.+)' | ForEach-Object {$_.Matches[0].Groups[1].Value}).Trim()

    if ($state -eq 'connected') {
        $ssid = ($currentBlock | Select-String -Pattern 'SSID\s*:\s*(.+)' | ForEach-Object {$_.Matches[0].Groups[1].Value}).Trim()
        $signal = ($currentBlock | Select-String -Pattern 'Signal\s*:\s*(.+)' | ForEach-Object {$_.Matches[0].Groups[1].Value}).Trim()
        $radioType = ($currentBlock | Select-String -Pattern 'Radio type\s*:\s*(.+)' | ForEach-Object {$_.Matches[0].Groups[1].Value}).Trim()
        $authentication = ($currentBlock | Select-String -Pattern 'Authentication\s*:\s*(.+)' | ForEach-Object {$_.Matches[0].Groups[1].Value}).Trim()

        $wifiDetails += [PSCustomObject]@{
            InterfaceName  = $name
            SSID           = $ssid
            SignalStrength = $signal
            RadioType      = $radioType
            Authentication = $authentication
        }
    }
}

# Add a message if no active Wi-Fi connections are found
if ($wifiDetails.Count -eq 0) {
    $wifiDetails = @([PSCustomObject]@{
        InterfaceName  = "N/A"
        SSID           = "No active Wi-Fi connections found."
        SignalStrength = "N/A"
        RadioType      = "N/A"
        Authentication = "N/A"
    })
}


# --- Convert Data to HTML Fragments ---
# Each section is converted to an HTML table fragment
$computerInfoHtml = $computerInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>General System Information</h3>"
$cpuInfoHtml = $cpuInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Processor Information</h3>"
$memoryInfoHtml = $memoryInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Memory Modules (RAM)</h3>"
$diskInfoHtml = $diskInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Logical Disk Information (Fixed)</h3>"
$physicalDiskInfoHtml = $physicalDiskInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Physical Disk Information</h3>"
$networkAdaptersHtml = $networkAdapters | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Network Adapters</h3>"
$ipConfigInfoHtml = $ipConfigInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>IP Configuration</h3>"
$videoControllerInfoHtml = $videoControllerInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Video Controller Information</h3>"
$wifiDetailsHtml = $wifiDetails | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Current Wi-Fi Connection Details</h3>"
$sharedDrivesHtml = $sharedDrives | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Mapped Network Drives</h3>"
#$bitlockerInfoHtml = $bitlockerInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>BitLocker Status</h3>"
$hotfixesHtml = $hotfixes | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Installed Updates (Hotfixes)</h3>"
$installedProgramsHtml = $installedPrograms | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Installed Applications</h3>"


# --- Create the Full HTML Report ---
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Report - $(Get-Date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
        h1 { color: #0056b3; text-align: center; margin-bottom: 30px; }
        h2 { color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 5px; margin-top: 30px; }
        h3 { color: #007bff; margin-top: 20px; margin-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; background-color: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #e9e9e9; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .container { /*max-width: 1200px; Increased from 1000px */ margin: auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.2); }
        .footer { text-align: center; margin-top: 40px; font-size: 0.9em; color: #777; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Report</h1>
        <p><strong>Date Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Computer Name:</strong> $($computerInfo.CsName)</p>
        <p><strong>Current User:</strong> $($env:USERNAME)</p>

        $computerInfoHtml
        $cpuInfoHtml
        $memoryInfoHtml
        $diskInfoHtml
        $physicalDiskInfoHtml
        $networkAdaptersHtml
        $ipConfigInfoHtml
        $wifiDetailsHtml
	    $videoControllerInfoHtml
        $sharedDrivesHtml
        $hotfixesHtml
        $installedProgramsHtml

        <div class="footer">
            Generated by AndyWare
        </div>
    </div>
</body>
</html>
"@

# Save the report to the file
$htmlReport | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "System report saved to: $outputPath"
Invoke-Item $outputPath # Opens the HTML file in your default browser


