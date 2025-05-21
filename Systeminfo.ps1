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
$bitlockerInfo = Get-BitLockerVolume |
    Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus, KeyProtector

# Add a message if no BitLocker information is found
if ($bitlockerInfo.Count -eq 0) {
    $bitlockerInfo = @([PSCustomObject]@{
        MountPoint          = "N/A"
        VolumeStatus        = "No BitLocker information available."
        EncryptionPercentage = "N/A"
        ProtectionStatus    = "N/A"
        KeyProtector        = "N/A"
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


# --- Convert Data to HTML Fragments ---
# Each section is converted to an HTML table fragment
$computerInfoHtml = $computerInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>General System Information</h3>"
$cpuInfoHtml = $cpuInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Processor Information</h3>"
$memoryInfoHtml = $memoryInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Memory Modules (RAM)</h3>"
$diskInfoHtml = $diskInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Logical Disk Information (Fixed)</h3>"
$physicalDiskInfoHtml = $physicalDiskInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Physical Disk Information</h3>"
$networkAdaptersHtml = $networkAdapters | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Network Adapters</h3>"
$sharedDrivesHtml = $sharedDrives | ConvertTo-Html -Fragment -As Table -PreContent "<h3>Mapped Network Drives</h3>"
$bitlockerInfoHtml = $bitlockerInfo | ConvertTo-Html -Fragment -As Table -PreContent "<h3>BitLocker Status</h3>"
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

        $computerInfoHtml
        $cpuInfoHtml
        $memoryInfoHtml
        $diskInfoHtml
        $physicalDiskInfoHtml
        $networkAdaptersHtml
        $sharedDrivesHtml
        $bitlockerInfoHtml
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
