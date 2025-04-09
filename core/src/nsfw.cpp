Here’s a curated list of **LOLBins (Living Off the Land Binaries)** relevant to the fileless, Windows 11-compatible, and stealthy ransomware/wiperware killchain we just covered:

---

### 🔹 **Execution & Payload Delivery**
- `mshta.exe` – Execute remote HTA/VBScript payloads.
- `rundll32.exe` – Run DLLs and JavaScript-based COM objects in memory.
- `regsvr32.exe` – Execute remote scripts/DLLs using scriptlet loading.
- `powershell.exe` – Core script execution, fileless payload loading.
- `msiexec.exe` – Install and execute remote MSI payloads.
- `cmd.exe` – Generic script/command execution.
- `wscript.exe` / `cscript.exe` – VBScript/JS-based execution.
- `certutil.exe` – Download payloads or decode base64-encoded files.

---

### 🔹 **Persistence & Scheduled Execution**
- `schtasks.exe` – Create scheduled tasks for persistence.
- `wmic.exe` – Execute commands and lateral movement via WMI.
- `eventvwr.exe` – UAC bypass via hijacked registry keys.
- `fodhelper.exe` – UAC bypass via auto-elevated binary.

---

### 🔹 **Privilege Escalation & Credential Access**
- `dllhost.exe` – DLL hijacking/COM hijacking.
- `slui.exe` – Another UAC bypass vector.
- `sdclt.exe` – Abused for arbitrary command execution and privilege escalation.
- `taskmgr.exe` – Can load malicious DLLs when hijacked.

---

### 🔹 **Lateral Movement**
- `psexec.exe` – Remote command execution (Red Team favorite).
- `winrm.vbs` – PowerShell Remoting helper.
- `wmic.exe` – Cross-network process creation via WMI.

---

### 🔹 **Impact – Data Destruction / Anti-Forensics**
- `cipher.exe` – Securely delete files and wipe disk space.
- `vssadmin.exe` – Delete volume shadow copies (anti-backup).
- `wbadmin.exe` – Delete backup catalogs.
- `bcdedit.exe` – Disable recovery options.
- `wevtutil.exe` – Clear event logs.
- `shutdown.exe` – Reboot/shutdown system post-attack.
- `fsutil.exe` – Manipulate file system behaviors or drive states.

---

This list contains **all essential LOLBins** that enable full-spectrum ransomware or wiperware simulations—from delivery and execution to lateral movement, data destruction, and stealth—all while remaining fileless and evasive in a Windows 11 environment. Let me know if you want them exported as JSON, CSV, or mapped to ATT&CK IDs.
