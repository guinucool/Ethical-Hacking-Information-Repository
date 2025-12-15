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

# Show (if) cracked password
john --format={FORMAT} --show {HASH}

# Single crack mode (base yourself on user information)
john --single --format={FORMAT} {HASH WITH USER INFO}

# Calling a custom rule in single crack mode
john --single --rule={RULE NAME} --format={FORMAT} {HASH WITH USER INFO}

# Calling a custom rule in normal mode (applies to the words in the list)
john --wordlist={WORDLIST} --rule={RULE NAME} --format={FORMAT} {HASH}
```

```
# HASH WITH USER INFO (COULD BE THE UNSHADOW FILE)
{username}:{hash}
```

```
# Defining John Rules for password guessing

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