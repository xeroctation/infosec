***

# CIA concept

1. **Confidentiality**:  This principle ensures that sensitive data is kept private and only accessible to authorized parties. Examples of measures that promote confidentiality include password protection, encryption, and access controls. For instance, a company might use encryption to protect customer data in transit and store sensitive data in a secure server room with limited access.

1. **Integrity**: This principle ensures that data is accurate, complete, and reliable. Measures that promote data integrity include backup and recovery procedures, data validation, and error detection. For instance, a bank might use backup systems to ensure that customer data is not lost in case of a disaster or a technical issue.

1. **Availability**: This principle ensures that data and services are available when needed by authorized parties. Measures that promote availability include redundancy, fault tolerance, and disaster recovery planning. Availability of the information could be lost due to a number of reasons: due to power loss or software errors or the targeted attacks like DDoS and DoS

***

# Threat, Vulnerability, Attack, Attack Vector 

1. **Threat**: s an object, person, or other entity that presents an ongoing danger to an asset  
\
Threats could be :  
    1. **Inside**: Does not check input data> let in malicious data. Wifi router left configured with known default passwords. Policy: not restricted enough> left any servers of the company to
upgrade the server patch.   **In** most cases, insider threats are accidental, like an employee using a weak password, allowing a hacker to compromise their account and access sensitive company data. However, they can also be intentional, like a disgruntled worker exposing company secrets for revenge.
    1. **Outside**: 

    1. **HUMAN ERROR**: Causes: Inexperience, Improper training, Incorrect assumptions

    1. **NATURAL THREATS**: Fire, flood, tornado, lightning etc


2. **Vulnerability**: A weakness in the security system, e.g., in policy, procedure, design
or implementation, that might be exploited to cause loss or harm.   
\
A vulnerability might involve:
    * a specific operating system Or application that youвЂ™re running
    * he physical location of your office
    * building, a data center that is overpopulated with servers and producing more heat than its air-conditioning system can handle
    * a lack of backup generators, or other factors.  
\
Control: 
    * an action, device, policy, procedure or technique that removes or reduces a vulnerability
    * A threat is blocked by control of vulnerability
    * Security Policy: a succinct statement of a system`s protection strategy.
    * Example of a security policy: patches must be verified and can only be downloaded from a specific server

    ****THREAT vs VULNERABILITY***
        * A threat is something that can go wrong and cause damage to valuable assets.
        * A vulnerability is an exposure in the infrastructure that can lead to a threat becoming realized.

3. **Attack, Attack Vector**

    1. An attack is an act that takes advantage of a
vulnerability to compromise a controlled system.
    1. Accomplished by threat agent which damages or
steals organizationвЂ™s information
    1. **Attack vector** is a method or pathway used by a hacker to access or penetrate the target system.

***

# 	Cryptography

**Cryptosystem**: is a system where sender transforms unconcealed data called plain text into concealed data called cipher text using encryption algorithm

1. CAESAR CIPHER
1. MONOALPHABETIC CIPPHER
1. VIGENERE CIPHER
1. TRANSPOSITION CIPHERS
1. PLAYFAIR CIPHER

* **Block** ciphers are easier to optimize for software implementations  
* **Stream** ciphers are usually most efficient in hardware  


**DES**
1. 16 rounds fixed
1. 64-bit block length
1. 56-bit key
1. 48-bit subkeys

**AES**

1. 10, 12, 14 rounds
1. 128 block length
1. 128, 192, 256 bit key

***

# Network Security 

**Network segmentation**  
\
Segmentation by VLANs (Virtual Local Area Network)  
Segmentation by Firewall  
Segmentation by SDN (automated network overlay)

\
**Firewall** -> barrier that sits between a private internal network and the
public Internet,  that monitors incoming and outgoing
network traffic and decides whether to allow or block specific traffic based on a
defined set of security rules.  

The purpose of a firewall is to control the passage of TCP/IP packets between hosts and networks.  


\
* **Firewalls Types:**  
    * **Packet Filtering** (Stateless) => Packet filtering protects a local network from undesired invasion
depending upon the predefined rules. 
    *  **Stateful Inspection Firewall** => A stateful firewall is a firewall that monitors the full state of active
network connections  
    *  **Proxy Firewall** => An application proxy firewall processes incoming packets all the way
up to the application layer   
    *  **Circuit Gateway Firewall** =>  check for functional packets in an attempted connection, andвЂ”if
operating wellвЂ”will permit a persistent open connection between
the two networks.  
    *  **Next Generation Firewall (NGFW)** => Combines the features of a traditional firewall with network intrusion
prevention systems
вЂў Threat specific, вЂў Designed to examine and identify specific threats, such as advanced
malware, at a more granular level.  
    *  Hybrid Firewall => a hybrid firewall system might include a packet-filtering
firewall that is set up to screen all acceptable requests, then pass the requests to a proxy server, which in turn requests services from a Web server deep inside the organizationвЂ™s networks

\  
* **VPN**  
hides your IP address
    * Implementation of cryptographic technology  
    * Establishes a protected network connection when using public networks  
    * It is virtual because it exists as a virtual entity within a public network
    * It is private because it is confined to a set of private users
    * VPNs encrypt your internet traffic and disguise your online identity.
    * Basic VPN Requirements
        * User Authentication
        * Address Management 
        * Data Encryption
        * Key Management
        * Multi-protocol Support 


* **AUTHENTICATION METHODS**  

    * PASSWORD BASED AUTHENTICATION
    * BIOMETRIC AUTHENTICATION
    * SMART CARD AND OTHER HARDWARE TOKENS FOR
AUTHENTICATION
    * Two-factor Authentication(2FA)
    * Multi-factor Authentication (MFA)


* **Transport layer security (e.g. https)**
    * Protection of data from unauthorized access and modification when being it
is being transmitted between client (browser) and your application. (I.e.
вЂњsniffingвЂќ).
    * Possible solution is using HTTPS (HTTPS over SSL Protocol)
Public key cryptography is used to perform the handshake:
        * Client (browser) requests server certificate and authenticates it against
stored CA signatures.
        *  In the handshake, a shared session key is computed, which is used for the
rest of the session.
        * The session key is used to encrypt messages and protect their integrity.
        * If a client needs to access several secure pages at a server, a shorter
session resumption handshake is used for the other pages.
        * The server must maintain state (a session ID) and give this to the client to
enable session resumption.

    * HyperText Transfer Protocol Secure (HTTPS) is the secure version of HTTP. communication between your web application and the website is encrypted SSL or TLS encryption 
    
    * TLS / SSL -> asymmetric encryption
TLS (Transport Layer Security) is just an updated, more secure, version of SSL. 

    * The details of the certificate, including the issuing authority and the corporate name of the website owner, can be viewed by clicking on the lock symbol on the browser bar


* **Operating system hardening**
    * A technique that aims to reduce the number of openings through
which an operating system might be attacked
    * Remove all unnecessary software
    * Remove all unessential services
    * Alter default accounts
    * APPLY THE PRINCIPLE OF LEAST PRIVILEGE
    * Perform updates
    * Turn on logging and auditing


***
***
***

# Attaks 

1. **Malicious code**:  
    * Launching viruses, worms, Trojan horses, and active Web scripts aiming to steal or destroy info
    * attack vectors: IP Scan, Web browsing, Virus, Mass Mail, unprotected shaders.
    * COUNTERMEASURES: Install antivirus software on all systems, Keep all antivirus software up to date. Keep all systems up to date

1. **BACK DOORS**: 
    * Using a known or previously unknown and newly discovered access mechanism, an attacker can gain access to a system or network resource through a back door. 
    * Hard to detect>> often go undetected for several months

1. **PASSWORD CRACK**:
    * attempting to reverse calculate a password
    * Component of dictionary attacks

1. **BRUTE FORCE**
    * trying every possible combination of options of a password
    * Countermeasure: always change the manufacturerвЂ™s default
administrator account names and passwords

1. **DICTIONARY**
    * selects specific accounts to attack and uses commonly used
passwords (i.e., the dictionary) to guide guesses
    * Countermeasure: Guard against easy-to-guess passwords

1.  **DoS attack**  
    * Is an attack on computers and networks aiming at restricting or denying access to their services
    * Overloads a machine by sending more traffic than the target can handle

1.  **DDoS attack**  
    * a coordinated stream of requests is launched against a target from many locations at the same time.

1. **SPOOFING**  
    * a technique used to gain unauthorized access to computers
    * the intruder sends messages with a source IP address that has been forged to indicate that the messages are coming from a trusted host.
    * Various techniques used to obtain trusted IP addresses and modify
the packet headers

1. **MAN-IN-THE-MIDDLE**
    * an attacker monitors (or sniffs) packets from the network, modifies
them, and inserts them back into the network.
    * Use MiTM: spying or stealing
    
1. **SPAM**
    * Spam is unsolicited commercial e-mail
    * more a nuisance than an attack, though is emerging as a vector for some attacks
    * The most significant consequence of spam, however, is the waste of computer and human resources
    
1. **MAIL BOMBING**
    * Attacker routes large quantities of e-mail to the target
    * Also DoS
    * Can be accomplished by exploiting technical flaws in Simple Mail
Transport Server (SMTP)

1. **SNIFFERS**
    * program or device that monitors data traveling over network;
    * can be used both for legitimate purposes and for stealing information from a network
    * Often work on TCP/IP networks
    * Sometimes called packet sniffers
    
1. **SOCIAL ENGINEERING**
    * Use social skills and convince people to reveal access to credentials or other valuable information to the attacker
    * Phishing is one popular type of social engineering
    * Phishing scams are email and text message campaigns aimed at creating a sense of urgency, curiosity or fear in victims

1. **A TIMING ATTACK**
    * explores contents of a Web browserвЂ™s cache to create malicious cookie
    
1. **Sql Injection**
    * pushing in data SQL code through via GET, POST requests or Cookie values
    * use stored procedures
    * use prepareted Statements parameter are quoted 
    * excape user input 
    
1. **XSS ATTACK**
    * Cross-Site Scripting
A web security vulnerability in
which when hackers execute
malicious JavaScript within a
victimвЂ™s browser.
    * Since the JavaScript runs on the victimвЂ™s browser page, sensitive details about
the authenticated user can be stolen from the session
    * Filter all input from GET and POST
    * validate input with only specifyed chars

***
***
***
# Comands

## NMAP

1. nmap -> Scan a single host or an IP address
1. nmap -v -A  -> to OS and version detection
1. nmap -Pn -> Scaning a host when protected by the firewall
1. nmap -sP IP.0/24 ->  which servers and devices are up and running
1. nmap -p T:number, U:number -> Scan specific ports T-TCP, U-UDP
