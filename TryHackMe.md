# Pyramid of Pain: Hash value, IP address, Domain Names, Network, Tools, TTP
## Hash Values (Trival)
-> Hashing algorithm - MD5(Messege Digest, Defined by RFC 1321 Link:https://www.ietf.org/rfc/rfc1321.txt \
=> MD5 RFC 1321 hashes are not considered cryptographycally secure. but RFC 6151(LINK:https://datatracker.ietf.org/doc/html/rfc6151) , Updated security considerations for the MD5 message digest and the HMAC-MD5 algorithms which mentioned a number of attacks against MD5 hashes, Including the hash collision. \
=> Sha-1(Secure Hash Algorithm 1, defined by RFC 3174) when data is fed tp sha-1 hashing algorithm, sha-1 takes an input and produce a 160 bit hash value string as a 40 digit hexadecimal number. NIST deprected the use of sha-1 in 2011 and banned its use for digital signatiures at the end of 2013 based on it being susceptible to brute force attacks. Indtead NIST recommends migrating from SHA-1 to stronger hash algorithms in the SHA-2 and SHA-3 families. \
=> Study SHA-256.\
=> A hash is not considered to be cryptographically secure if two files have the same hash value or digest.

=> Various online tools can be used to do hash lookups like VirusTotal and Metadefender Cloud - OPSWAT. 
## IP addressing.
=> Attackers usually hide the malicious domains under URL shorteners.   A URL Shortener is a tool that creates a short and unique URL that will redirect to the specific website specified during the initial step of setting up the URL Shortener link. The attackers normally use the following URL-shortening services to generate malicious links: 
 
bit.ly \
goo.gl \
ow.ly \
s.id \
smarturl.it \
tiny.pl \
tinyurl.com \
x.co \
-> study: HTTP request, DNS request.
## Host artifacts
## Network Artifacts : LINK:https://datatracker.ietf.org/doc/html/rfc2616#page-145 
## Tools 
## TTPS 


# Cyber Kill Chain


=> Cyber kill chain will help you understand and protect against ransomeware attacks, security breaches as well as Advanced Persistent Threats(APTs). You can use the Cyber kill chain to assess your network and system security by identifying missing security controls and closing certain security gaps based on your company's infrastructure.

=> Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and control, Actions on Objectives

## Reconnaissance
=> It is the research and planning phase of an attack against the system or victim. Reconnaissance is often passive and undetected. Poor recon typically leads to sloppy attacks while well informed adversaries can create highly targated, believable payloads that increases their chances to success.

=> OSINT data can be collected from include: search engine, print and online media, social media accounts, online forums and blogs, online public record database, WHOIS and technical data.

=> recon type - Passive recon which involves having no direct interaction with the target. This may include WHOIS lookups, social media scraping or reviewing breach data. Active Recon involves direct contract with the target with activities such as social engineering, port scanning, banner grabing or probing open services.

=> Email harvesting: The attacker will have a big arsenal of tools available for reconnaissance purposes. Here are some of them:

theHarvester: other than gathering emails, this tool is also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources.
Hunter.io: this is an email hunting tool that will let you obtain contact information associated with the domain.
OSINT Framework: OSINT Framework provides the collection of OSINT tools based on various categories.(LINK:https://osintframework.com/)

## weaponization
=> Dark Web: LINK:https://www.kaspersky.com/resource-center/threats/deep-web

=> Malware is a program or software that designed to damage, disrupt or gain unauthorized access to a computer.

=> Exploits are programs or code that take advantage of the vulnerability or flaw in the application or system.

=> A payload is a malicious code that the attacker runs on the system.

=> Study: macros or VBA (Visual Basic for Applications) scripts

## Delivery
## Exploutation
=> Exploitation is the moment the attacker's code executes on the target, taking advantage of a known vulnerability. In this phase, Megatron can opt to utilise a number of key techniques to gain access:

Malicious macro execution: This may have been delivered through a phishing email, that would execute ransomware when the victim opens it.
Zero-day exploits: These leverages on unknown and unpatched flaws in a system. These exploits leave no opportunity for detection at the beginning.
Known CVEs: The attacker can choose to exploit unpatched public vulnerabilities found on the target environment.
After gaining access to the system, the malicious actor could exploit software, system, or server-based vulnerabilities to escalate the privileges or move laterally through the network. 

Signs of exploitation to look out for include:

Unexpected process spawns.
Registry changes or new services created.
Suspicious command-line arguments found in system logs.

## Installation
=> persistent backdoor

=> Meterpreter

=> technique is known as T1543.003 on MITRE ATT&CK 

=> the attacker can also use the Timestomping technique to avoid detection by the forensic investigator and also to make the malware appear as a part of a legitimate program. The timestomping technique lets an attacker modify the file's timestamps, including to modify, access, create and change times.

## Command and control

=> C&C or C2 Beaconing 

The most common C2 channels used by adversaries include:

HTTP on port 80 and HTTPS on port 443, where this type of beaconing blends the malicious traffic with the legitimate traffic and can help the attacker evade firewalls.

DNS (Domain Name Server), where the infected machine makes constant DNS requests to the DNS server that belongs to an attacker, this type of C2 communication is also known as DNS Tunnelling



# Unified Kill Chain (LINK:https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf)
=> a framework that is used to complement other frameworks such as MITRE.












