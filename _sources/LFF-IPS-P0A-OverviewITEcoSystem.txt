==============================================
Overview of IT EcoSystem with Security:
==============================================

This blog is about the IT Ecosystem and how do we secure it? We would start with a simple concept of two people ( Alice and Bob ) starting a new company and building it to Micro ( < 10 employees ), Small ( < 50 employees ), Medium-sized ( < 250 employees ), larger with security breachs, vulnerablitiy assessments happening. We would mention a story, what all devices are required with what security etc. Hopefully this will provide a general lifecycle of what happens and how things/ security evolves at companies.

New Company
^^^^^^^^^^^

Two friends Alice and Bob met up and decided to open a company called Fantastics Solutions. Alice loves Linux (Debian) and Bob loves Windows. So, let's see what they require at this current point of time?

**Current Strength**: 2 People

**Current Setup**:

* Internet Connection
* Home Router with built in Wi-Fi
* Two laptops ( One Windows, One Linux )

Let's see what security options we have here:

* Home Router wih built in Wi-Fi

  * WEP
  * WPA
  * WPA2-Enterprise
  * Hidden SSID
  * Home Router DNS Entry: No-Ads DNS Servers - free, global Domain Name System (DNS) resolution service, that you can use to block unwanted ads. Few examples are 

   * `Adguard DNS <https://adguard.com/en/adguard-dns/overview.html>`_
   * `OpenDNS <https://www.opendns.com/>`_

Micro Enterprise
^^^^^^^^^^^^^^^^

The company started well and hired 8 more people ( Let's say two who loves Linux, two who loves Mac and two who loves Windows )

**Current Strength**: 10 People

**Current Setup**:

* New Company Setup Included
* File Server ( Network Attached Storage )

**Security Additions**:

* Windows - `Microsoft Baseline Security Analyser <https://www.microsoft.com/en-in/download/details.aspx?id=7558>`_ - The Microsoft Baseline Security Analyzer provides a streamlined method to identify missing security updates and common security misconfigurations.
* Linux/ Mac - `Lynis <https://cisofy.com/lynis/>`_ - Lynis is an open source security auditing tool. Used by system administrators, security professionals, and auditors, to evaluate the security defenses of their Linux and UNIX-based systems. It runs on the host itself, so it performs more extensive security scans than vulnerability scanners.
* File Server ( NAS ) : Access control lists on which folder can be accessed by which user or password protected folders.

**Operations Issues**:

* The MBSA and Lynis has to be executed on every machine individually.
* Administration of every individual machine is tough. Any changes in the security settings will have to be done manually by an IT person.

Small Enterprise
^^^^^^^^^^^^^^^^

**Current Strength**: 45 People

**Current Setup**:

* Micro Company Setup Included
* Windows Domain Controller : Active Directory Domain Services provide secure, structured, hierarchical data storage for objects in a network such as users, computers, printers, and services.
* Domain Name Server : A DNS server hosts the information that enables client computers to resolve memorable, alphanumeric DNS names to the IP addresses that computers use to communicate with each other.
* Windows Server Update Services (WSUS) Server : Windows Server Update Services (WSUS) enables information technology administrators to deploy the latest Microsoft product updates. A WSUS server can be the update source for other WSUS servers within the organization.
* DHCP Server : Dynamic Host Configuration Protocol (DHCP) servers on your network automatically provide client computers and other TCP/IP based network devices with valid IP addresses.
* Company decided to take 8 Linux Servers ( Debian, CentOS, Arch-Linux and Red-Hat ).

**Security Additions**:

* `Security Compliance Manager <https://technet.microsoft.com/en-us/solutionaccelerators/cc835245.aspx>`_ : SCM enables you to quickly configure and manage computers and your private cloud using Group Policy and Microsoft System Center Configuration Manager. SCM 4.0 provides ready-to-deploy policies based on Microsoft Security Guide recommendations and industry best practices, allowing you to easily manage configuration drift, and address compliance requirements for Windows operating systems and Microsoft applications.

**Operations Issues**:

* How to manage multiple Linux machines and make sure they are hardened and compliant to security standards such as `CIS <https://www.cisecurity.org/cis-benchmarks/>`_ ( Center for Internet Security ) or `STIG <https://www.stigviewer.com/stigs>`_ ( Security Technical Implementation Guide ). 

.. Note 

 STIG: A Security Technical Implementation Guide (STIG) is a cybersecurity methodology for standardizing security protocols within networks, servers, computers, and logical designs to enhance overall security. These guides, when implemented, enhance security for software, hardware, physical and logical architectures to further reduce vulnerabilities.
 CIS: CIS Benchmarks help you safeguard systems, software, and networks against today's evolving cyber threats. Developed by an international community of cybersecurity experts, the CIS Benchmarks are configuration guidelines for over 100 technologies and platforms.

**Operations Addition**:

* Infrastructure Automation Tools
 * Puppet : Puppet is an open-source software configuration management tool. It runs on many Unix-like systems as well as on Microsoft Windows. It was created to easily automate repetitive and error-prone system administration tasks. Puppet's easy-to-read declarative language allows you to declare how your systems should be configured to do their jobs.
 * Ansible is an open-source automation engine that automates software provisioning, configuration management, and application deployment
 * Salt : Salt (sometimes referred to as the SaltStack Platform) is a Python-based open-source configuration management software and remote execution engine. Supporting the "Infrastructure as Code" approach to deployment and cloud management.
 * Chef : Chef lets you manage them all by turning infrastructure into code. Infrastructure described as code is flexible, versionable, human-readable, and testable.

Security Breach 1:
^^^^^^^^^^^^^^^^^^

Let's assume a security breach happened at this point of time.

* Customer data was exfilterated from one of the internal servers. 
* A mis-configured server was exploited.
* Open SMTP Server: A internal employee was able to send a email posing as CFO and asked the finance department to transfer money to attackers bank.

**Security Additions**

* ELK ( Elasticsearch, Logstash, and Kibana ): 
 * Elasticsearch : Elasticsearch is a distributed, RESTful search and analytics engine capable of solving a growing number of use cases. As the heart of the Elastic Stack, it centrally stores your data so you can discover the expected and uncover the unexpected.
 * Logstash : Logstash is an open source, server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it, and then sends it to your favorite “stash.” ( Elasticsearch ).
 * Kibana : Kibana lets you visualize your Elasticsearch data and navigate the Elastic Stack, so you can do anything from learning why you're getting paged at 2:00 a.m. to understanding the impact rain might have on your quarterly numbers.

* Windows Event Forwarding : Windows Event Forwarding (WEF) reads any operational or administrative event log on a device in your organization and forwards the events you choose to a Windows Event Collector (WEC) server. Jessica Payne has written a nice blog on `Monitoring what matters – Windows Event Forwarding for everyone (even if you already have a SIEM.) <https://blogs.technet.microsoft.com/jepayne/2015/11/23/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem/>`_  and Microsoft has written another nice blog `Use Windows Event Forwarding to help with intrusion detection <https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection>`_ 

* Internet Proxy Server ( Squid ) : Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator.

Medium Enterprise:
^^^^^^^^^^^^^^^^^^^

**Current Users** : 700-1000
**Current Setup**

* Small Enterprise included + Security Additions after Security Breach 1
* 250 Windows + 250 Linux + 250 Mac-OS User

**Operations Issues**
* Are all the network devices, operatings systems security hardened according to CIS Benchmarks?
* Do we maintain a inventory of Network Devices, Servers, Machines? What's their status? Online, Not reachable? 
* Do we maintain a inventory of softwares installed in all of the machines? 

**Operations Additions**

* Security Hardening utilizing DevSec Hardening Framework or Puppet/ Ansible/ Salt Hardening Modules. There are modules for almost hardening everything Linux OS, Windows OS, Apache, Nginx, MySQL, PostGRES, docker etc.
* Inventory of Authorized Devices and Unauthorized Devices
 * OpenNMS: OpenNMS is a carrier-grade, highly integrated, open source platform designed for building network monitoring solutions.
 * OpenAudit: Open-AudIT is an application to tell you exactly what is on your network, how it is configured and when it changes.
* Inventory of Authorized Softwares and Unauthorized softwares.

Vulnerability Assessment 1
^^^^^^^^^^^^^^^^^^^^^^^^^^

* A external consultant connects his laptop on the internal network either gets a DHCP address or set himself a static IP Address or poses as an malicious internal attacker.
* Finds open shares accessible or shares with default passwords.
* Same local admin passwords as they were set up by using Group Policy Preferences! ( Bad Practise )
* Major attack vector - Powershell.

**Security Additions**

* Implement LAPS ( Local Administrator Password Solutions ): The "Local Administrator Password Solution" (LAPS) provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset. Every machine would have a different random password and only few people would be able to read it.

* Implement Network Access Control
 * OpenNAC : openNAC is an opensource Network Access Control for corporate LAN / WAN environments. It enables authentication, authorization and audit policy-based all access to network. It supports diferent network vendors like Cisco, Alcatel, 3Com or Extreme Networks, and different clients like PCs with Windows or Linux, Mac,devices like smartphones and tablets.
 * Other Vendor operated NACs

* Allow only allowed applications to be run
 * Software Restriction Policies: 
 * Applocker:
 * Device Guard:

* Implement Windows Active Directory Hardening Guidelines
* Deploy Microsoft Windows Threat Analytics
* Deploy Microsoft Defender Advance Threat Protection

Security Breach 2
^^^^^^^^^^^^^^^^^^

* A Phishing email was sent to a specific user ( C-Level Employees ) from external internet.
* Country Intelligence agency contacted and informed that the company IP Address is communicating to a Command and Control Center in a hostile country.
* Board Members ask "What happened to Cyber-Security"?
* A internal administrator gone rogue.

**Security Additions**

* Threat Intelligence : 

  * Intel Critical Stack
  * Collective Intelligence Framework
  * Mantisa
  * CVE-Search

* Threat Hunting:
 
 * CRITS
 * GRR
 * MISP

* Sharing Threat Intelligence
 
 * STIX
 * TAXII

* Privilged Identity Mangement: Privileged identity management (PIM) is the monitoring and protection of superuser accounts in an organization's IT environments. Oversight is necessary so that the greater access abilities of super control accounts are not misused or abused.
