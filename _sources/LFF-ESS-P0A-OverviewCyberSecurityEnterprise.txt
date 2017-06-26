***********************************************************
The Essentials : Overview of Cybersecurity in an Enterprise
***********************************************************

This blog is about the cybersecurity in an Enterprise. We would start with a simple concept of two people ( Alice and Bob ) starting a new company and building it to Micro ( < 10 employees ), Small ( < 50 employees ), Medium-sized ( < 250 employees ), larger with security breaches, vulnerability assessments happening. We would mention a story, what all devices are required with what security etc. Hopefully this will provide a general life-cycle of what happens and how things/ security evolves at companies.

There are few terms which would come across:

* Current Users: This represents the number of people working in that company.
* Current Setup: This represents the current IT Infrastructure the company has.
* Security Additions: How we can improve the security of the current infrastructure.
* Operations Issues: Any challenges for the IT Team managing the IT Infrastructure.
* Operations Additions: How we can improve the management of IT Infrastructure. 

New Company
===========

Two friends Alice and Bob met up and decided to open a company called Fantastic Solutions. Alice loves Linux (Debian) and Bob loves Windows. So, let's see what they require at this current point of time?

Current Users 
-------------

2 Users

Current Setup
-------------

* Internet Connection
* Home Router with built in Wi-Fi
* Two laptops ( One Windows, One Linux )

Security Additions
------------------

Home Router wih built in Wi-Fi
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* WEP
* WPA
* WPA2-Enterprise
* Hidden SSID
* Home Router DNS Entry: No-Ads DNS Servers - free, global Domain Name System (DNS) resolution service, that you can use to block unwanted ads. Few examples are 

 * `Adguard DNS <https://adguard.com/en/adguard-dns/overview.html>`_
 * `OpenDNS <https://www.opendns.com/>`_

Micro Enterprise
================

The company started well and hired 8 more people ( Let's say two who loves Linux, two who loves Mac and two who loves Windows )

Current Users
-------------
10 People

Current Setup
-------------

* New Company Setup Included
* File Server ( Network Attached Storage )

Security Additions
------------------

* Windows - `Microsoft Baseline Security Analyser <https://www.microsoft.com/en-in/download/details.aspx?id=7558>`_ - The Microsoft Baseline Security Analyzer provides a streamlined method to identify missing security updates and common security misconfigurations.
* Linux/ Mac - `Lynis <https://cisofy.com/lynis/>`_ - Lynis is an open source security auditing tool. Used by system administrators, security professionals, and auditors, to evaluate the security defenses of their Linux and UNIX-based systems. It runs on the host itself, so it performs more extensive security scans than vulnerability scanners.
* File Server ( NAS ) : Access control lists on which folder can be accessed by which user or password protected folders.

Operations Issues
-----------------

* The MBSA and Lynis has to be executed on every machine individually.
* Administration of every individual machine is tough. Any changes in the security settings will have to be done manually by an IT person.

Small Enterprise
================

Current Users
-------------

45 People

Current Setup
-------------

* Micro Company Setup Included

Windows Domain Controller
^^^^^^^^^^^^^^^^^^^^^^^^^
Active Directory Domain Services provide secure, structured, hierarchical data storage for objects in a network such as users, computers, printers, and services.

Domain Name Server
^^^^^^^^^^^^^^^^^^
A DNS server hosts the information that enables client computers to resolve memorable, alphanumeric DNS names to the IP addresses that computers use to communicate with each other.

Windows Server Update Services (WSUS) Server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Windows Server Update Services (WSUS) enables information technology administrators to deploy the latest Microsoft product updates. A WSUS server can be the update source for other WSUS servers within the organization. Refer `Deploy Windows Server Update Services in Your Organization <https://technet.microsoft.com/en-us/library/hh852340(v=ws.11).aspx>`_ 

DHCP Server
^^^^^^^^^^^

Dynamic Host Configuration Protocol (DHCP) servers on your network automatically provide client computers and other TCP/IP based network devices with valid IP addresses.

Others
^^^^^^
* Company decided to take 8 Linux Servers ( Debian, CentOS, Arch-Linux and Red-Hat ).
* Added two servers hosting three web-application running on `IIS-WebServer <https://technet.microsoft.com/en-us/library/cc770634(v=ws.11).aspx>`_, `Apache Tomcat <http://tomcat.apache.org/>`_ and `Nginx <https://www.nginx.com/resources/wiki/>`_.

Operations Issues
-----------------

* How to manage multiple Linux machines and make sure they are hardened and compliant to security standards such as `CIS <https://www.cisecurity.org/cis-benchmarks/>`_ ( Center for Internet Security ) or `STIG <https://www.stigviewer.com/stigs>`_ ( Security Technical Implementation Guide ). 

Minimum Baseline Security Standard ( MBSS )
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
* STIG: A Security Technical Implementation Guide (STIG) is a cybersecurity methodology for standardizing security protocols within networks, servers, computers, and logical designs to enhance overall security. These guides, when implemented, enhance security for software, hardware, physical and logical architectures to further reduce vulnerabilities.
 
* CIS: CIS Benchmarks help you safeguard systems, software, and networks against today's evolving cyber threats. Developed by an international community of cybersecurity experts, the CIS Benchmarks are configuration guidelines for over 100 technologies and platforms.

Security Additions
------------------

Security Compliance Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^

`Security Compliance Manager <https://technet.microsoft.com/en-us/solutionaccelerators/cc835245.aspx>`_ : SCM enables you to quickly configure and manage computers and your private cloud using Group Policy and Microsoft System Center Configuration Manager. SCM 4.0 provides ready-to-deploy policies based on Microsoft Security Guide recommendations and industry best practices, allowing you to easily manage configuration drift, and address compliance requirements for Windows operating systems and Microsoft applications.

Operations Additions
--------------------

Infrastructure Automation Tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `Puppet <https://puppet.com/>`_ : Puppet is an open-source software configuration management tool. It runs on many Unix-like systems as well as on Microsoft Windows. It was created to easily automate repetitive and error-prone system administration tasks. Puppet's easy-to-read declarative language allows you to declare how your systems should be configured to do their jobs.
* `Ansible <https://www.ansible.com/>`_ is an open-source automation engine that automates software provisioning, configuration management, and application deployment
* `Salt <https://www.ansible.com/>`_ : Salt (sometimes referred to as the SaltStack Platform) is a Python-based open-source configuration management software and remote execution engine. Supporting the "Infrastructure as Code" approach to deployment and cloud management.
* `Chef <https://www.chef.io/>`_ : Chef lets you manage them all by turning infrastructure into code. Infrastructure described as code is flexible, versionable, human-readable, and testable.

Automation Tools Addition
^^^^^^^^^^^^^^^^^^^^^^^^^

If we are utilizing Automation Tools above, there are few other tools which should be known such as 

* `Inspec <https://www.chef.io/inspec/>`_ : InSpec is an open-source testing framework for infrastructure with a human-readable language for specifying compliance, security and other policy requirements. When compliance is code, you can integrate automated tests that check for adherence to policy into any stage of your deployment pipeline.

* `Rubocop <http://rubocop.readthedocs.io/en/latest/>`_ : RuboCop is a Ruby static code analyzer. Out of the box it will enforce many of the guidelines outlined in the community `Ruby Style Guide <https://github.com/bbatsov/ruby-style-guide>`_ . If we are writing code in ruby, rubocop makes sure that it is written according to the Ruby style guide.

* `Puppet-Linter <http://puppet-lint.com/>`_ : Puppet Lint tests Puppet code against the recommended Puppet language style guide. Puppet Lint validates only code style; it does not validate syntax.

* `Kitchen <http://kitchen.ci/>`_ : Kitchen provides a test harness to execute your infrastructure code on one or more platforms in isolation. A driver plugin architecture is used which lets you run your code on various cloud providers and virtualization technologies such as Amazon EC2, Google GCE, Azure, Blue Box, CloudStack, Digital Ocean, Rackspace, OpenStack, Vagrant, Docker, LXC containers, and more. In short, whatever code we wrote for one platform or operating system ( example: Debian 8 ), utilizing Kitchen, we can test it on multiple platforms.

Security Breach 1
=================

Let's assume a security breach happened at this point of time.

* Customer data was ex-filtrated from one of the internal servers. 
* A mis-configured web-application server was exploited and the Product website was defaced.
* Open SMTP Server: A internal employee was able to send a email posing as CFO and asked the finance department to transfer money to attackers bank.

Security Additions
------------------

ELK ( Elasticsearch, Logstash, and Kibana ) 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `Elasticsearch <https://www.elastic.co/products/elasticsearch>`_ : Elasticsearch is a distributed, RESTful search and analytics engine capable of solving a growing number of use cases. As the heart of the Elastic Stack, it centrally stores your data so you can discover the expected and uncover the unexpected.
* `Logstash <https://www.elastic.co/products/logstash>`_ : Logstash is an open source, server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it, and then sends it to your favorite “stash.” ( Elasticsearch ).
* `Kibana <https://www.elastic.co/products/kibana>`_ : Kibana lets you visualize your Elasticsearch data and navigate the Elastic Stack, so you can do anything from learning why you're getting paged at 2:00 a.m. to understanding the impact rain might have on your quarterly numbers.

Windows Event Forwarding
^^^^^^^^^^^^^^^^^^^^^^^^
Windows Event Forwarding (WEF) reads any operational or administrative event log on a device in your organization and forwards the events you choose to a Windows Event Collector (WEC) server. Jessica Payne has written a nice blog on `Monitoring what matters – Windows Event Forwarding for everyone (even if you already have a SIEM.) <https://blogs.technet.microsoft.com/jepayne/2015/11/23/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem/>`_  and Microsoft has written another nice blog `Use Windows Event Forwarding to help with intrusion detection <https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection>`_ 

* Japan Computer Emergency Response Team has very well written a practical guide on `Detecting Lateral Movement through Tracking Event Logs <https://www.jpcert.or.jp/english/pub/sr/ir_research.html>`_

Internet Proxy Server
^^^^^^^^^^^^^^^^^^^^^

Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator.

Web-Application Pentest
^^^^^^^^^^^^^^^^^^^^^^^

Performed Web-Application Internal Pentest using Open-Source Scanners such as `OWASP-ZAP ( Zed Attack Proxy ) <https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project>`_

Secure Coding Guidelines
^^^^^^^^^^^^^^^^^^^^^^^^

Implement

* `OWASP Secure Coding Practices <https://www.owasp.org/index.php/OWASP_Secure_Coding_Practices_-_Quick_Reference_Guide>`_
* `SEI CERT Coding Standards <https://www.securecoding.cert.org/confluence/display/seccode/SEI+CERT+Coding+Standards>`_

Web Application Firewall
^^^^^^^^^^^^^^^^^^^^^^^^

Deploy a Web Application Firewall (WAF): WAF is an application firewall for HTTP applications. It applies a set of rules to an HTTP conversation. Generally, these rules cover common attacks such as cross-site scripting (XSS) and SQL injection. One of the open source WAF is `Modsecurity <https://modsecurity.org/>`_

Medium Enterprise
=================

Current Users
-------------
700-1000

Current Setup
-------------

* Small Enterprise included + Security Additions after Security Breach 1
* 250 Windows + 250 Linux + 250 Mac-OS User

Operations Issues
-----------------

* Are all the network devices, operating systems security hardened according to CIS Benchmarks?
* Do we maintain a inventory of Network Devices, Servers, Machines? What's their status? Online, Not reachable? 
* Do we maintain a inventory of software installed in all of the machines? 

Operations Additions
--------------------

DevSec Hardening Framework
^^^^^^^^^^^^^^^^^^^^^^^^^^

Security Hardening utilizing `DevSec Hardening Framework <http://dev-sec.io/>`_ or Puppet/ Ansible/ Salt Hardening Modules. There are modules for almost hardening everything Linux OS, Windows OS, Apache, Nginx, MySQL, PostGRES, docker etc.

Inventory
^^^^^^^^^

* of Authorized Devices and Unauthorized Devices

 * `OpenNMS <https://www.opennms.org/en>`_: OpenNMS is a carrier-grade, highly integrated, open source platform designed for building network monitoring solutions.
 * `OpenAudit <http://www.open-audit.org/>`_: Open-AudIT is an application to tell you exactly what is on your network, how it is configured and when it changes.

* of Authorized Software and Unauthorized software.

Vulnerability Assessment
========================

* A external consultant connects his laptop on the internal network either gets a DHCP address or set himself a static IP Address or poses as an malicious internal attacker.
* Finds open shares accessible or shares with default passwords.
* Same local admin passwords as they were set up by using Group Policy Preferences! ( Bad Practice )
* Major attack vector - Powershell! Where are the logs?

Security Additions
------------------

Active Directory Hardening
^^^^^^^^^^^^^^^^^^^^^^^^^^

* Implement `LAPS <https://technet.microsoft.com/en-us/mt227395.aspx>`_ ( Local Administrator Password Solutions ): LAPS provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset. Every machine would have a different random password and only few people would be able to read it.

* Implement `Windows Active Directory Hardening Guidelines <https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory>`_

Network Access Control
^^^^^^^^^^^^^^^^^^^^^^

Implement

* `OpenNAC <http://opennac.org/opennac/en.html>`_ : openNAC is an opensource Network Access Control for corporate LAN / WAN environments. It enables authentication, authorization and audit policy-based all access to network. It supports diferent network vendors like Cisco, Alcatel, 3Com or Extreme Networks, and different clients like PCs with Windows or Linux, Mac,devices like smartphones and tablets.
* Other Vendor operated NACs

Application Whitelist/ Blacklisting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Allow only allowed applications to be run

* `Software Restriction Policies <https://technet.microsoft.com/en-us/library/hh831534(v=ws.11).aspx>`_: Software Restriction Policies (SRP) is Group Policy-based feature that identifies software programs running on computers in a domain, and controls the ability of those programs to run
* `Applocker <https://docs.microsoft.com/en-us/windows/device-security/applocker/applocker-overview>`_: AppLocker helps you control which apps and files users can run. These include executable files, scripts, Windows Installer files, dynamic-link libraries (DLLs), packaged apps, and packaged app installers.
   
* `Device Guard <https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies>`_:  Device Guard is a group of key features, designed to harden a computer system against malware. Its focus is preventing malicious code from running by ensuring only known good code can run. 

Detection Mechanism
^^^^^^^^^^^^^^^^^^^^

* Deploy `Microsoft Windows Threat Analytics <https://www.microsoft.com/en-us/cloud-platform/advanced-threat-analytics>`_ : Microsoft Advanced Threat Analytics (ATA) provides a simple and fast way to understand what is happening within your network by identifying suspicious user and device activity with built-in intelligence and providing clear and relevant threat information on a simple attack timeline. Microsoft Advanced Threat Analytics leverages deep packet inspection technology, as well as information from additional data sources (Security Information and Event Management and Active Directory) to build an Organizational Security Graph and detect advanced attacks in near real time.
* Deploy `Microsoft Defender Advance Threat Protection <https://www.microsoft.com/en-us/windowsforbusiness/windows-atp>`_: Windows Defender ATP combines sensors built-in to the operating system with a powerful security cloud service enabling Security Operations to detect, investigate, contain, and respond to advanced attacks against their network.

Security breach 2
=================

* A phishing email was sent to a specific user ( c-level employees ) from external internet.
* Country intelligence agency contacted and informed that the company ip address is communicating to a command and control center in a hostile country.
* Board members ask "what happened to cyber-security"?
* A internal administrator gone rogue.

Security Additions
------------------

Threat Intelligence
^^^^^^^^^^^^^^^^^^^

Must read MWR InfoSecurity `Threat Intelligence: Collecting, Analysing, Evaluating <https://www.ncsc.gov.uk/content/files/protected_files/guidance_files/MWR_Threat_Intelligence_whitepaper-2015.pdf>`_

* `Intel Critical Stack <https://intel.criticalstack.com/>`_ : Free threat intelligence aggregated, parsed and delivered by Critical Stack for the Bro network security monitoring platform.
* `Collective Intelligence Framework <http://csirtgadgets.org/>`_ : CIF allows you to combine known malicious threat information from many sources and use that information for identification (incident response), detection (IDS) and mitigation (null route). The most common types of threat intelligence warehoused in CIF are IP addresses, domains and urls that are observed to be related to malicious activity.
* `MANTIS (Model-based Analysis of Threat Intelligence Sources) <http://django-mantis.readthedocs.io/en/latest/>`_: MANTIS Framework consists of several Django Apps that, in combination, support the management of cyber threat intelligence expressed in standards such as STIX, CybOX, OpenIOC, IODEF (RFC 5070), etc.
* `CVE-Search <https://github.com/cve-search/cve-search>`_ : cve-search is a tool to import CVE (Common Vulnerabilities and Exposures) and CPE (Common Platform Enumeration) into a MongoDB to facilitate search and processing of CVEs. cve-search includes a back-end to store vulnerabilities and related information, an intuitive web interface for search and managing vulnerabilities, a series of tools to query the system and a web API interface.

Threat Hunting
^^^^^^^^^^^^^^

* `CRITS Collaborative Research Into Threats <https://crits.github.io/>`_ : CRITs is an open source malware and threat repository that leverages other open source software to create a unified tool for analysts and security experts engaged in threat defense. The goal of CRITS is to give the security community a flexible and open platform for analyzing and collaborating on threat data.
* `GRR Rapid Response <https://github.com/google/grr>`_ : GRR Rapid Response is an incident response framework focused on remote live forensics.

Sharing Threat Intelligence
^^^^^^^^^^^^^^^^^^^^^^^^^^^
 
* `STIX <https://oasis-open.github.io/cti-documentation/stix/about.html>`_ : Structured Threat Information Expression (STIX) is a language and serialization format used to exchange cyber threat intelligence (CTI). STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

* `TAXII <https://oasis-open.github.io/cti-documentation/>`_: Trusted Automated Exchange of Intelligence Information (TAXII) is an application layer protocol for the communication of cyber threat information in a simple and scalable manner. TAXII enables organizations to share CTI by defining an API that aligns with common sharing models. TAXII is specifically designed to support the exchange of CTI represented in STIX.

* `Malware Information Sharing Platform (MISP) <http://www.misp-project.org/>`_: A platform for sharing, storing and correlating Indicators of Compromises of targeted attacks.

Privilged Identity Mangement ( PIM ) 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PIM is the monitoring and protection of superuser accounts in an organization's IT environments. Oversight is necessary so that the greater access abilities of super control accounts are not misused or abused.

We hope that the above chain of events helped you to understand the IT Eco-system, Operations issues and the various security options available. If we have missed anything, please feel free to contribute.

.. disqus::
