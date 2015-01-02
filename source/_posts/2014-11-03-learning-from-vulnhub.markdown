---
layout: post
title: "Learning from VulnHub"
date: 2014-11-03 16:40:21 +0000
comments: true
categories: 
---
This post (Work in Progress) mark downs the learning gathered by doing the vulnerable machines provided by the VulnHub. Once you download the virtual machine from the website and run it in VMware or Virtual Box, below steps could be followed to find the vulnerabilties.
<!-- more -->
<ol>
{% comment %} 
First Point Starts
{% endcomment %}
<li>Finding the IP address:

<ul>
<li>Netdiscover:  an active/passive arp reconnaissance tool
{% codeblock %}
netdiscover [options] 
-i interface : The network interface to sniff and inject packets.
-r range     : Scan a given range instead of auto scan.

Example: netdiscover -i eth0/wlan0/vboxnet0/vmnet1 -r 192.168.1.0/24
{% endcodeblock %}
{% codeblock Interface name for Virtualization Software%}
Virtualbox   : vboxnet
Vmware       : vmnet
{% endcodeblock %}
</li>

<li>Nmap: Network exploration tool and security / port scanner
{% codeblock %}
nmap [Scan Type] [Options] {target specification}
-sP/-sn Ping Scan - disable port scan 
Example: nmap -sP/-sn 192.168.1.0/24
{% endcodeblock %}
</li>
</ul>
</li>
{% comment %} 
First Point Ends
{% endcomment %}
{% comment %} 
Second Point Starts
{% endcomment %}

<li>Port Scanning the system:
<br>
Port scanning provides a large amount of information on open services and possible exploits that target these services.
Two options
<ul>
<li>Unicornscan:  port scanner that utilizes it’s own userland TCP/IP stack, which allows it to run a asynchronous scans. Faster than nmap and can scan 65,535 ports in a relatively shorter time frame.
{% codeblock %}
unicornscan [options] X.X.X.X/YY:S-E
-i, --interface      : interface name, like eth0 or fxp1, not normally required
-m, --mode           : scan mode, tcp (syn) scan is default, U for udp T for tcp `sf' for tcp connect scan and A for arp
	               for -mT you can also specify tcp flags following the T like -mTsFpU for example that would send tcp syn packets with (NO Syn|FIN|NO Push|URG)

Address ranges are cidr like 1.2.3.4/8 for all of 1.?.?.?, if you omit the cidr mask then /32 is implied.
Port ranges are like 1-4096 with 53 only scanning one port, a for all 65k and p for 1-1024

example: unicornscan 192.168.1.5:1-4000 gateway:a would scan port 1 - 4000 for 192.168.1.5 and all 65K ports for gateway.
{% endcodeblock %}
</li>

<li>Nmap: Network exploration tool and security / port scanner
{% codeblock %}
nmap [Scan Type] [Options] {target specification}
HOST DISCOVERY:
-sL: List Scan - simply list targets to scan
-sn: Ping Scan - disable port scan
-Pn: Treat all hosts as online -- skip host discovery

SCAN TECHNIQUES:
-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
-sU: UDP Scan
-sN/sF/sX: TCP Null, FIN, and Xmas scans

PORT SPECIFICATION:
-p <port ranges>: Only scan specified ports
Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9

SERVICE/VERSION DETECTION:
-sV: Probe open ports to determine service/version info

OUTPUT:
-oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
-oA <basename>: Output in the three major formats at once
-v: Increase verbosity level (use -vv or more for greater effect)

MISC:
-6: Enable IPv6 scanning
-A: Enable OS detection, version detection, script scanning, and tracerout
{% endcodeblock %}
</li>
</ul>

As unicornscan is so fast, it makes sense to use it for scanning large networks or a large number of ports. The idea is to use unicornscan to scan all ports, and make a list of those ports that are open and pass them to nmap for service detection. <a href="https://twitter.com/superkojiman">superkojiman</a> has written a script for this available at <a href="https://github.com/superkojiman/onetwopunch">GitHub</a>.
</li>
<br>
{% comment %} 
Second Point Ends
{% endcomment %}
<li>Probing it further: 
<br>
At this point, you would have an idea about the different services and service version running on the system.
{% comment %} 
New Order List Start
{% endcomment %}
<ol>
<li>searchsploit: Exploit Database Archive Search.
<br>
First, we need to check if the operating system is using any services which are vulnerable or the exploit is already available in the internet.
For example, A vulnerable service webmin is present in <a href="http://vulnhub.com/entry/pwnos-10,33/">pWnOS 1.0</a> which can be exploited to extract information from the system.
{% codeblock %}
root@kali:~# nmap -sV -A 172.16.73.128
**********Trimmed**************
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| ndmp-version: 
|_  ERROR: Failed to get host information from server
**********Trimmed**************
{% endcodeblock %}

If you search for webmin in searchsploit, you would find different exploits available for it and you would just have to use the correct one based on the utility and the version matching.
{% codeblock %}
root@kali:~# searchsploit webmin
**********Trimmed**************
 Description                                                                            Path
----------------------------------------------------------------------------------------------------------------
Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit                   | /multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit (perl)            | /multiple/remote/2017.pl
Webmin 1.x HTML Email Command Execution Vulnerability                                | /cgi/webapps/24574.txt
**********Trimmed**************
{% endcodeblock %}
</li>
<li>Webserver Opportunities?:
<br>
<ul>
<li>Names? Possible Usernames? Possible Passwords?:
<br>
Sometimes, on visiting the webpage of the webserver (If Vulnerable machine is running any http/https webserver), you would found possible names of the employees working in the company. Now, it is common practise to have username based on your first/last name. It can be based on different combinations such as firstname.lastname or first letter of first name + lastname etc. <a href="https://twitter.com/superkojiman">superkojiman</a> has written a python script named "namemash.py" available at <a href="https://gist.githubusercontent.com/superkojiman/11076951/raw/namemash.py">here</a> which could be used to create possible usernames.
<br><br>
However, we still have a large amount of usernames to bruteforce with passwords. Further, if the vulnerable machine is running a SMTP mail server, we can verify if the particular username exists or not and modify namemash.py to generate usernames for that pattern.
<ol>
<li>Using metasploit smtp_enum module:
<br>
Once msfconsole is running, use auxiliary/scanner/smtp/smtp_enum, enter the RHOSTS (target address) and USER FILE containing the list of probable user accounts.
</li>
<li>Using VRFY command:</li>
<li>Using RCPT TO command:</li>
</ol>

</li>
</ul>
</li>
<br>
<li>FTP Opportunities:
<br>
If ftp anonymous login is provided or you have login details, you can download the contents by wget, (For anonymous login user password are not required)
{% codeblock %}
wget -rq ftp://<IP address> 
--ftp-user=username
--ftp-password=password
{% endcodeblock %}
</li>

</ol>
</li>

<li>Tips:
<ul>
<li>Wheel group typically has special(higer) privileges such as ability to become root, or the ability to bypass certain security restrictions.</li>
</ul>
</li>
</ol>
