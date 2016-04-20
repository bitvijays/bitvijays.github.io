---
layout: post
title: "Learning from the field: Intelligence Gathering"
date: 2015-04-09 10:23:38 +0530
comments: true
categories: 
---

This post (always Work in Progress) would list the technical steps which might be important while doing the intelligence gathering of an organization and we only know the company name or it's domain name such as example.com.
<!-- more -->

###Thanks to Vulnhub-ctf team, bonsaiviking, recrudesce, Rajesh and Tanoy.

Suppose, we have to do a external/ internal pentest of a big organization with DMZ, Data centers, Telecom network etc. We can either do <strong>Passive fingerprinting</strong> ( method to learn more about the enemy, without them knowing it ) or <strong>Active fingerprinting</strong> ( process of transmitting packets to a remote host and analysing corresponding replies ).
<br>
<br>
<strong>Passive fingerprinting</strong> and <strong>Active fingerprinting</strong> can be done by using various methods such as

<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}
.tg .tg-e3zv{font-weight:bold}
.tg .tg-yw4l{vertical-align:top}
</style>
<table class="tg">
  <tr>
    <th class="tg-e3zv">Passive Fingerprinting              </th>
    <th class="tg-e3zv">Active Fingerprintering</th>
  </tr>
  <tr>
    <td class="tg-031e">- whois</td>
    <td class="tg-031e">- Finding DNS, MX, AAAA, A</td>
  </tr>
  <tr>
    <td class="tg-031e">- ASN Number</td>
    <td class="tg-031e">- DNS Zone Transfer</td>
  </tr>
  <tr>
    <td class="tg-031e">- Enumeration with Domain Name</td>
    <td class="tg-031e">- SRV Records</td>
  </tr>
  <tr>
    <td class="tg-yw4l">- Publicly available scans of IP Addresses         </td>
    <td class="tg-yw4l">- Port Scanning</td>
  </tr>
  <tr>
    <td class="tg-yw4l">- Reverse DNS Lookup using External Websites         </td>
    <td class="tg-yw4l">-</td>
  </tr>
</table>

<br>
<ol>
<li><strong>Passive Fingerprinting:</strong>
<ol>
<li><strong>Whois</strong>: provide information about the registered users or assignees of an Internet resource, such as Domain name, an IP address block, or an autonomous system.
<br><br>
whois command acts differently for ip address and domain name. 
<ul>
<li>In Domain name it just provides registrar name etc.</li> 
<li>In IP address it provides the net-block ASN Number etc.</li>
</ul>
```
whois <Domain Name/ IP Address>
-H Do not display the legal disclaimers some registries like to show you.
```
<li><strong>ASN Number</strong>: We could find AS Number that participates in Border Gateway Protocol (BGP) used by particular organization which could further inform about the IP address ranges used by the organization.

ASN Number and information could be found by using Team CMRU whois service
```
whois -h whois.cymru.com " -v 216.90.108.31"
```
If you want to do bulk queries refer @ <a href="http://www.team-cymru.org/IP-ASN-mapping.html">IP-ASN-Mapping-Team-CYMRU</a>
<br>
<br>
Hurricane Electric Internet Services also provide a website <a href="http://bgp.he.net">BGP Toolkit</a> which provides your IP Address ASN or search function by Name, IP address etc. It also provides AS Peers which might help in gathering more information about the company in terms of it's neighbors. 
<br><br>
TODO: Commandline checking of subnet and making whois query efficient.<br>
</li>
<br>
<br>
<li><strong>Enumeration with Domain Name (e.g example.com) using external websites</strong>: If you have domain name you could use
<ul>
<li><strong>DNS Dumpster API</strong> to know the various sub-domain related to that domain.
```
#Script connects to the API and convert the required output to a CSV ready format.
#!/bin/bash
#$1 is the first argument to the script
curl -s http://api.hackertarget.com/hostsearch/?q=$1 > hostsearch
cat hostsearch | awk -F , '{print "\""$1"\""",""\""$2"\""}' > temp.csv
```
and the various dns queries by 
```
#Script connects to the API and greps only the Name Servers.
#!/bin/bash
#$1 is the first argument to the script
curl -s http://api.hackertarget.com/dnslookup/?q=$1 > dnslookup
cat dnslookup | grep -v RRSIG | grep -v DNSKEY | grep -v SOA | grep NS > temp
cat -T temp > temp2
cat temp2 | cut -d "I" -f7 | rev | cut -c 2- | rev
#rm temp temp2
```
</li>
<li><strong>Recon-ng:</strong>
<ul>
<li> use recon/domains-hosts/bing_domain_web : Harvests hosts from Bing.com by using the site search operator.</li>
<li> use recon/domains-hosts/google_site_web : Harvests hosts from google.com by using the site search operator.</li>
<li> use recon/domains-hosts/brute_hosts     : Brute forces host names using DNS.</li>
<li> use recon/hosts-hosts/resolve           : Resolves the IP address for a host.</li>
<li> use reporting/csv                       : Creates a CSV file containing the specified harvested data.</li>
</ul>
<br>
Jason Haddix has created a dynamic resource script for sub-domain discovery which is available <a href="https://github.com/jhaddix/domain">here</a>. Simply put the domain name and it runs the necessary modules, creates a new workspace and save the report. 
<br>
<br>
TODO: Check API option too, why google_site_web is failing, add a module to add ASN Info and Location Info too.
</li>
<br> 
<li><strong>The Harvester:</strong>
<br>The harvester provides a email address, virtual hosts, different domains, shodan results for the domain. Provides really good results, especially if you combine with shodan results as it may provide server versions and what's OS is running on the IP address.
```
Usage: theharvester options 

       -d: Domain to search or company name
       -b: data source: google, googleCSE, bing, bingapi, pgp
                        linkedin, google-profiles, people123, jigsaw, 
                        twitter, googleplus, all
       -v: Verify host name via dns resolution and search for virtual hosts
       -f: Save the results into an HTML and XML file
       -c: Perform a DNS brute force for the domain name
       -t: Perform a DNS TLD expansion discovery
       -e: Use this DNS server
       -h: use SHODAN database to query discovered hosts
```

TODO: Combine these results with recon-ng and DNS Dumpsters and create one csv with all results.
</li>
<br>
<li><strong>Google search operators</strong>
<ul>
<li><strong>site</strong>: Get results from certain sites or domains.</li>
<li><strong>filetype:suffix</strong>: Limits results to pages whose names end in suffix.  The suffix is anything following the last period in the file name of the web page. For example: filetype:pdf</li>
<li><strong>allinurl/inurl</strong>: Restricts results to those containing all the query terms you specify in the URL. For example, [ allinurl: google faq ] will return only documents that contain the words “google” and “faq” in the URL, such as “www.google.com/help/faq.html”.</li>
<li><strong>allintitle/intitle</strong>:Restricts results to those containing all the query terms you specify in the title.</li>
</ul>
Three good places to refer are <a href="https://support.google.com/websearch/answer/2466433">Search Operators</a>, <a href="https://sites.google.com/site/gwebsearcheducation/advanced-operators">Advanced Operators</a> and <a href="https://www.exploit-db.com/google-hacking-database/">Google Hacking Database</a>.
<br>
<br>
Another two important tools are 
<ul>
<li><a href="http://www.mcafee.com/in/downloads/free-tools/sitedigger.aspx">Mcafee Site Digger</a> which searches Google’s cache to look for vulnerabilities, errors, configuration issues, proprietary information, and interesting security nuggets on web sites.</li>
<li><a href="http://www.bishopfox.com/resources/tools/google-hacking-diggity/attack-tools/"><strong>SearchDiggity v3</strong></a>: It is Bishop Fox’s MS Windows GUI application that serves as a front-end to the most recent versions of our Diggity tools: GoogleDiggity, BingDiggity, Bing LinkFromDomainDiggity, CodeSearchDiggity, DLPDiggity, FlashDiggity, MalwareDiggity, PortScanDiggity, SHODANDiggity, BingBinaryMalwareSearch, and NotInMyBackYard Diggity.</a></li>
</ul>
</li>
<br>
<li><strong>Publicly available scans of IP Addresses</strong>
<ul>
<li><a href="https://exfiltrated.com/"><strong>Exfiltrated</strong></a>: It provides the scans from the 2012 Internet Census. It would provide the IP address and the port number running at the time of scan in the year 2012.</li>
<li><a href="https://www.shodan.io/"><strong>Shodan</strong></a>: Shodan provides the same results may be with recent scans. You need to be logined. Shodan CLI is available at <a href="https://cli.shodan.io/">Shodan Command-Line Interface</a></li>
<br>
Shodan Queries
```
title: Search the content scraped from the HTML tag
html: Search the full HTML content of the returned page
product: Search the name of the software or product identified in the banner
net: Search a given netblock (example: 204.51.94.79/18)
version: Search the version of the product
port: Search for a specific port or ports
os: Search for a specific operating system name
country: Search for results in a given country (2-letter code)
city: Search for results in a given city
```
TODO: Learn how to access Shodan with API.
<li><a href="http://www.netmux.com/"><strong>Netmux</strong></a>: NETMUX is the all-source information hub about every IP address, device, IOT, or domain on the internet. All with a single query.</li>
<li><a href="https://censys.io/"><strong>Censys</strong></a>: Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet. Driven by Internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, websites, and certificates are configured and deployed. A good feature is the Query metadata which tells the number of Http,https and other protocols found in the IP network range.
<br>
Censys.io queries
```
ip:192.168.0.0/24 -- CIDR notation
```</li>
</ul>
</li>
</ul>
</li>
<li><strong>Reverse DNS Lookup using External Websites:</strong> Even after doing the above, sometimes we miss few of the domain name. Example: Recenlty, In one of our engagement, the domain name was example.com and the asn netblock was 192.168.0.0/24. We did recon-ng, theharvester, DNS reverse-lookup via nmap. Still, we missed few of the websites hosted on same netblock but with different domain such as exam.in. We can find such entries by using ReverseIP lookup by 
<ul>
<li><a href="http://reverseip.domaintools.com">Reverse IP Lookup by Domaintools</a>: Domain name search tool that allows a wildcard search, monitoring of WHOIS record changes and history caching, as well as Reverse IP queries.</li>
<li><a href="https://www.passivetotal.org/">Passive Total</a> : A threat-analysis platform created for analysts, by analysts.</li>
<li><a href="http://serversniff.net.ipaddress.com/">Server Sniff</a> :  A website providing IP Lookup, Reverse IP services.</li>
<li><a href="https://www.robtex.com/">Robtex</a> : Robtex is one of the world's largest network tools. At robtex.com, you will find everything you need to know about domains, DNS, IP, Routes, Autonomous Systems, etc.

There's a nmap nse <a href="https://nmap.org/nsedoc/scripts/http-robtex-reverse-ip.html">http-robtex-reverse-ip</a> which can be used to find the domain/website hosted on that ip.
```
nmap --script http-robtex-reverse-ip --script-args http-robtex-reverse-ip.host='XX.XX.78.214'

Starting Nmap 7.01 ( https://nmap.org ) at 2016-04-20 21:39 IST
Pre-scan script results:
| http-robtex-reverse-ip: 
|   xxxxxxindian.com
|_  www.xxxxxindian.com
```
 </li>
</ul></li>
</ol>
 </li>
<li><strong>Active Fingerprinting:</strong>
<ol>
Above all methods, would help you to provide information without actually interacting with the client infrastructure.
<li>Most probably by now we have gathered all the public available information without interacting with client infrastructure. Next, we can use <strong>DNS enumeration</strong> to gather more information about the client. The below information could gather externally as well as internally. However, amount of information gathered from internal network would definitely be more than when done externally.
<br>
<br>
<strong>Finding DNS, MX, AAAA, A using</strong> 

<ul> 
<li><strong>host:</strong>
```
host <domain> <optional_name_server>
host -t ns <domain>           -- Name Servers
host -t a <domain>            -- Address
host -t aaaa <domain>         -- AAAA record points a domain or subdomain to an IPv6 address
host -t mx <domain>           -- Mail Servers   
host -t soa <domain>          -- Start of Authority
host <IP>                     -- Reverse Lookup
```

Example:
```
host -t ns zonetransfer.me
zonetransfer.me name server nsztm1.digi.ninja.
zonetransfer.me name server nsztm2.digi.ninja.
```
</li>
<li><strong>nslookup:</strong>
```
nslookup - <optional_name_server>
set type=mx
set type=ns
```
</li>
<li><strong>DNS Zone Transfer:</strong>
Using
<ul>
<li><strong>host:</strong>
```
host -l <Domain Name> <DNS Server>
```
Try zonetransfer using host for zonetransfer.me using their name servers. </li>
<li><strong>Dig:</strong>
```
dig axfr <domain_name> @nameserver
```
Try zonetransfer using dig for zonetransfer.me using their name servers.</li>
<li><strong>dnsrecon</strong>
```
dnsrecon -d <domain> -t axfr
```
dnsrecon could also be used for other purposes such as finding nameservers, mailserver, forward reverse lookup
```
-d, --domain      <domain>          Domain to Target for enumeration.
-r, --range       <range>           IP Range for reverse look-up brute force in formats (first-last) or in (range/bitmask).
-n, --name_server <name>            Domain server to use, if none is given the SOA of the target will be used
```
</li>
<li><strong>DNSEnum: </strong>DNS Enumeration tool
```
dnsenum <domain>
```</li>
Ideally, we should try every DNS server to do a zone transfer because there might be a probability of one mis-configured dns server. Also, DigiNinja a well known security researcher has made the domain zonetransfer.me available for testing and learning, so you can test the online zone transfer and other queries with the deliberately configured zone transfer capable domain.

<br><br>
</ul></li>
<li><strong>SRV Records:</strong><br>
Service record (SRV record) is a specification of data in the Domain Name System defining the location, i.e. the hostname and port number, of servers for specified services.

An SRV record has the form:
```
_service._proto.name. TTL class SRV priority weight port target.

service  : the symbolic name of the desired service.
proto    : the transport protocol of the desired service; this is usually either TCP or UDP.
name     : the domain name for which this record is valid, ending in a dot.
TTL      : standard DNS time to live field.
class    : standard DNS class field (this is always IN).
priority : the priority of the target host, lower value means more preferred.
weight   : A relative weight for records with the same priority, higher value means more preferred.
port     : the TCP or UDP port on which the service is to be found.
target   : the canonical hostname of the machine providing the service, ending in a dot.
```
<strong>Retrieving an SRV record:</strong>
```
 $ dig _sip._tls.example.com SRV

 $ host -t SRV _sip._tls.example.com

 $ nslookup -querytype=srv _sip._tls.example.com

 $ nslookup
 > set querytype=srv
 > _sip._tls.example.com
```
<strong>Usage:</strong>
SRV records are used by the below standardized communication protocols.
```
Teamspeak 3 (since version 3.0.8 - Neither priority nor weight is taken into consideration. The client appears to choose an SRV record at random for a connection attempt.[1])
Minecraft (since version 1.3.1, _minecraft._tcp)
CalDAV and CardDAV
Client SMTP Authorization
DNS Service Discovery (DNS-SD)
IMPS
Kerberos
LDAP
Puppet
SIP
XMPP
Mail submission, Post Office Protocol, and Internet Message Access Protocol
Libravatar uses SRV records to locate avatar image servers
Microsoft Lync
Citrix Receiver
```
Checkout the brute_srv function in the dnsrecon tool script to get familar with the different SRV names and services.
</li>
</ul>
</li>
</ol>
<br>
<br>
<li><strong>Internal Infrastructure Mapping:</strong>
<br>
All the steps in 2.a which are DNS related recon could also be performed in the internal penetration testing provided we have the access to the internal DNS Server. After, we have gathered all the information from DNS enumeration, still we haven't enumerated internal infrastructure. We apply the below methods to enumerate further.
<br>
<ol>
<li>
<strong>Internal range identification:</strong>
<br>
In many instances, we are provided or expected to find vulnerabilities in a 10.0.0.0/8 network which would contain around 16 million IP Addresses. Scanning 16 million IP address in a considerable time is difficult. In which case, we need faster and targeted result. So, how do we find out the ranges?
<ul>
<br>
<li><strong>DNS Enumeration:</strong>
<br>
If you are connected to a internal dns server, you may query it with
```
dig -t any <domainname>
```
which should result in outputting different name servers, mail servers, A, AAAA, SOA records which would possibly give you a inner scenario how the network has been designed as there can be different nameservers, domain controllers for different locations, internal departments etc.
<br>
TODO: Convert dig output directly into hostname, ip address format.<br></li>
<li>
<strong>Internal Portal Links:</strong>
Most of the organization have one internal portals which serves has a one-stop links to every possible portal link. This could also result in some internal range exposure.
<br>
TODO: Write the script for grep and printing host and IP address and combine it with DNS Enumeration. 
</li>
<li><strong>Reverse DNS Lookup:</strong>
<br>
Nmap provides a List scan option which does the reverse lookup. It provides the hostnames of the IP Address
```
nmap -sL 10.0.0.0/8

It can also be used with the below options:
 --randomize-hosts  : make the scans less obvious to various network monitoring systems
 --dns-servers server1,server2 : By default, it would use the dns servers which are listed in resolve.conf (if you haven't used --system-dns option). We can also list custom servers using these options.
```</li>
</ul>
</li>
<li><strong>Identifying Alive IP Addresses:</strong><br>
Nmap by default provides a -sn Ping scan option. The default host discovery done with -sn consists of an ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default. This works as if ICMP echo request is blocked, nmap would know if a host is alive if it receives any response from port 443 or 80 or timestamp reply.
<br><br>
Let's see what the nmap does when do a ping scan.
```
nmap -sn -n 10.0.0.230
#My IP is 10.0.0.1
```
It is very important to mention that -n option (No DNS resolution) should be used going forward as we have already did DNS resolution while using List scan. Since DNS can be slow even with Nmap's built-in parallel stub resolver, this option can slash scanning times.
<br><br>
TCP Dump output is presented here. As both the IP address are in the same subnet, nmap would use ARP Ping scan to find the alive IP Address.
```
22:11:27.292054 ARP, Request who-has 10.0.0.230 (Broadcast) tell 10.0.0.1, length 28
22:11:27.361100 ARP, Reply 10.0.0.230 is-at 8c:64:22:3b:2b:2d (oui Unknown), length 28
```

However, this behavior can be changed using --disable-arp-ping
```
nmap -sn 10.0.0.230 --disable-arp-ping
```
TCPdump output is as below: One ICMP Echo Request, SYN to Port 443, ACK to Port 80 and a time stamp request.
```
22:14:02.742180 IP 10.0.0.1 > 10.0.0.230: ICMP echo request, id 45066, seq 0, length 8
22:14:02.742222 IP 10.0.0.1.59246 > 10.0.0.230.https: Flags [S], seq 3994420539, win 1024, options [mss 1460], length 0
22:14:02.742234 IP 10.0.0.1.59246 > 10.0.0.230.http: Flags [.], ack 3994420539, win 1024, length 0
22:14:02.742241 IP 10.0.0.1 > 10.0.0.230: ICMP time stamp query id 38635 seq 0, length 20
22:14:02.801243 IP 10.0.0.230 > 10.0.0.1: ICMP echo reply, id 45066, seq 0, length 8
22:14:02.801930 IP 10.0.0.230.https > 10.0.0.1.59246: Flags [R.], seq 0, ack 3994420540, win 0, length 0
22:14:02.805083 IP 10.0.0.230.http > 10.0.0.1.59246: Flags [R], seq 3994420539, win 0, length 0
22:14:02.805930 IP 10.0.0.230 > 10.0.0.1: ICMP time stamp reply id 38635 seq 0: org 00:00:00.000, recv 16:40:52.731, xmit 16:40:52.731, length 20
```

If you use --reason option, nmap would tell why it thinks the host is alive. In the below case (received echo-reply).
```
Nmap scan report for 10.0.0.230
Host is up, received echo-reply (0.073s latency).
```
If we only want to send ICMP Ping query ( as if the host replies to it, the other three packets (SYN 443, ACK 80 and Timestamp ) are extra burden. ( I may be wrong here)
We can use
```
nmap -n -sn -PE --disable-arp-ping 10.0.0.230 
```
TCP Dump output:
```
22:30:20.768525 IP 10.0.0.1 > 10.0.0.230: ICMP echo request, id 39366, seq 0, length 8
22:30:20.826098 IP 10.0.0.230 > 10.0.0.1: ICMP echo reply, id 39366, seq 0, length 8
```

Please note, this ICMP scan would miss all the host which are alive but the firewall is dropping the ICMP echo request packet. However, if you want to find more hosts, it would be advisable to separate the list of IPs which responded to ICMP from the IP address scan range and run the scan again may be with SYN to 443 and ACK to 80 using PA, PS options.
<br><br>
Please also note Nmap's ICMP ping, by default, sends zero data as part of the ping. Nmap typically pings the host via icmp if the user has root privileges, and uses a tcp-ping otherwise. This is easily detected by the Snort IDS Rule 1-469 <a href="https://www.snort.org/rule_docs/1-469">SID 1-469</a>.
<br><br>
This could be evaded by using 
```
--data <hex string> (Append custom binary data to sent packets)
--data-string <string> (Append custom string to sent packets)
--data-length <number> (Append random data to sent packets)
```
Please note that you should use this options only on ICMP Echo Request for IDS Evasion as the data gets appended to every packet (ex. port scan packets).
<br>
<br>
Designing the ideal combinations of probes as suggested in the Nmap Book is 
```
-PE -PA -PS 21,22,23,25,80,113,31339 -PA 80,113,443,10042
Adding --source-port 53 might also help
```
The above combination would find more hosts than just the ping scan, however it also gonna cost a decent amount of time. Normal Time vs Accuracy trade off.
</li>

<li><strong>Port Scanning:</strong><br>
Once you have the list of IP Addresses which are alive, we can do port scan on them. Nmap provides multiple options such as
```
-sS TCP SYN Stealth : Half Open SYN Scan : Nmap sends the SYN packet, Server would send SYN/ACK, System would send RST.
-sT TCP Connect Scan : Nmap uses system to send the SYN scan : Connect full TCP Handshake
-sU UDP Scan 
-sA ACK Scan : Ack scan is generally used to map out firewall rulesets. Whether firewall is stateful or not.
``` 

Please note p0f recognizes Nmap's SYN scan because of the TCP Options such as TCP window size a multiple of 1024, and only the MSS option supported with a value of 1460 (Check the tcpdump output of Ping scan above, SYN Packet). Recently, a IRC user was getting filtered port while using SYN Scan whereas was getting OPN ports which using telnet or TCP Connect Scan.

Also, A patch to allow a user to override the TCP Window size in SYN scan was just posted to the <a href="http://seclists.org/nmap-dev/2015/q3/52">Nmap Development List</a>.

<br><br>
By default, nmap scans the 1000 most popular ports of each protocol ( gathered by scanning million of IP address). Scanning 1000 ports in an unknown environment with 16 million IP Address could be challenging. Nmap also provides -F Fast scan option which scans the 100 most common ports in each protocol. Otherwise it also provides --top-ports to specify an arbitrary number of ports.
<br><br>
So, How do we know what are the ports scanned with --top-ports option. This could be found by
```
nmap -sT -oG - -v | grep '^# Ports'
```
or
```
nmap localhost -F -oX - | grep '^<scaninfo'
```
Nmap needs an nmap-services file with frequency information in order to know which ports are the most common. See the section called <a href="http://seclists.org/nmap-dev/2015/q3/52">Well Known Port List: nmap-services</a> : for more information about port frequencies.
<br>
We could provide ports to nmap by using -p option also, for example
```
-p 22 : Scan single port
-p 22,25,80 : Scan multiple ports with comma separated values. If -sS is specified TCP ports would be scanned. If -sU UDP Scan is specified, UDP Ports would be scanned.
-p80-85, 443, 8000-8005 : Scan port with ranges.
-p- : Scan all the ports excluding 0.
-pT:21,22,25,U:53,111,161 : Scan TCP 21,22,25 and UDP Ports 53,111,161. -sU must also be specified.
-p http* : wild cards may be used for ports with similar names. This would match nine ports including 80,280,443,591,593,8000,8008,8080,8443.
```

<strong>Identifying service versions:</strong>
<br>
Ideally, we can use -sV to probe the ports to find the version running. When performing a version scan (-sV), Nmap sends a series of probes, each of which is assigned a rarity value between one and nine.  The higher the number, the more likely it is the service will be correctly identified. However, high intensity scans take longer. The intensity must be between 0 and 9. The default is 7.
<br><br>
Ideally, to avoid the IDS Detection, we should avoid using -sV option. However, we can keep the noise less by using --version intensity by which we can control the number of probes sent to determine the service. Setting this option to 0 will send only the Null probe (connect and wait for banner) and any probes that have been specifically listed as pertaining to the scanned port in nmap-service-probes. The other options available are below:
```
--version-light (Enable light mode) : Alias for --version-intensity 2.
--version-all (Try every single probe) : An alias for --version-intensity 9
--version-trace (Trace version scan activity) : Print debugging information.
```

Also, when -sV is specified apart from the probes, all the scripts in the <a href="https://nmap.org/nsedoc/categories/version.html">Version</a> category are executed. These scripts could be prevented from running by removing them from the script.db catalog or by building Nmap without NSE support (./configure --without-liblua). However, if --version-intensity option is less than 7, those scripts won't be executed ( I might be a little wrong here).
<br>
So our scan would become approx
```
nmap <IP_Address_Range> -n --top-ports <number>/-p <Custom Port List> -sV --version-intensity 0/ (No -sV)
```

<strong>Performance:</strong>
So, How can we improve the performance of our nmap scan, so that result could be achieved faster. However, as always we will have Time Vs Accuracy Trade off.
```
-T<0-5>: Set timing template (higher is faster)
--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies probe round trip time.
--max-retries <tries>: Caps number of port scan probe retransmissions.
--host-timeout <time>: Give up on target after this long
--scan-delay/--max-scan-delay <time>: Adjust delay between probes
--min-rate <number>: Send packets no slower than <number> per second
--max-rate <number>: Send packets no faster than <number> per second
```

T0,T1,T2 is specifically for IDS Evasion. T3 is the default.<br>

We can set max-retries to a lower value such as 2. Currently it's 10 for T0,T1,T2,T3; 6 for T4 and 2 for T5.
<br><br>
<strong>Nmap Scripts:</strong>
<br>
As bonsaiviking says <a href="http://blog.bonsaiviking.com/2015/07/they-see-me-scannin-part-2.html">Here</a>:<br>
If you are wild enough to try NSE scripts against an IDS-protected target, you should know how to read Lua, since the script sources are the final authority on what data is sent. But if you're just looking to get a little better at blending in, these tips should help:
<ul>
<li>Use --script-args-file to pass script arguments to Nmap from a file. This will keep your command line clean and make it harder to accidentally miss one of the options you choose</li>
<li>Obviously avoid dos, intrusive, and exploit category scripts.</li>
<li>Use scripts by name instead of by category, so that you know exactly what will be run.</li>
<li>Thoroughly read the documentation for each script you intend to use.</li>
<li>Set http.useragent to something believable that blends in. Currently, The HTTP scripts all use a User-Agent header that identifies as "Nmap Scripting Engine."</li>
</ul>
<br>
<strong>Output Options:</strong>
```
-oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
-oA <basename>: Output in the three major formats at once
--reason: Display the reason a port is in a particular state
--open: Only show open (or possibly open) ports
--packet-trace: Show all packets sent and received
--resume <filename>: Resume an aborted scan : Filename should be .nmap or .gnmap
```

At this point, it's good to find what are the most common ports open in the scan we just performed by
```
grep "^[0-9]\+" <nmap file .nmap extension> | grep "\ open\ " | sort | uniq -c | sort -rn | awk '{print "\""$1"\",\""$2"\",\""$3"\",\""$4"\",\""$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13"\""}' > test.csv
```
</li>
<li><strong>Exploring the Network Further:</strong><br>
By now, we would have information about what ports are open and possibly what services are running on them. Further, we need to explore the various options by which we can get more information.<br>
<ul>
<br>
<strong>Gathering Screenshots for http* services:</strong><br>

There are four ways (in my knowledge to do this)
<li><strong>http-screenshot NSE</strong>:<br> Nmap has a NSE script <a href="https://github.com/SpiderLabs/Nmap-Tools/blob/master/NSE/http-screenshot.nse">http-screenshot</a> This could be executed while running nmap. It uses wkhtml2image tool in the script. Sometimes, you may find that running this script takes a long time. It might be a good idea to gather all the http* running IP, Port and provide this information to wkhtml2image directly via scripting. You do have to install wkhtml2image and test with disable javascript and other options available.</li>
<li><strong>httpscreenshot</strong> from breenmachine: <a href="https://github.com/breenmachine/httpscreenshot">httpscreenshot</a>  is a tool for grabbing screenshots and HTML of large numbers of websites. The goal is for it to be both thorough and fast which can sometimes oppose each other.</li>
<li><strong>Eyewitness</strong> from Chris Truncer: <a href="https://github.com/ChrisTruncer/EyeWitness">EyeWitness</a>  is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.</li>
<li>Another method is to use <a href="https://code.google.com/p/java-html2image/">html2image</a> which is a simple Java library converts plain HTML markup to image and provides client-side image-map using HTML <map> element.</li>

<br>
<strong>Information gathering for http* services:</strong><br>
<br>
<li><strong>RAWR: Rapid Assesment of Web Resourses</strong>:<br> <a href="https://bitbucket.org/al14s/rawr/wiki/Home">RAWR</a> provides with a customizable CSV containing ordered information gathered for each host, with a field for making notes/etc.; An elegant, searchable, JQuery-driven HTML report that shows screenshots, diagrams, and other information. A report on relevent security headers. In short, it provides a landscape of your webapplications. It takes input from multiple formats such as Nmap, Nessus, OpenVAS etc.</li>
<li> <a href="http://www.morningstarsecurity.com/research/whatweb"><strong>WhatWeb</strong></a> recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded device.  <a href="https://www.aldeid.com/wiki/Tellmeweb">Tellmeweb</a> is a ruby script to read Nmap Gnmap file and run whatweb on all of them. A <a href="https://github.com/stevecoward/whatweb-parser">WhatWeb Result Parser</a>  also has been written  which converts the results to CSV format. More information about advance usage can be found <a href="https://github.com/urbanadventurer/WhatWeb/wiki/Advanced-Usage">here</a>.</li>
<li><a href="http://wappalyzer.com"><strong>Wapplyzer</strong></a> is a Firefox plug-in. It works only on regular expression matching and doesn't need anything other than the page to be loaded on browser. It works completely at the browser level and gives results in the form of icons.</li>
<li><a href="http://w3techs.com/"><strong>W3Tech</strong></a> is another Chrome plug-in which provides information about the usage of various types of technologies on the web. It tells the web technologies based on the crawling it has done. So example.com, x1.example.com, x2.example.com will show the same technologies as the domain is same (which is not correct).</li>
<li><a href="https://github.com/justjavac/ChromeSnifferPlus"><strong>ChromeSnifferPlus</strong></a> is another chrome extension to sniff about the different web-technologies used by the website.</li>
<li><a href="http://builtwith.com/"><strong>BuiltWith</strong></a> is another website which provides a good amount of information about the different technologies used by website.</li>
</ul>
</li>
<li><strong>NetBIOS Service:</strong> 
<br>
Netbios listens on TCP Port 139, 445 and UDP Port 137.
<br><br>
How do we machines on which these three ports or a combination are open and feed that IP information to nbtscan and enum4linux.
We can do this by using grep such as
```
grep -E "^Host.*[ ]137/open/udp" <Nmap .gnmap file>     : Grep 137 UDP Ports to run nbtscan
grep -E "^Host.*[ ]139/open/tcp" <Nmap .gnmap file>     
#If we want that tcp port 139 and 445 both must be open
grep -E "^Host.*[ ]139/open/tcp" <Nmap .gnmap file> | grep -E "^Host.*[ ]445/open/tcp" <Nmap .gnmap file> : Grep TCP 135 and 445 port to run enum4linux
#If we want that tcp port 139 or 445 must be open
grep -E "^Host.*[ ]139/open/tcp|[ ]443/open/tcp" <Nmap .gnmap file>
```
<ul>
<li><strong>NBTSCAN:</strong>
```
nbtscan
-v        Verbose output. Print all names received from each host.
-f filename     Take IP addresses to scan from file "filename"
```</li>
<li><strong>enum4linux</strong>: A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts. It is is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. A very good usage guide is <a href="https://labs.portcullis.co.uk/tools/enum4linux/">here</a>
```
enum4linux -a 192.168.2.55  : enumerate all the information it can from a remote host
```
 </li>
</ul>
</li>
<li><strong>SNMP Enumeration:</strong>
<br>
For SNMP Enumeration, UDP Port 161 should be open.
If the port 161 is open we can use
<ul>
<li><strong>snmpcheck:</strong>
```
snmpcheck -t <IP address>
-c : SNMP community; default is public
-v : SNMP version (1,2); default is 1
-w : detect write access (separate action by enumeration)
```</li>
<li>
<strong>snmpwalk:</strong>
<br>
It also allows us to interact with the SNMP version 3. It also allows to extract particular nodes of a MIB tree.
```
snmpwalk -­c public ­‐v1 <IP Address>  : Enumerating  the  Entire  MIB  Tree
snmpwalk -­c public ­‐v1 <IP Address>  <MIB Tree Number> : Enumerate particular node
-v 1|2c|3		specifies SNMP version to use
-c COMMUNITY		set the community string
```
</li>
<li><strong>OneSixtyOne:</strong>
<br>
onesixtyone allows you to brute force the community strings, you could onesixty one tool
```
onesixtyone [options] <host> <community>
  -c <communityfile> file with community names to try
  -i <inputfile>     file with target hosts
  -o <outputfile>    output log
```
</li>
</ul> </li>
</ol>

</li>
</li>
</ol>

###Notes
<ol>
<li>If your team in non-techie and you see that ipconfig, ping, whoami, cmd.exe, netsh is not needed. You could disable them using (Software Restriction Policies, Applocker, Access Control List, Process Auditing). This would reduce the attack surface area largely.</li>
<li>
TODO: Gather all the IP, ports for all the ports running http* services for wkhtml2image.<br>
Before, this how do we find ports which are running are running http services, continuing with the test.csv which we created above
```
cat test.csv | grep http | cut -d , -f2-4 | sort | uniq | cut -d , -f1 | sort | uniq
```
A sample results should look like
```
"10000/tcp"
"1025/tcp"
"1027/tcp"
"2000/tcp"
"32768/tcp"
"443/tcp"
"6001/tcp"
"8000/tcp"
"8008/tcp"
"8080/tcp"
"80/tcp"
"81/tcp"
"8443/tcp"
"8888/tcp"
```
Script In Progress
<br></li>
<li>Automate this whole process: In Progress</li>
</ol>

