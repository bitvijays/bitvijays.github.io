---
layout: post
title: "Learning from the field: Securing Debian"
date: 2016-05-29 14:51:28 +0530
comments: true
categories: 
---

Recently, we got an extra laptop with decent configuration to host as a server. We decided to host Kali-Linux on it and make available multiple vulnerable OS from vulnhub.com on it for practice to our teams.

After installing Kali-Linux and running lynis audit tool, linux hardening index was 55. As we are opening this server to public/ people capable of hacking, we need to make sure our server doesn't get hacked.
<!-- more -->

This source is mainly compiled from <a href="https://www.debian.org/doc/manuals/securing-debian-howto/">Securing Debian Manual</a> 

<ol>
<li><strong>Set up a GRUB password</strong>: This is mainly done to prevent any unauthorized person to change the grub to get a root shell. Anybody can easily get a root-shell and change your passwords by entering <name-of-your-bootimage> init=/bin/sh at the boot prompt. After changing the passwords and rebooting the system, the person has unlimited root-access and can do anything he/she wants to the system.
<ul>
<li>Generate an encrypted password, open a terminal and run the following command:
```
grub-mkpasswd-pbkdf2
```
```
grub-mkpasswd-pbkdf2 
Enter password: 
Reenter password: 
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.A56BEB30E27FE2F7D119E8DEFD6A8049E4300734BB139A5DD08E668BA434792B8AB45A285AC88B95DD16658AC7EC0XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```</li>
<li>Insert the hash in /etc/grub.d/40_custom
```
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.A56BEB30E27FE2F7D119E8DEFD6A8049E4300734BB139A5DD08E668BA434792B8AB45A285AC88B95DD16658AC7EC0XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
export superusers
```</li>
<li>Execute update-grub
```
update-grub
Generating grub configuration file ...
Found background image: .background_cache.png
Found linux image: /boot/vmlinuz-4.0.0-kali1-amd64
Found initrd image: /boot/initrd.img-4.0.0-kali1-amd64
done
```
</li>
</ul></li>

<li><strong>Providing secure user access</strong>: PAM (Pluggable Authentication Modules) allows system administrators to choose how applications authenticate users: 
<ul>
<br>
<li><strong>Password security in PAM</strong>: Install libpam-passwdqc which is a PAM module for password strength policy enforcement.
<ul>Insert the below line in /etc/pam.d/common-password
```
password	requisite			pam_passwdqc.so min=disabled,disabled,8,8,8
```
Format is min=N0,N1,N2,N3,N4		[min=disabled,24,11,8,7]
where
<ul>
<li>N0 is used for passwords consisting of characters from one character class only. The character classes are: digits, lower-case letters, upper-case letters, and other characters. There is also a special class for non-ASCII characters, which could not be classified, but are assumed to be non-digits.</li>
<li>N1 is used for passwords consisting of characters from two character classes that do not meet the requirements for a passphrase.</li>
<li>N2 is used for passphrases. Note that besides meeting this length requirement, a passphrase must also consist of a sufficient number of words.</li>
<li>N3 and N4 are used for passwords consisting of characters from three and four character classes, respectively.</li>
</ul>
</ul></li>
<br>
<li><strong>Control of su in PAM</strong>: If you want to protect su, so that only some people can use it to become root on your system, you need to add a new group "wheel" to your system. Add root and the other users that should be able to su to the root user to this group. This makes sure that only people from the group "wheel" can use su to become root. Other users will not be able to become root. In fact they will get a denied message if they try to become root.<a href="https://wiki.debian.org/WHEEL/PAM">Wheel PAM</a> provides a quick tutorial how to set this up.
<ul>
<li>With root privileges uncomment the following line in /etc/pam.d/su, by removing the leading '#':
```
#auth       required pam_wheel.so
```
That's all for the file and no user can execute su anymore. This is the most secure configuration.
</li>
<li>Allow a user to execute su: After having restricted the execution of su, create the group wheel with root privileges:
```
groupadd wheel
```
And then add user_name to that group:
```
usermod -aG wheel user_name
```
From now user_name can execute su.
</li></ul>
</li>
<br>
<li><strong>Temporary directories in PAM</strong>: Since there have been a number of so called insecure tempfile vulnerabilities, thttpd is one example, the libpam-tmpdir is a good package to install. All you have to do is add the following to /etc/pam.d/common-session:
```
session    optional     pam_tmpdir.so
```
</li>

<li><strong>Configuration for undefined PAM applications</strong>

Finally, but not least, create /etc/pam.d/other and enter the following lines:
```
       auth     required       pam_securetty.so
       auth     required       pam_unix_auth.so
       auth     required       pam_warn.so
       auth     required       pam_deny.so
       account  required       pam_unix_acct.so
       account  required       pam_warn.so
       account  required       pam_deny.so
       password required       pam_unix_passwd.so
       password required       pam_warn.so
       password required       pam_deny.so
       session  required       pam_unix_session.so
       session  required       pam_warn.so
       session  required       pam_deny.so
```
These lines will provide a good default configuration for all applications that support PAM (access is denied by default).</li>
<br>
<li><strong>Setting users umasks</strong>: Debian's default umask setting is 022 this means that files (and directories) can be read and accessed by the user's group and by any other users in the system. More restrictive umask settings include 027 (no access is allowed to new files for the other group, i.e. to other users in the system) or 077 (no access is allowed to new files to the members the user's group).This change is set by defining a proper umask setting for all users
<ul>
<li>introducing an umask call in the shell configuration files: /etc/profile (source by all Bourne-compatible shells), /etc/csh.cshrc, /etc/csh.login, /etc/zshrc and probably some others (depending on the shells you have installed on your system)</li>
<li>change the UMASK setting in /etc/login.defs, Of all of these the last one that gets loaded by the shell takes precedence. The order is: the default system configuration for the user's shell (i.e. /etc/profile and other system-wide configuration files) and then the user's shell (his ~/.profile, ~/.bash_profile, etc...).</li>
<li>Install libpam-umask package adjusts the users' default umask using PAM. Add the following, after installing the package, to /etc/pam.d/common-session:
```
session    optional     pam_umask.so umask=077
```</li>
<li>you should consider changing root's default 022 umask (as defined in /root/.bashrc) to a more strict umask. That will prevent the system administrator from inadvertenly dropping sensitive files when working as root to world-readable directories (such as /tmp) and having them available for your average user.
</li>
<li>Limiting access to other user's information: However, users' $HOME directories are created with 0755 permissions (group-readable and world-readable). The group permissions is not an issue since only the user belongs to the group, however the world permissions might (or might not) be an issue depending on your local policy.

You can change this behavior so that user creation provides different $HOME permissions. To change the behavior for new users when they get created, change DIR_MODE in the configuration file /etc/adduser.conf to 0750 (no world-readable access).</li>
</ul></li>
</ul>
</li>
<li><strong>User login actions</strong>: edit /etc/login.defs

The next step is to edit the basic configuration and action upon user login. Note that this file is not part of the PAM configuration, it's a configuration file honored by login and su programs, so it doesn't make sense tuning it for cases where neither of the two programs are at least indirectly called (the getty program which sits on the consoles and offers the initial login prompt does invoke login).
```
       FAILLOG_ENAB        yes
```
If you enable this variable, failed logins will be logged. It is important to keep track of them to catch someone who tries a brute force attack.
```
       LOG_UNKFAIL_ENAB    no
```
If you set this variable to 'yes' it will record unknown usernames if the login failed. It is best if you use 'no' (the default) since, otherwise, user passwords might be inadvertenly logged here (if a user mistypes and they enter their password as the username). If you set it to 'yes', make sure the logs have the proper permissions (640 for example, with an appropriate group setting such as adm).
```
       SYSLOG_SU_ENAB      yes
```
This one enables logging of su attempts to syslog. Quite important on serious machines but note that this can create privacy issues as well.
```
       SYSLOG_SG_ENAB      yes
```
The same as SYSLOG_SU_ENAB but applies to the sg program.
```
       ENCRYPT_METHOD  SHA512
```
As stated above, encrypted passwords greatly reduce the problem of dictionary attacks, since you can use longer passwords. This definition has to be consistent with the value defined in /etc/pam.d/common-password.</li>
<li><strong>Log files Permissions</strong>: It is not only important to decide how alerts are used, but also who has read/modify access to the log files (if not using a remote loghost. First /var/log/lastlog and /var/log/faillog do not need to be readable by normal users. In the lastlog file you can see who logged in recently, and in the faillog you see a summary of failed logins. The author recommends chmod 660 for both.
```
       #  find /var/log -type f -exec ls -l {} \; | cut -c 17-35 |sort -u
       (see to what users do files in /var/log belong)
       #  find /var/log -type f -exec ls -l {} \; | cut -c 26-34 |sort -u
       (see to what groups do files in /var/log belong)
       # find /var/log -perm +004
       (files which are readable by any user)
       #  find /var/log \! -group root \! -group adm -exec ls -ld {} \;
       (files which belong to groups not root or adm)
```</li>
<li><strong>Few important softwares to be installed</strong>:
<ul>
<li><strong>sysstat</strong>: The sysstat utilities are a collection of performance monitoring tools for Linux. These include sar, sadf, mpstat, iostat, tapestat, pidstat, cifsiostat  and sa tools.</li>
<li><strong>apt-listbugs</strong>: apt-listbugs is a tool which retrieves bug reports from the Debian Bug Tracking System and lists them. Especially, it is intended to be invoked before each installation/upgrade by APT in order to check whether the installation/upgrade is safe.</li>
<li><strong>Debian-goodies</strong>: is a package that includes toolbox-style utilities used to manage Debian and its derivative systems such as Ubuntu, Kali Linux.
<ul>
<li>dglob – Produce a list of package names which match a pattern</li>
<li>dgrep – Search all files in given packages for a regex</li>
<li>dpigs – Display which installed packages taken the most disk space</li>
<li>debget – Obtain a .deb for a package in APT’s database</li>
<li>debmany – Choose manpages of installed or removed packages</li>
<li>checkrestart – Finds and restart processes which are using outdated versions of upgraded files</li>
<li>popbugs – Show a customized release-critical bug report based on packages you use</li>
<li>which-pkg-broke – Catch which package might have broken another</li>
</ul></li>
<li><strong>debscan</strong>: The debsecan program evaluates the security status of a host running the Debian operation system. It reports missing security updates and known vulnerabilities in the programs which are installed on the host.</li>
<li>Install <strong>fail2ban</strong>: Fail2ban scans log files (e.g. /var/log/apache/error_log) and bans IPs that show the malicious signs -- too many password failures, seeking for exploits, etc. Generally Fail2Ban is then used to update firewall rules to reject the IP addresses for a specified amount of time, although any arbitrary other action (e.g. sending an email) could also be configured.
<ul>
Configure 
<li><a href="https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-debian-7">SSH with fail2ban</a></li>
<li><a href="https://www.digitalocean.com/community/tutorials/how-to-set-up-modsecurity-with-apache-on-ubuntu-14-04-and-debian-8">Modsecurity</a>ModSecurity is a free web application firewall (WAF) that works with Apache, Nginx and IIS. It supports a flexible rule engine to perform simple and complex operations and comes with a Core Rule Set (CRS) which has rules for SQL injection, cross site scripting, Trojans, bad user agents, session hijacking and a lot of other exploits.</li>
<li><a href="https://www.digitalocean.com/community/tutorials/how-to-use-tripwire-to-detect-server-intrusions-on-an-ubuntu-vps">Tripwire</a>: Open Source Tripwire® software is a security and data integrity tool useful for monitoring and alerting on specific file change(s) on a range of systems.</li>
</ul></li>
</ul>
</li>
<li></strong>Kernel Hardening: Sysctl Values</strong>:
<ul>
<li><strong>kernel.core_uses_pid</strong> (expected 1): If the /proc/sys/kernel/core_uses_pid file contains the value 0, then a core dump file is simply named core.  If this file contains a nonzero value, then the core dump file includes the process ID in a name of the form core.PID.</li>
<li><strong>kptr_restrict</strong> (expected 1): This toggle indicates whether restrictions are placed on exposing kernel addresses via /proc and other interfaces.
<ul>
<li>When kptr_restrict is set to (0), the default, there are no restrictions.</li>
<li>When kptr_restrict is set to (1), kernel pointers printed using the %pK format specifier will be replaced with 0's unless the user has CAP_SYSLOG and effective user and group ids are equal to the real ids. This is
because %pK checks are done at read() time rather than open() time, so if permissions are elevated between the open() and the read() (e.g via a setuid binary) then %pK will not leak kernel pointers to unprivileged
users. Note, this is a temporary solution only. The correct long-term solution is to do the permission checks at open() time. Consider removing world read permissions from files that use %pK, and using dmesg_restrict
to protect against uses of %pK in dmesg(8) if leaking kernel pointer values to unprivileged users is a concern.</li>
<li>When kptr_restrict is set to (2), kernel pointers printed using %pK will be replaced with 0's regardless of privileges.</li>
</ul></li>
<li><strong>kernel.sysrq</strong> (expected 0): It is a 'magical' key combo you can hit which the kernel will respond to regardless of whatever else it is doing, unless it is completely locked up.
Here is the list of possible values in /proc/sys/kernel/sysrq:
<ul>
<li>   0 - disable sysrq completely</li>
<li>   1 - enable all functions of sysrq</li>
<li>  >1 - bitmask of allowed sysrq functions (see below for detailed function description):
```
          2 =   0x2 - enable control of console logging level
          4 =   0x4 - enable control of keyboard (SAK, unraw)
          8 =   0x8 - enable debugging dumps of processes etc.
         16 =  0x10 - enable sync command
         32 =  0x20 - enable remount read-only
         64 =  0x40 - enable signalling of processes (term, kill, oom-kill)
        128 =  0x80 - allow reboot/poweroff
        256 = 0x100 - allow nicing of all RT tasks.
```
</li>
</ul>
</li>
<li><strong>net.ipv4.conf.all.log_martians</strong> (expected 1) or <strong>net.ipv4.conf.default.log_martians</strong> : Log packets with impossible addresses to kernel log. log_martians for the interface will be enabled if at least one of	conf/{all,interface}/log_martians is set to TRUE, it will be disabled otherwise </li>
<li><strong>net.ipv4.conf.all.rp_filter</strong> (expected 1): rp_filter - INTEGER
<ul>
<li>	0 - No source validation.</li>
<li>	1 - Strict mode as defined in RFC3704 Strict Reverse Path
	    Each incoming packet is tested against the FIB and if the interface
	    is not the best reverse path the packet check will fail.
	    By default failed packets are discarded.</li>
<li>	2 - Loose mode as defined in RFC3704 Loose Reverse Path
	    Each incoming packet's source address is also tested against the FIB
	    and if the source address is not reachable via any interface
	    the packet check will fail.</li>

<li>	Current recommended practice in RFC3704 is to enable strict mode
	to prevent IP spoofing from DDos attacks. If using asymmetric routing
	or other complicated routing, then loose mode is recommended.

	The max value from conf/{all,interface}/rp_filter is used
	when doing source validation on the {interface}.

	Default value is 0. Note that some distributions enable it
	in startup scripts.</li>
</ul></li>
<li><strong>net.ipv4.conf.all.send_redirects</strong> (expected 0): send_redirects - BOOLEAN
	Send redirects, if router.
	send_redirects for the interface will be enabled if at least one of
	conf/{all,interface}/send_redirects is set to TRUE,
	it will be disabled otherwise
	Default: TRUE</li>
<li> <strong>net.ipv4.conf.all.accept_redirects</strong> (expected 0) or <strong>net.ipv6.conf.all.accept_redirects</strong> or <strong>net.ipv4.conf.default.accept_redirects</strong> (expected 0):: Disable acceptance of all ICMP redirected packets on all interfaces. Accept ICMP redirect messages.
	accept_redirects for the interface will be enabled if:
	- both conf/{all,interface}/accept_redirects are TRUE in the case
	  forwarding for the interface is enabled
	or
	- at least one of conf/{all,interface}/accept_redirects is TRUE in the
	  case forwarding for the interface is disabled
	accept_redirects for the interface will be disabled otherwise
	default TRUE (host)
		FALSE (router)</li>
<li><strong>nnet.ipv4.conf.default.accept_source_route</strong> (expected 0):The accept_source_route option causes network interfaces to accept packets with the Strict Source Route (SSR) or Loose Source Routing (LSR) option set.</li>
<li><strong>net.ipv4.tcp_timestamps</strong> (Expected 0): </li>
</ul>
</li>
<li><strong>Legal Banner</strong>: Add legal banner to:
<ul>
<li>/etc/motd</li>
<li>/etc/issue</li>
<li>/etc/issue.net</li></ul></li>
<li><strong>Harden compilers like restricting access to root user only</strong>: Use grep to found out the compilers installed from the /var/log/lynis.log file.
```
Found known binary: as (compiler) - /usr/bin/as
Found known binary: g++ (compiler) - /usr/bin/g++
Found known binary: gcc (compiler) - /usr/bin/gcc
```
```
ls -lah /usr/bin/as /usr/bin/g++ /usr/bin/gcc
lrwxrwxrwx 1 root root 19 May 12 20:29 /usr/bin/as -> x86_64-linux-gnu-as
lrwxrwxrwx 1 root root  7 Sep  9  2015 /usr/bin/g++ -> g++-4.9
lrwxrwxrwx 1 root root  7 Sep  9  2015 /usr/bin/gcc -> gcc-4.9
```
Remove permissions of read, write, execute from others:
```
chmod o-x /usr/bin/as /usr/bin/g++ /usr/bin/gcc
chmod o-r /usr/bin/as /usr/bin/g++ /usr/bin/gcc
chmod o-w /usr/bin/as /usr/bin/g++ /usr/bin/gcc
```</li>
<li>Disable drivers like USB Mass storage / firewire storage (if not used) to prevent unauthorized storage or data-theft.
<ul>
<li>USB Mass storage: Add the below line in /etc/modprobe.d/blacklist-usbstorage
```
#Disabling USB Storage
blacklist usb-storage
```</li>
<li>Firewire storage: Add the below line in /etc/modprobe.d/blacklist-firewire
```
#Disabling Firewire Storage
blacklist firewire_core
blacklist firewire_ohci
```</li>
</ul></li>
</ol>
