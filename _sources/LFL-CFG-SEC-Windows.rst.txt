*****************************************************
Configuring and Securing Series : Windows Environment
*****************************************************

Welcome to the Configuring and Securing Series - Windows environment. Here we would cover how to configure Windows Domain Controller, add users , how to secure a windows environment etc. We would try to cover most of the stuff using powershell and commandline.

============================
Creating a Domain Controller
============================

Chad Cox and Harry Eagles has already provided steps `Chad’s Quick Notes – Installing a Domain Controller with Server 2016 Core <https://blogs.technet.microsoft.com/chadcox/2016/10/25/chads-quick-notes-installing-a-domain-controller-with-server-2016-core/>`_ and `Setting up Active Directory via PowerShell <https://blogs.technet.microsoft.com/uktechnet/2016/06/08/setting-up-active-directory-via-powershell/>`_

Renaming the Computer
---------------------

Probably, we want to rename the existing computername to something more sensible or as per the naming convention

::

 hostname
 WIN-N2P19KAHMFG

 Rename-Computer -NewName MUMDC01
 ^ This would rename the computer from WIN-N2P19KAHMFG to MUMDC01


Setting up the Static IP
------------------------

Figure out the network adapters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

 PS C:\Windows\system32> Get-NetAdapter
 
 Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
 ----                      --------------------                    ------- ------       ----------             ---------
 VBoxHost                  Intel(R) PRO/1000 MT Desktop Adapter #2      13 Up           08-00-27-F3-8B-23         1 Gbps
 Ethernet                  Intel(R) PRO/1000 MT Desktop Adapter         12 Up           08-00-27-7C-9A-4E         1 Gbps

Setting the IP Address
^^^^^^^^^^^^^^^^^^^^^^

::

 $ipaddress = "192.168.56.4"   # Your DC IP Address according to your IP Address range
 New-NetIPAddress -InterfaceAlias Ethernet -IPAddress $ipaddress -AddressFamily IPv4 -PrefixLength 24

 IPAddress         : 192.168.56.4
 InterfaceIndex    : 12
 InterfaceAlias    : Ethernet
 AddressFamily     : IPv4
 Type              : Unicast
 PrefixLength      : 24
 PrefixOrigin      : Manual
 SuffixOrigin      : Manual
 AddressState      : Tentative
 ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
 PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
 SkipAsSource      : False
 PolicyStore       : ActiveStore

 IPAddress         : 192.168.56.4
 InterfaceIndex    : 12
 InterfaceAlias    : Ethernet
 AddressFamily     : IPv4
 Type              : Unicast
 PrefixLength      : 24
 PrefixOrigin      : Manual
 SuffixOrigin      : Manual
 AddressState      : Invalid
 ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
 PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
 SkipAsSource      : False
 PolicyStore       : PersistentStore

Updating the DNS Server
^^^^^^^^^^^^^^^^^^^^^^^

::

 $dnsaddress = "127.0.0.1"
 Set-DnsClientServerAddress -InterfaceAlias VBoxHost -ServerAddresses $dnsaddress -Validate

Installing the Domain Services
------------------------------

Install AD-Domain-Services
^^^^^^^^^^^^^^^^^^^^^^^^^^

::

 Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install ADDS-Forest
^^^^^^^^^^^^^^^^^^^

::

 Install-ADDSForest -DomainName bitvijays.local

Validate the Domain Controller
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* AD/ DNS services are running

 ::

   Get-Service adws, kdc, netlogon, dns

   Status   Name               DisplayName
   ------   ----               -----------
   Running  adws               Active Directory Web Services
   Running  dns                DNS Server
   Running  kdc                Kerberos Key Distribution Center
   Running  Netlogon           netlogon


* SYSVOL and NetLogon shares

 ::
   

  Get-SmbShare

  Name     ScopeName Path                                           Description
  ----     --------- ----                                           -----------
  ADMIN$   *         C:\Windows                                     Remote Admin
  C$       *         C:\                                            Default share
  IPC$     *                                                        Remote IPC
  NETLOGON *         C:\Windows\SYSVOL\sysvol\bitvijays.com\SCRIPTS Logon server share
  SYSVOL   *         C:\Windows\SYSVOL\sysvol                       Logon server share

==============
User Creation
==============

New-ADUser
----------

Detailed information could be found at `Technet New-ADUser <https://technet.microsoft.com/en-us/library/ee617253.aspx>`_

New-ADUser creates a new Active Directory user.

::
 
 New-ADUser -Name "John Smith" -SamAccountName john.smith -GivenName John -Surname Smith

The above would create a user with the above details. However, the account would disabled as no password is specified.

New-ADUser with Password
^^^^^^^^^^^^^^^^^^^^^^^^

The following example shows one method to set this parameter. This command will prompt you to enter the password. 

::

 -AccountPassword (Read-Host -AsSecureString "AccountPassword")

Example:

::

 New-ADUser -Name "John Smith" -SamAccountName john.smith -GivenName John -Surname Smith -AccountPassword (Read-Host -AsSecureString "AccountPassword")

To enable the account, we do have use the switch -Enabled $true

::

 
 New-ADUser -Name "John Smith" -SamAccountName john.smith -GivenName John -Surname Smith -AccountPassword (Read-Host -AsSecureString "AccountPassword") -Enabled True


Random Password Creation
^^^^^^^^^^^^^^^^^^^^^^^^

* Powershell Way: Simon Wahlin has created powershell script `New-SWRandomPassword.ps1 <https://gallery.technet.microsoft.com/scriptcenter/Generate-a-random-and-5c879ed5>`_ to generate a number of random passwords that will be complex enough for Active Directory. Passwords will contain chars from all strings in InputStrings.

* Microsoft Excel Way: To create a password with 9 characters ( some numbers and special characters with 4 digit number ). In the formula tab, write

 ::

  =CHAR(RANDBETWEEN(65,90))&CHAR(RANDBETWEEN(97,122))&CHAR(RANDBETWEEN(97,122))&CHAR(RANDBETWEEN(65,90))&RANDBETWEEN(1000,9999)&CHAR(RANDBETWEEN(42,43))

 we can repeat this to create more complex password.

.. WARNING:: As we are using RANDBETWEEN function in MS Excel, password generated will change almost everytime focus is changed. To resolve this, it is suggested to copy the passwords by Value.


New-ADUser creation with CSV
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We also can create multiple users at once using CSV option. For example, let's say CSV is

::

 GivenName,Surname,Name,StreetAddress,City,Title,EmailAddress,Username,RPassword,Country,TelephoneNumber,Password
 Jane,Green,Jane Green,Libellengasse 60,SASSL,Ms.,Jane.Green@bitvijays.local,Jane.Green,OdlL6837*ai,AT,0650 130 26 58,TyzM9015+dp
 John,Hudson,John Hudson,Landstrasse 36,ETZELSDORF,Mr.,John.Hudson@bitvijays.local,John.Hudson,TbfY6122*ei,AT,0664 366 58 55,TtqF5989+wk

When we import this CSV using powershell

::

 Import-CSV ..\ADUsers.csv

 GivenName       : Cory
 Surname         : Nava
 Name            : Cory Nava
 StreetAddress   : Hauptstrasse 65
 City            : PRUTZ
 Title           : Dr.
 EmailAddress    : Cory.Nava@bitvijays.local
 Username        : Cory.Nava
 RPassword       : DfnV5074+hy
 Country         : AT
 TelephoneNumber : 0699 989 75 38
 Password        : JskE4317*of

We can create multiple users by passing these parameter to the New-ADUser function by 

::

 Import-Csv ..\..\Users\Administrator\Desktop\ADUsers.csv | % { New-ADUser -GivenName  $_.GivenName -Surname $_.Surname -Name $_.Name -SamAccountName $_.Username -Title $_.title -AccountPassword (ConvertTo-SecureString -Force -AsPlainText $_.Password) -Enabled $true }

For lab purposes, Carlos Perez has written a blog on `Creating Real Looking User Accounts in AD Lab <https://www.darkoperator.com/blog/2016/7/30/creating-real-looking-user-accounts-in-ad-lab>`_ 

.. Tip:: While creating user, we can also specify the computers that the user can access by using LogonWorkstations property. To specify more than one computer, create a single comma-separated list. We can identify a computer by using the Security Accounts Manager (SAM) account name (sAMAccountName) or the DNS host name of the computer. The SAM account name is the same as the NetBIOS name of the computer. In my opinion, this could probably help in stoping later movement

=========================
Adding Computer to Domain
=========================

AD-Computer
-----------

Microsoft documentation has provided a good documentation `Add-Computer <https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Management/Add-Computer>`_ 

Add the local computer to a domain or workgroup.

::

 Add-Computer
    [-DomainName] <String>                      : Specifies the domain to which the computers are added. This parameter is required when adding the computers to a domain.
    [-WorkgroupName <String>]                   : Specifies the name of a workgroup to which the computers are added. The default value is "WORKGROUP".
    [-ComputerName <String[]>]                  : Specifies the computers to add to a domain or workgroup. The default is the local computer.
    -Credential <PSCredential>                  : Specifies a user account that has permission to join the computers to a new domain.
    [-LocalCredential <PSCredential>]           : Specifies a user account that has permission to connect to the computers that are specified by the ComputerName parameter. The default is the current user.
    [-NewName <String>]                         : Specifies a new name for the computer in the new domain. This parameter is valid only when one computer is being added or moved.
    -OUPath <String>]                           : Specifies an organizational unit (OU) for the domain account. Enter the full distinguished name of the OU in quotation marks. The default value is the default OU for machine objects in the domain.
    [-Restart]                                  : Indicates that this cmdlet restarts the computers that were added to the domain or workgroup. A restart is often required to make the change effective.
    [-Server <String>]                          : Specifies the name of a domain controller that adds the computer to the domain. Enter the name in DomainName\ComputerName format. By default, no domain controller is specified.
    [-UnjoinDomainCredential <PSCredential>]    : Specifies a user account that has permission to remove the computers from their current domains. The default is the current user.
    [-Unsecure]                                 : Indicates that this cmdlet performs an unsecured join to the specified domain.
    [-WhatIf]
    [<CommonParameters>]


Add a local computer to the domain
----------------------------------

::

 Add-Computer -Domain "Domain02" -NewName "Server044" -Credential Domain02\Admin01 -Restart

Add a remote computer to the domain
-----------------------------------
::

 Add-Computer -ComputerName "Server01" -Domain "Domain02" -LocalCredential User01 -Credential Domain02\Admin01 -Restart

For moving a remote computer, probably, WMI or WinRM should be enabled.

By default, any authenticated user can add a computer in a domain. However, probably, this is discouraged and only one user/ group should be allowed to add computer to Domain. More details at `Who can add workstation to the domain <https://blogs.technet.microsoft.com/dubaisec/2016/02/01/who-can-add-workstation-to-the-domain/>`_ 

.. ToDo :: Need to figure out a powershell way to delegate the "Add computer to domain" to a specific user/ group.

=======================
Moving Computer to OUs
=======================

As the security baselines are Operating System specifics, We would probably want to move the computers joined to a specific OU, so that we can apply the security baseline.

Creating a New OU
-----------------

Let's first create few OU ( Organizational Unit ). In the below example we are creating a OU named Security_Baseline which will contain two or more sub-OUs. Let's say for Windows 7, Windows 10 or Windows Server.

::

 New-ADOrganizationalUnit -Name "Security_Baseline" -Description "Security Baseline" -Path "DC=bitvijays,DC=com"
 New-ADOrganizationalUnit -Name "Windows7" -Description "Windows 7 Machine Security Baseline" -Path "OU=Security_Baseline,DC=bitvijays,DC=com"
 New-ADOrganizationalUnit -Name "Windows10" -Description "Windows 10 Machine Security Baseline" -Path "OU=Security_Baseline,DC=bitvijays,DC=com"


Let's figure out what are the different OUs in our domain

::

 PS C:\Windows\system32> Get-ADOrganizationalUnit -Filter * | FT Name, DistinguishedName

 Name               DistinguishedName
 ----               -----------------
 Domain Controllers OU=Domain Controllers,DC=bitvijays,DC=com
 Workstations       OU=Workstations,DC=bitvijays,DC=com
 Security_Baseline  OU=Security_Baseline,DC=bitvijays,DC=com
 Windows7           OU=Windows7,OU=Security_Baseline,DC=bitvijays,DC=com
 Windows10          OU=Windows10,OU=Security_Baseline,DC=bitvijays,DC=com

If we just wanna see Windows7 one, we can do

::

 Get-ADOrganizationalUnit -LDAPFilter "(name=Windows7)" | FT Name, DistinguishedName

 Name     DistinguishedName
 ----     -----------------
 Windows7 OU=Windows7,OU=Security_Baseline,DC=bitvijays,DC=com

Figuring out different OS in Domain
-----------------------------------

We would require ActiveDirectory Module for this.

::

 Import-Module ActiveDirectory

Microsoft has provided a technet article on `Get-ADComputer <https://technet.microsoft.com/en-us/itpro/powershell/windows/addsadministration/get-adcomputer>`_ The Get-ADComputer cmdlet gets a computer or performs a search to retrieve multiple computers.

::

 Get-ADComputer -Filter * -Property *

 AccountExpirationDate                :
 accountExpires                       : 9223372036854775807
 AccountLockoutTime                   :
 AccountNotDelegated                  : False
 AllowReversiblePasswordEncryption    : False
 AuthenticationPolicy                 : {}
 AuthenticationPolicySilo             : {}
 BadLogonCount                        : 0
 badPasswordTime                      : 0
 badPwdCount                          : 0
 CannotChangePassword                 : False
 CanonicalName                        : bitvijays.com/Workstations/IE10WIN72
 Certificates                         : {}
 CN                                   : IE10WIN72
 codePage                             : 0
 CompoundIdentitySupported            : {False}
 countryCode                          : 0
 Created                              : 5/9/2017 4:34:31 AM
 createTimeStamp                      : 5/9/2017 4:34:31 AM
 Deleted                              :
 Description                          :
 DisplayName                          : IE10WIN72$
 DistinguishedName                    : CN=IE10WIN72,OU=Workstations,DC=bitvijays,DC=com
 DNSHostName                          : IE10WIN72.bitvijays.com
 DoesNotRequirePreAuth                : False
 dSCorePropagationData                : {8/14/2017 8:19:24 AM, 8/14/2017 8:18:23 AM, 8/14/2017 1:13:21 AM, 5/9/2017 1:55:10 PM...}
 Enabled                              : True
 HomedirRequired                      : False
 HomePage                             :
 instanceType                         : 4
 IPv4Address                          :
 IPv6Address                          :
 isCriticalSystemObject               : False
 isDeleted                            :
 KerberosEncryptionType               : {RC4, AES128, AES256}
 LastBadPasswordAttempt               :
 LastKnownParent                      :
 lastLogoff                           : 0
 lastLogon                            : 131471983161372555
 LastLogonDate                        : 8/8/2017 6:00:28 PM
 lastLogonTimestamp                   : 131467140289373056
 localPolicyFlags                     : 0
 Location                             :
 LockedOut                            : False
 logonCount                           : 47
 ManagedBy                            :
 MemberOf                             : {}
 MNSLogonAccount                      : False
 Modified                             : 8/14/2017 8:19:24 AM
 modifyTimeStamp                      : 8/14/2017 8:19:24 AM
 mS-DS-CreatorSID                     : S-1-5-21-1727263102-1930659670-937436522-1106
 ms-Mcs-AdmPwd                        : %!2]78.j7n+c3E
 ms-Mcs-AdmPwdExpirationTime          : 131493063003466404
 msDS-SupportedEncryptionTypes        : 28
 msDS-User-Account-Control-Computed   : 0
 Name                                 : IE10WIN72
 nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
 ObjectCategory                       : CN=Computer,CN=Schema,CN=Configuration,DC=bitvijays,DC=com
 ObjectClass                          : computer
 ObjectGUID                           : 1cc964d9-3164-4780-bc0a-1149049d6df9
 ObjectSid                            : S-1-5-21-1727263102-1930659670-937436522-1107
 OperatingSystem                      : Windows 7 Enterprise
 OperatingSystemHotfix                :
 OperatingSystemServicePack           : Service Pack 1
 OperatingSystemVersion               : 6.1 (7601)
 PasswordExpired                      : False
 PasswordLastSet                      : 8/14/2017 2:14:29 AM
 PasswordNeverExpires                 : False
 PasswordNotRequired                  : False
 PrimaryGroup                         : CN=Domain Computers,CN=Users,DC=bitvijays,DC=com
 primaryGroupID                       : 515
 PrincipalsAllowedToDelegateToAccount : {}
 ProtectedFromAccidentalDeletion      : False
 pwdLastSet                           : 131471756690576604
 SamAccountName                       : IE10WIN72$
 sAMAccountType                       : 805306369
 sDRightsEffective                    : 15
 ServiceAccount                       : {}
 servicePrincipalName                 : {TERMSRV/IE10WIN72.bitvijays.com, RestrictedKrbHost/IE10WIN72.bitvijays.com, HOST/IE10WIN72.bitvijays.com, TERMSRV/IE10WIN72...}
 ServicePrincipalNames                : {TERMSRV/IE10WIN72.bitvijays.com, RestrictedKrbHost/IE10WIN72.bitvijays.com, HOST/IE10WIN72.bitvijays.com, TERMSRV/IE10WIN72...}
 SID                                  : S-1-5-21-1727263102-1930659670-937436522-1107
 SIDHistory                           : {}
 TrustedForDelegation                 : False
 TrustedToAuthForDelegation           : False
 UseDESKeyOnly                        : False
 userAccountControl                   : 4096
 userCertificate                      : {}
 UserPrincipalName                    :
 uSNChanged                           : 86161
 uSNCreated                           : 24601
 whenChanged                          : 8/14/2017 8:19:24 AM
 whenCreated                          : 5/9/2017 4:34:31 AM


Let's say we just want to see Name and OperatingSystem, we can do 

::

 Get-ADComputer -Filter * -Property * | Format-Table Name, OperatingSystem, OperatingSystemVersion

 Name            OperatingSystem                            OperatingSystemVersion
 ----            ---------------                            ----------------------
 WIN-N2P19KAHMFG Windows Server 2012 R2 Standard Evaluation 6.3 (9600)
 IE10WIN72       Windows 7 Enterprise                       6.1 (7601)

Moving ADComputer Object to a specific OU
-----------------------------------------

Let's say we want to move Windows 7 Machines to the a specific OU ( one we created to have Security baseline for Windows7 )

::

  Get-ADComputer -Filter {OperatingSystem -Like "Windows 7*"} | Move-ADObject -TargetPath "OU=Windows7,OU=Security_Baseline,DC=bitvijays,DC=com"

This has been explained by Scripting Guys at `The Easy Way to Use PowerShell to Move Computer Accounts <https://blogs.technet.microsoft.com/heyscriptingguy/2012/03/01/the-easy-way-to-use-powershell-to-move-computer-accounts/>`_


==========================
Windows Security Hardening
==========================

.. Note :: I am not an expert in hardening, this is just an experiment to see, what all we can do.


At this point, probably, we can work on the hardening of our Domain.


Security Compliance Manager
---------------------------

At this point, probably we can setup `Security Compliance Manager (SCM) <https://technet.microsoft.com/en-us/solutionaccelerators/cc835245.aspx>`_ on the separate machine. Go thru the baseline for different Windows Operating System. SCM 4.0 provides ready-to-deploy policies based on Microsoft Security Guide recommendations and industry best practices, allowing you to easily manage configuration drift, and address compliance requirements for Windows operating systems and Microsoft applications.

However, SCM is now retired and replaced as mentioned at `Security Compliance Manager (SCM) retired; new tools and procedures <https://blogs.technet.microsoft.com/secguide/2017/06/15/security-compliance-manager-scm-retired-new-tools-and-procedures/>`_ which is replaced by `Security Compliance Toolkit <https://www.microsoft.com/en-us/download/details.aspx?id=55319>`_ which contains Policy Analyzer and LGPO.

However, coming back to SCM and it's ability to export the GPO. Let's see how we can import it in the Group Policy Managment Tool ( Preferrbly using Powershell ) We can do it for almost every OS version. In the below example we would do it for Windows 7.

Now, As we had two OU "Windows 7 SB" and "Windows 10 SB", by using Group Policy Management Tool, create two GPO Win7SB and Win10SB.


We can get current GPO in the domain by using

::

 Get-GPO -All | FT DisplayName

 DisplayName
 -----------
 Default Domain Policy
 Win7SB
 Default Domain Controllers Policy
 Win10SB

Let's create a New-GPO and link it to a OU.

::

 New-GPO -Name GlobalSB -Comment "GPO for all the OS"


 DisplayName      : GlobalSB
 DomainName       : bitvijays.com
 Owner            : BITVIJAYS\Domain Admins
 Id               : 651e0d7b-ad70-4369-b21e-8a9cde424a04
 GpoStatus        : AllSettingsEnabled
 Description      : GPO for all the OS
 CreationTime     : 8/15/2017 12:37:14 AM
 ModificationTime : 8/15/2017 12:37:14 AM
 UserVersion      : AD Version: 0, SysVol Version: 0
 ComputerVersion  : AD Version: 0, SysVol Version: 0
 WmiFilter        :

Let's link it to a OU

::

 New-GPLink -Guid 651e0d7b-ad70-4369-b21e-8a9cde424a04 -Target "OU=Security_Baseline,DC=bitvijays,DC=com"

 GpoId       : 651e0d7b-ad70-4369-b21e-8a9cde424a04
 DisplayName : GlobalSB
 Enabled     : True
 Enforced    : False
 Target      : OU=Security_Baseline,DC=bitvijays,DC=com
 Order       : 1


Let's import the SecurityBaseline Settings generated by the SCM ( Creation of GPO Export Folder for Security Baseline is out-of-scope for this document )

::

 Import-GPO -BackupId aa23f7c2-c57c-4fc0-82f9-7c12c8787d25 -Path "C:\Users\Administrator\Desktop" -TargetGuid 358bb269-024a-408a-b010-0e54062cbd94

  DisplayName      : Win7SB
  DomainName       : bitvijays.com
  Owner            : BITVIJAYS\Domain Admins
  Id               : 358bb269-024a-408a-b010-0e54062cbd94
  GpoStatus        : UserSettingsDisabled
  Description      :
  CreationTime     : 8/14/2017 8:21:07 AM
  ModificationTime : 8/15/2017 12:51:32 AM
  UserVersion      : AD Version: 2, SysVol Version: 2
  ComputerVersion  : AD Version: 2, SysVol Version: 2
  WmiFilter        :


 a23f7c2-c57c-4fc0-82f9-7c12c8787d25 - is the Guid for the exported GPO from SCM.
 358bb269-024a-408a-b010-0e54062cbd94 - is the Guid for the Win7SB 

Extra Hardening
---------------

Sean Metcalf has written a blog on `Securing Windows Workstations: Developing a Secure Baseline <https://adsecurity.org/?p=3299>`_ 

Custom Settings
^^^^^^^^^^^^^^^

We can create a custome GPO which includes few custom settings for the below:

* Force Group Policy to reapply settings during “refresh” : In SCM, there is a option to Create a setting group and a setting. We can create "Configure scripts policy processing" 

* Disable LLMNR : Link-Local Multicast Name Resolution (LLMNR) resolves single label names (like: COMPUTER1), on the local subnet, when DNS devolution is unable to resolve the name. This is helpful if you are in an Ad-Hoc network scenario, or in a scenario where DNS entries do not include hosts on the local subnet.LLMNR should be disabled if not used since disabling it removes a method Responder uses for passive credential theft.Group Policy:Computer Configuration/Administrative Templates/Network/DNS Client  Set “Turn Off Multicast Name Resolution” to “Enabled”

* Disable NBT-NS

 * Download `Set-NetBIOS-node-type-KB160177.zip <http://blog.westmonroepartners.com/wp-content/uploads/2017/04/Set-NetBIOS-node-type-KB160177.zip>`_ which is mentioned at `Secure Against NetBIOS Name Service (NBT-NS) Poisoning Attacks with Group Policy <http://blog.westmonroepartners.com/secure-nbt-ns-poisoning-attacks/>`_ 
 
 * Import the ADMX Template by referring `Managing Group Policy ADMX Files Step-by-Step Guide <https://msdn.microsoft.com/en-us/library/bb530196.aspx>`_ 

 * Set the setting to P-Node type

Disable Net Session Enumeration ( NetCease )
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the domain contains operating system earlier than Windows 10, We should run `Net Cease - Hardening Net Session Enumeration <https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b>`_ powershell script.

It changes the registry key

NetSessionEnum method permissions are controlled by a registry key under the following path:

::

 HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/LanmanServer/DefaultSecurity/SrvsvcSessionInfo


.. ToDo :: Need to figure out, how to run a script on all workstations ?

By default Windows 10, doesn't allow authenticated users to enumerate sessions.

Local Administrator Password Solution LAPS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Microsoft has provided a `Local Administrator Password Solution <https://www.microsoft.com/en-us/download/details.aspx?id=46899>`_ which provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset. Details on how to deploy can be found in Operations Guide and Technical Specification.
