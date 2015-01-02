---
layout: post
title: "Linux Essentials"
date: 2014-10-07 23:07:48 +0100
comments: true
categories: 
---
This post lists essential commands and concepts which would be helpful to a Linux user. We would cover tools required for programming, system administration. Also, provide some useful tips, tricks and TODO which would help you learn and practice.
<!-- more -->  
<ol>
<li>Vi : Powerful Editor:
{% codeblock %}
vi <filename>           - Open a file to edit in Vi editor.
Two modes               - Command and Insert Mode. All commands below are in command mode.
:q                      - Quit.
:wq                     - Save and close.
:syntax on              - Turn on Syntax highlighting for C programming and other languages.
:set number             - Turn on the line numbers.
:set nonumber           - Turn off the line numbers.
:u                      - Undo one change.
dd                      - Delete current line. 
d$                      - Delete the text from where your cursor is to the end of the line.
dnd                     - Delete n lines.
yy                      - Yank or copy current line.
y$, yny                 - Similar to delete lines.
p                       - Paste the line in the buffer in to text after the current line.
{% endcodeblock %}
Two configurations files which are important:
<ul>
<li>.vimrc&nbsp;&nbsp;&nbsp;&nbsp;   - Contains optional runtime configuration settings to initialize Vim when it starts. Example: If you want Vim to have syntax on and line numbers on, whenever you open vi, enter syntax on and set number in this file.</li>
<li>.viminfo - Viminfo file stores command-line, search string, input-line history and other stuff. Useful if you want to find out what user has been doing in vi.</li>
</ul> 
<br>  
PS: Both files are present in user home directory.   
<br>
<br>
sed - stream editor in Vi is really very useful. It is also a standalone application.
{% codeblock %}
:s/test/learn     - would replace test to learn in current line but only first instance.
:s/test/learn/g   - would replace test to learn in current line all the instance.
:s/test/learn/gi  - would replace test (all cases) to learn in current line all the instance.
:%s/test/learn/gi - would replace test to learn in the file (all lines)
{% endcodeblock %}
</li>
<li>Bash configuration files - For Debian/Ubuntu based Systems.
<ol type="i">
<li>~/.bash_profile - Stores user environment variables.</li>
<li>~/.bash_history - contains all the history of the commands.</li>
<li>~/.bash_logout&nbsp;  - contains the command which are executed when bash is exited.</li>
<li>~/.bashrc&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;       - setting of variables for bash.</li>
<li>/etc/profile&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Global system configuration for bash which controls the environmental variables and programs that are to be run when bash is executed. Setting of PATH variable and PS1.</li>
<li>/etc/bashrc&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;     - Global system configuration for bash which controls the aliases and functions to be run when bash is executed.</li>
</ol>
<br>
Few Important Variables
<ol type="i">
<li>HISTSIZE&nbsp;&nbsp;&nbsp;&nbsp; - Controls the number of commands to remember in the history command. The default value is 500.</li>
<li>HISTFILE&nbsp;&nbsp;&nbsp;&nbsp; - Defines the file in which all commands will be logged to. Normally the value for this variable is set to ~/.bash_history. This means that whatever you type in bash will be stored into the value of HISTFILE. It is advisable to leave it undefined, or pipe the output to /dev/null (For privacy reasons).</li>
<li>HISTFILESIZE - Defines the maximum number of commands in ~/.bash_history.</li>
</ol>
</li>
<br>
<li>System Administration
<ul>
<li>Updating Debian Linux System
<ul>
<li>Using apt-get
{% codeblock %}
apt-get update                 - Sync with Repositories.
apt-get upgrade                - Upgrade installed packages.
apt-get dist-upgrade           - Upgrade distribution packages.
apt-get install "Package Name" - Install the package.
apt-get remove  "Package Name" - Uninstall the package.
apt-get purge   "Package Name" - Removes the package as well as the configurations files.
apt-cache show  "Package name" - Shows what package is used for.
apt-cache search "Keywords"    - Search package name based on keywords.
{% endcodeblock %}
Tip: As mostly, updating takes time, you can club all the commands like "apt-get update && apt-get upgrade && apt-get dist-upgrade && poweroff". 
<br>
<br>
poweroff would shutdown the system after everything is updated.
<br>
<br>
</li>
<li>Using Debian Package Manager dpkg
{% codeblock %}
dpkg -i <Package>.deb          - install package.
dpkg -r <Package>              - Removes everything except configuration files.
dpkg -P <Package>              - Removes configurations files too.
dpkg -l                        - Shows the list of all installed packages.
dpkg -L "Package name"         - Shows a list of files installed by specific packages.
dpkg -S "File path"            - Shows the package to which a file belong to.
{% endcodeblock %}
</li>
</ul>
</li>

<li>Adding/Deleting/Modifying Users/Groups
{% codeblock%}
adduser <username> : Add a user.
   --gecos GECOS   : adduser won't ask for finger information.
   --system        : Create a system user.
   --quiet         : Suppress informational messages, only show warnings and errors.
   --disabled-login: Do not run passwd to set the password.
deluser <username> : Delete a user.
 --remove-home     : Remove the home directory of the user and its mailspool.
 --remove-all-files: Remove all files from the system owned by this user. 
 --backup          : Backup all files contained in the userhome and the mailspool-file to a file named /$user.tar.bz2 or /$user.tar.gz.
usermod            : Modify a user account.
 -e EXPIREDATE     : The date on which the user account will be disabled. The date is specified in the format YYYY-MM-DD.
 -L, --lock        : Lock a user's password.
 -U, --unlock      : Unlock a user's password.
groupadd           : Create a new group.
groupdel           : Delete a group.
groupmod           : Modify a group definition on the system.
{% endcodeblock %}
</li>
<li>Changing Group/Owner/Permission
{% codeblock%}
chown              : Change file owner and group.
-reference=RFILE   : use RFILE's owner and group rather than specifying OWNER:GROUP values.
-R, --recursive    : operate on files and directories recursively.
chmod              : change file mode bits.
chgrp              : change group ownership.
SUID bit           : SetUID bit specfies that an executable should run as its owner instead of the user executing it.
                   : SUID is mostly commonly used to run an executable as root, allowing users to perform tasks such as changing their passwords.
		   : If there is a flaw in a SUID root executable, you can run arbitrary code as root.
{% endcodeblock %}
</li>

<li>Mounting/Unmounting
{% codeblock %}
mount <device> <dir> : Mount a filesystem.
-r, --read-only      : Mount the filesystem read-only.
unmount {dir|device} : Umount file systems.	
{% endcodeblock %}
</li>
</ul>

<li>Linux Directories
{% codeblock %}
/home                             : users home directories.
/etc                              : system-wide configuration files.
/bin, /usr/bin, /usr/local/bin    : directories with executable files.
/lib, /usr/lib, /usr/local/lib    : shared libraries needed to support the applications.
/sbin, /usr/sbin, /usr/local/sbin : directories with executables supposed to be run by the Superuser.
/tmp, /var/tmp                    : temporary directories, watch out as /tmp is, by default, cleaned out on each reboot.
/usr/share/doc, /usr/share/man    : complete system documentation.
/dev                              : system device files. In Unix, hardware devices are represented as files.
/proc                             : "virtual" directory containing files through which you can query or tune Linux kernel settings.
{% endcodeblock %}
</li>

<li>Runlevels and Kernel Configurations

<ul type="i">
<li>Linux Boot Process:
<ol>
<li>BIOS starts the boot loader.</li>
<li>Boot loader loads the kernel into memory.</li>
<li>The Kernel mounts disks/partitions and starts the init daemon.</li>
<li>The init daemon starts services based on the runlevel.</li>
</ol></li>
<li>Linux has six runlevels 0-6. Scripts are contained in /etc/rc[0-6,S].d/. Each folder contains the scripts which are followed by either K or S. If the first letter is K that script is not executed. If S, that script is executed. /etc/inittab contains the default run level.
<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;border-color:#ccc;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:4px 4px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#ccc;color:#333;background-color:#fff;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:4px 4px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#ccc;color:#333;background-color:#f0f0f0;}
</style><table class="tg">
  <tr>
    <th class="tg-031e">ID</th>
    <th class="tg-031e">Name</th>
    <th class="tg-031e">Description</th>
  </tr>
  <tr>
    <td class="tg-031e">0</td>
    <td class="tg-031e">Halt</td>
    <td class="tg-031e">Shuts down the system.</td>
  </tr>
  <tr>
    <td class="tg-031e">1</td>
    <td class="tg-031e">Single-user Mode</td>
    <td class="tg-031e">Mode for administrative tasks.</td>
  </tr>
  <tr>
    <td class="tg-031e">2</td>
    <td class="tg-031e">Multi-user Mode</td>
    <td class="tg-031e">Does not configure network interfaces and does not export networks services.</td>
  </tr>
  <tr>
    <td class="tg-031e">3</td>
    <td class="tg-031e">Multi-user Mode with Networking</td>
    <td class="tg-031e">Starts the system normally.</td>
  </tr>
  <tr>
    <td class="tg-031e">4</td>
    <td class="tg-031e">Not used/User-definable</td>
    <td class="tg-031e">For special purposes.</td>
  </tr>
  <tr>
    <td class="tg-031e">5</td>
    <td class="tg-031e">Start system normally with display manager. ( with GUI )</td>
    <td class="tg-031e">Same as runlevel 3 + display manager.</td>
  </tr>
  <tr>
    <td class="tg-031e">6</td>
    <td class="tg-031e">Reboot</td>
    <td class="tg-031e">Reboot the system.</td>
  </tr>
</table>
</li>


<li>Sysctl - configure kernel parameters
{% codeblock %}
/etc/sysctl.conf                : Contains the variables for kernel parameters.
sysctl -a                       : Display all the kernel parameters
sysctl -w <kernel parameter>    : Change a sysctl setting.
PS: To make permanent changes to the kernel, edit the /etc/sysctl.conf file.
{% endcodeblock %}
</li>
<li> Kernel Modules contained in /lib/modules/$(uname -r)/
{% codeblock %}
lsmod      : list all loaded modules
modprobe   : load kernel modules
lspci      : list all pci devices
lsusb      : list all usb devices
hal-device : list all the Hardware Abstraction layer devices
{% endcodeblock %}</li>
<li>Debian GNU provides a convenient tool to manage runlevels (to control when services are started and shut down); it's called update-rc.d and there are two commonly used invocation methods:
{% codeblock %}
update-rc.d -f <service name> remove : Disabling a service
update-rc.d <service name> defaults  : Insert links using defaults, start in runlevel 2-5 and stop in runlevels 0,1 and 6.
{% endcodeblock %}
</li>
</ul>
</li>

<li>Programming Related
<ul>
<li>GIT: Version Control System, really useful for tracking your changes.
<br>
TODO: <a href="try.github.com">try.github.com</a> 15 mins tutorial.</li>
<li>gcc - GNU Compile Collection:
{% codeblock %}
To Compile: gcc -Wall -pedantic -g <C source file> -o <Executable file>
-Wall -pedantic : to check for all the warnings and errors if any.
-g              : to create the symbol file to be used by gdb 
-o              : to create the executable file.
{% endcodeblock %}</li>
<li>GDB: GNU debugger
{% codeblock %}
gdb -tui <Program name>
-tui              : for listing the source while debugging
b <linenumber>    : to set the break point
p <variable name> : to print the value of the variable
bt                : to print the stack call, mainly useful to find segmentation fault when multiple functions are called.
{% endcodeblock %}
</li>
</ul>
</li>

<li>Gathering Information
<ul>
<li>From Files
{% codeblock %}
/etc/issue     : Contains the message which is displayed on terminal before login. 
/etc/motd      : Contains the message which is displayed on terminal after login.
/proc/cpuinfo  : provides information about cpu.
/proc/meminfo  : provides information about memory/ RAM.
/proc/version  : provides information about the version of your system.
{% endcodeblock %}
</li>
<li>From Commands
{% codeblock %}
last      : shows all the login attempts and the reboot occurred.
lastb     : shows all the bad login attempts. 
lastlog   : shows the list of all the users and when did they login.
id        : print real and effective user and group IDs.
whoami    : whoami - print effective userid.
uname     : print system information.
      -a  : print all the information (Kernel name, nodename, kernel-release, kernel-version, machine, processor, hardware-platform)
pstree    : display a tree of processes.
hostname  : prints out the hostname of the machine which is stored in /etc/hostname.
{% endcodeblock %}
</li>
</ul>
</li>

<li>Useful Utilites/Commands
<ul>
<li>Copy - Copy files and directories.
{% codeblock %}
cp <SOURCE> <DIRECTORY>
-r        : recursive.
-a        : similar to preserve,
-p        : preserve
-v        : verbose.
{% endcodeblock %}
</li>
<li>cut - remove sections from each line of files.
{% codeblock %}
-d        : use DELIM instead of TAB for field delimiter.
-f        : select only these fields.
{% endcodeblock %}
</li>

<li>Pipes
{% codeblock %}
\>        : direct normal output.
2>        : direct error output.
&>        : direct all output.
{% endcodeblock %}
</li>

<li>tar - Archiving utility
{% codeblock %}
-c        : create archive
-t        : list the content of the file
-x        : extract the files
-j        : bzip2 format
-z        : gzip format
{% endcodeblock %}
</li>

<li>find - Searching files
{% codeblock %}
-user       : File is owned by user uname (numeric user ID allowed).
-group      : File belongs to group gname (numeric group ID allowed).
-size       : File uses n units of space. c/k/M/G: bytes/Kilobytes/Megabytes/Gigabytes.
-name       :
{% endcodeblock %}
</li>

<li>Some other
{% codeblock %}
nm-applet : a applet for network manager.
wc        : print newline, word, and byte counts for each file.
   -c     : print the bytes count.
   -l     : print the lines count.
   -w     : print the word count.
sort      : sort lines of text files.
diff      : compare files line by line.
less      : print information one per page.
more      : prints information one per page.
head      : prints first 10 lines
tail      : prints last 10 lines.
whatis    : Provides a one line description of the commands.
which     : locate a command.
whereis   : locate the binary, source, and manual page files for a command.
locate    : find files by name
cal       : Display calendar
date      : Display date. Date command provides multiples options for displaying day and time, very helpful in creating backups with name having time and date.
tr        : Converts from smaller to uppercase. tr stands for translate.
   -d     : delete characters in the text.
tee       : saves output in file as well as forward it.
touch     : Create zero byte files, mainly used for changing the timestamps of the file.
make      : If your program source file name is test.c/cpp, then you can directly write make test, this would compile the test.c/cpp program. Remember this it's a faster way.
stat      : View detailed information about a file, including its name,size, last modified date, and permissons.
uniq      : Report or omit repeated lines.
   -c     : prefix lines by the number of occurrences. (--count)
{% endcodeblock %}
</li>
</ul>
</li>

<li>Special Characters:
{% codeblock %}
*(asterik)          : A wildcard used to represent zero or more characters in a filename. For example: ls *.txt will list all the names ending in ".txt" such as "file1.txt" and "file23.txt".
?(question mark)    : A wildcard used to represent a single character in a filename. For example ls pic?.jpg would match "pic1.jpg" and "pic2.jpg" but not "pic24.jpg" or "pic.jpg".
[](square brackets) : These are used to specify a range of values to match. For example, "[0-9]" and "[a-z]".
;(semi colon)       : Command separator that can be used to run multiple commands on a single line unconditionally.
&&(double ampersand): Command separator which will only run the second command if the first one is successful (does not return an error.)
||(double pipe)     : Command separator which will only run the second command if the first command failed (had errors). Commonly used to terminate the script if an important command fails.
{% endcodeblock %}</li>
<li>Few Important Differences in Commands:
<ol type="i">
<li> su&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; :&nbsp; Change users or become superuser. The difference between su - <username> and su <username> is that former su - would switch to the new user directory. It would also change the environment variable according to the changed user.
{% codeblock %}
su -c "command" : Specify a command that will be invoked by the shell using its -c.
{% endcodeblock %}</li>
<li>sudo&nbsp;&nbsp; :&nbsp; execute a command as another user. The difference between su and sudo is 'su' forces you to share your root password to other users whereas 'sudo' makes it possible to execute system commands without root password. 'sudo' lets you use your own password to execute system commands i.e. delegates system responsibility without root password.</li>
</ol></li>
<br>
<li>Tips and Tricks
<ul>
<li>Scan files for a text present in them
Find a way to scan my entire linux system for all files containing a specific string of text. Just to clarify, I'm looking for text within the file, not in the file name.
{% codeblock %}
grep -rnw 'directory' -e "pattern" --include={*.c,*.h} --exclude=*.o
-r                    : search recursively
-n                    : print line number
-w                    : match the whole word. 
--include={*.c,*.h}   : Only search through the files which have .c or .h extensions.
--exclude=*.o         : Exclude searching in files with .o extensions.
PS: --exclude or --include parameter could be used for efficient searching. 

-i, --ignore-case     : 'it DoesNt MatTTer WhaT thE CAse Is'
-v, --invert-match    : 'everything , BUT that text'
-A <NUM>              : Print NUM lines of trailing context after matching lines.
-B <NUM>              : Print NUM lines of trailing context before matching lines.
-a, --text            : Process a binary file as if it were text; this is equivalent to the --binary-files=text option.
{% endcodeblock %}
</li>
<li>We often do mistakes while updating using apt-get which just leaves us with command line access to the system (GUI messed up). Possibly we unintentionally removed some neccessary packages.
<br>
<br>
In this case, look for /var/log/apt/history.log, look for the time around which your system was broken. Copy the removed packages
which would be in the format of 
{% codeblock %}
libapt-inst1.5:amd64 (0.9.7.9+deb7u5, 0.9.7.9+deb7u6), apt-utils:amd64 (0.9.7.9+deb7u5, 0.9.7.9+deb7u6).
{% endcodeblock %}
To reinstall these packages you just need the package name such as 
{% codeblock %}
libapt-inst1.5, apt-utils.
{% endcodeblock %}

<ul>
<li>Step1: Use sed to search for pattern "), " and replace it with "), \n". This would separate the packages by new line. Within vi ":%s/), /\n/g"</li>
<li>Step2: Use cut -d ":" -f 1 to remove :amd64 and anything after that.</li>
<li>Step3: Now we have to get them back in one line rather than multiple lines. Within vi ":%s/\n/ /g"</li>
</ul>
</li>
<li>Want to keep track of etc directory? 
<br>
Etckeeper may be a bit more advanced, and it is used to put your whole /etc directory under revision control. 
To install and initialize it,
{% codeblock %}
apt-get install etckeeper
etckeeper init
cd /etc
git commit -am Initial
{% endcodeblock %} 
After that, you can see pending changes in /etc by cd-ing into it and running 
{% codeblock %}
git status or git diff
{% endcodeblock %} at any time, and you can see previous, committed changes by running 
{% codeblock %}
git log or git log -p
{% endcodeblock %} You can override pending changes to any file with the last committed version with 
{% codeblock %}
git checkout FILENAME
{% endcodeblock %}
</li>

</ul>
</li>

<li>Bash equality Tests
{% codeblock %}
test       : checks file types and compare values
   -d      : check if the file is a directory
   -e      : check if the file exists
   -f      : check if the file is a regular file
   -g      : check if the file has SGID permissions
   -r      : check if the file is readable
   -s      : check if the file's size is not 0
   -u      : check if the file has SUID permissions
   -w      : check if the file is writeable
   -x      : check if the file is executable
{% endcodeblock %}
Example:
{% codeblock %}
if test -f /etc/foo.txt
then

It can also be written as 

if [ -f /etc/foo.txt ]; then

--square brackets [] form test.
-- There has to be white space surrounding both square bracket
{% endcodeblock %}
List of equality tests:
<ul>
<li>
Checks equality between numbers:
{% codeblock %}
x -eq y         : Check is x is equals to y
x -ne y         : Check if x is not equals to y
x -gt y         : Check if x is greater than y
x -lt y         : Check if x is less than y
{% endcodeblock %}</li>
<li>Checks equality between strings:
{% codeblock %}
x = y           : Check if x is the same as y
x != y          : Check if x is not the same as y
-n x            : Evaluates to true if x is not null
-z x            : Evaluates to true if x is null.
{% endcodeblock %}</li>
</ul>
</li>

<li>Some Important Definitions:
<br>
We want our information to:
<ul>
<li>be read by only the right people (confidentiality)</li>
<li>only be changed by authorised people or processes (integrity)</li>
<li>be available to read and use whenever we want (availability).</li>
</ul>
<br>
Non-repudiation is about ensuring that users cannot deny knowledge of sending a message or performing some online activity at some later point in time. For example, in an online banking system the user cannot be allowed to claim that they didn’t send a payment to a recipient after the bank has transferred the funds to the recipient’s account.</li>

</ol>

**TODO**   

That was most probably a lot of information, to practice all the it's always better to do some hands on.
<ol>

<li>To Learn Programming, Debugging and Git
<ul>
<li> To learn git, would suggest to do a 15 min tutorial on <a href="try.github.com">try.github.com</a>.</li>
<li> Create a small program using vi with syntax on, compile it using gcc using make.</li>
<li> Debug it using gdb -tui option to see the source code, experiment with breakpoints, and printing values.</li>
<li> Track that program using git, upload them to a remote server, then pull your code, check if its the same.</li>
</ul>
</li>

<li>To learn System administration
<ul>
<li> Change the messages before login, after login. Remember the escapes sequences used in the /etc/issue.  man agetty lists them.</li>
<li> Supposed you got access via shell to a linux system and extract some information from it. Create a script
<ul>
<li>Create a alice, bob, eve with the password "password" HINT: set password using chpasswd, look some examples in google to change from cmdline.</li>
<li>Login from eve.</li>
<li>Copy and preserve all the configuration files from /etc and save it in eve home directory in the folder etc-backup-YYYYMMDD, direct all errors to cp.err</li>
<li>Change the owner of all the files in the folder just created to bob and the group of all the files to alice and change the permission of all the files to 440 i.e r--r-----
HINT: would have to be logined as root</li>
<li>Provide me all the unique shells used by the user present in the system in CAPS. HINT: /etc/passwd file contains all the shells, three four commands would be used.</li>
<li>Cover your tracks, clear out the /var/log/auth.log (Have a look at this file and create a backup before clearing), clean your terminal history
HINT: man pages would help you.</li>
<li>Delete all the user bob, alice, eve. Make sure you delete there files too.</li>
</ul>
</li>
<li> Turn off the ping responses for your system permanently and turn on the Syn-cookies protection mechanism. {Search on Google}</li>
<li> Use your previous script to create three users alice, bob, eve. 
<ul>
<li>-create a folder dept inside it two folder hr, web. </li>
<li>create two group hr and web.</li>
<li>change group of web folder to web and hr to hr.</li>
<li>add alice and bob user to web group</li>
<li>add alice to hr group.</li>
<li>check that bob is not able to enter in the hr folder and alice is able to enter in both hr and web folder</li>
<li>-add user bob to sudo group and check if it is able to run sudo ifconfig ?</li>
</ul>
</li>
<li>Objective to get few IP addresses of Microsoft.com Domains.
<ul>
<li>Download the index.html page of microsoft.com</li>
<li>Every link in html is referred by href. Filter all the href (which would contain the link to different domains for Microsoft)</li>
<li>Sort and find unique list. Get their ip addresses</li>
<li>HINT: Tools such as cut, grep, wget, sort, uniq, host and little bit of bash scripting would be used.</li>
</ul></li>
</ul>
</li>
</ol>
