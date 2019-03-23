.. Linux Essentials documentation master file, created by
   sphinx-quickstart on Fri Jan 27 15:06:58 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

*****************************
The Essentials : Linux Basics
*****************************

This post lists essential commands and concepts which would be helpful to a Linux user. We would cover tools required for programming (Vi, git), system administration (Bash configuration files, Updating Debian Linux System, Adding/ Deleting/ Modifying Users/ Groups, Changing Group/ Owner/ Permission, Mounting/ Unmounting, Linux Directories, Runlevels and Kernel Configurations). Also, provide some useful tips, tricks and TODO which would help you learn and practice.

Vi : Powerful Editor
======================

Open file with vi
-----------------

::

  vi <filename>               - Open a file to edit in Vi editor.

Vi Modes
--------

Two modes - Command and Insert Mode. All commands below are in command mode.

::

  h,l,j,k                     - Move left, right, down, up
  w                           - Move to the start of the next word.
  e                           - Move to the end of the word.
  b                           - Move to the beginning of the word.
  3w                          - 3w is similar to pressing w 3 times, moves to the start of the third word.
  30i-'EscKey'                - 30<insert>-<EscapeKey> : Inserts 30 - at once.
  f                           - find and move to the next (or previous) occurrence of a character. fo find next o.
  3fo                         - find third occurrence of o
  %                           - In text that is structured with parentheses or brackets, ( or { or [, use % to jump to the matching parenthesis or bracket.
  0 (Zero)                    - Reach beginning of the line
  $                           - Reach end of the line.
  *                           - Find the next occurrence of the word under cursor
  #                           - Find the previous occurrence of the word under cursor
  gg                          - Reach beginning of the file
  G                           - Reach end of the file
  30G                         - Reach the 30th line in the file
  /<text>                     - Search for the text. Utilize n, N for next and previous occurrences.
  o                           - Insert a new line below the cursor
  O                           - Insert a new line above the cursor
  x                           - Delete the character
  r                           - replace the character with the next key pressed.
  dw                          - Delete the current word.
  dd                          - Delete the current line. 
  d$                          - Delete the text from where your cursor is to the end of the line.
  dnd                         - Delete n lines.
  .                           - Repeat the last command
  :q                          - Quit.
  :wq                         - Save and close.
  :syntax on                  - Turn on Syntax highlighting for C programming and other languages.
  :history                    - Shows the history of the commands executed
  :set number                 - Turn on the line numbers.
  :set nonumber               - Turn off the line numbers.
  :set spell spelllang=en_us  - Turn spell checking on with spell language as "en_us"
  :set nospell                - Turn spell checking off
  :set list                   - If 'list' is on, whitespace characters are made visible. The default displays "^I" for each tab, and "$" at each EOL (end of line, so trailing whitespace can be seen)
  :u                          - Undo one change.
  :!{cmd}                     - Run the command without exiting the vim. {cmd} can be whoami without external brackets.
  z=                          - If the cursor is on the word ( which is highlighted with spell check), Vim will suggest a list of alternatives that it thinks may be correct.
  yy                          - Yank or copy current line.
  y$, yny                     - Similar to delete lines.
  p                           - Paste the line in the buffer in to text after the currentline.
  :%!xxd                      - to turn it into a hexeditor. 
  :%!xxd -r                   - to go back to normal mode (from hexedit mode)

Vi Configuration Files
----------------------
    
Two configurations files which are important:

.vimrc
^^^^^^
Contains optional runtime configuration settings to initialize Vim when it starts. Example: If you want Vim to have syntax on and line numbers on, whenever you open vi, enter syntax on and set number in this file.

::
  
 ##Sample contents of .vimrc

 syntax on
 set number

A good details about various options which can be set in vimrc can be found at `A Good Vimrc <https://dougblack.io/words/a-good-vimrc.html>`_

.viminfo
^^^^^^^^
Viminfo file stores command-line, search string, input-line history and other stuff. Useful if you want to find out what user has been doing in vi.

.. Tip:: Both files are present in user home directory.

Replace text in Vi
------------------

:: 

  :s/test/learn     - would replace test to learn in current line but only first instance.
  :s/test/learn/g   - would replace test to learn in current line all the instance.
  :s/test/learn/gi  - would replace test (all cases) to learn in current line all the instance.
  :%s/test/learn/gi - would replace test to learn in the file (all lines)

Other Info
^^^^^^^^^^

* `Vim Awesome <https://vimawesome.com/>`_ provides Awesome VIM plugins from across the universe. Few good one are

 * The NERD tree : Tree explorer plugin for vim

  ::

     :NERDTreeToggle : Toggle the NERD Tree
     :NERDTreeFocus  : Set the focus to NerdTree

 * Syntastic     : Syntax checking hacks for vim

  ::

   SyntasticCheck - Check for the possible syntax issues

 * Youcompleteme : Code-completion engine for Vim
 * `fzf <https://github.com/junegunn/fzf.vim>`_ :  Bundle of fzf-based commands and mappings

  ::

   GFiles [OPTS] :    Git files (git ls-files)
   GFiles?       :    Git files (git status)
   History       :    v:oldfiles and open buffers
   History:      :    Command history
   History/      :    Search history
   Snippets      :    Snippets (UltiSnips)
   Commits       :    Git commits (requires fugitive.vim)
   BCommits      :    Git commits for the current buffer
   Commands      :    Commands

 * `UltiSnips <https://github.com/SirVer/ultisnips>`_ The ultimate snippet solution for Vim
 * `Tabular <https://github.com/godlygeek/tabular>`_ : Vim script for text filtering and alignment

   ::

    Select the text which you want to align in the visual mode (Do make sure that cursor is also at the same position as visual)
    :Tabularize /{pattern to be aligned}




* Utilize `Vundle, the plug-in manager for Vim <http://github.com/VundleVim/Vundle.Vim>`_

 ::

  :PluginList       - lists configured plugins
  :PluginInstall    - installs plugins; append `!` to update or just :PluginUpdate
  :PluginSearch foo - searches for foo; append `!` to refresh local cache
  :PluginClean      - confirms removal of unused plugins; append `!` to auto-approve removal

Bash configuration files - For Debian/Ubuntu based Systems
==========================================================

Important Files
---------------

* ~/.bash_profile - Stores user environment variables.
* ~/.bash_history - contains all the history of the commands.
* ~/.bash_logout  - contains the command which are executed when bash is exited.
* ~/.bashrc       - setting of variables for bash.
* /etc/profile    - Global system configuration for bash which controls the environmental variables and programs that are to be run when bash is executed. Setting of PATH variable and PS1.
* /etc/bashrc     - Global system configuration for bash which controls the aliases and functions to be run when bash is executed

Important variables
-------------------

* HISTSIZE     - Controls the number of commands to remember in the history command. The default value is 500.
* HISTFILE     - Defines the file in which all commands will be logged to. Normally the value for this variable is set to ~/.bash_history. This means that whatever you type in bash will be stored into the value of HISTFILE. It is advisable to leave it undefined, or pipe the output to /dev/null (For privacy reasons).
* HISTFILESIZE - Defines the maximum number of commands in ~/.bash_history.


System Administration
======================

Updating Debian Linux System
-----------------------------

Using apt-get
^^^^^^^^^^^^^^

::

  apt-get update                 - Sync with Repositories.
  apt-get upgrade                - Upgrade installed packages.
  apt-get dist-upgrade           - Upgrade distribution packages.
  apt-get install "Package Name" - Install the package.
  apt-get remove  "Package Name" - Uninstall the package.
  apt-get purge   "Package Name" - Removes the package as well as the configuration files.
  apt-cache show  "Package name" - Shows what package is used for.
  apt-cache search "Keywords"    - Search package name based on keywords.

.. Tip:: As mostly, updating takes time, you can club all the commands like "apt-get update && apt-get upgrade && apt-get dist-upgrade &&  poweroff". poweroff would shutdown the system after everything is updated.


Using Debian Package Manager dpkg
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:: 

  dpkg -i <Package>.deb          - Install package.
  dpkg -r <Package>              - Removes everything except configuration files.
  dpkg -P <Package>              - Removes configurations files too.
  dpkg -l                        - Shows the list of all installed packages.
  dpkg -L "Package name"         - Shows a list of files installed by specific packages.
  dpkg -S "File path"            - Shows the package to which a file belong to.

Adding/Deleting/Modifying Users/Groups
--------------------------------------

::

  adduser <username> : Add a user.
   --gecos GECOS     : adduser won't ask for finger information.
   --system          : Create a system user.
   --quiet           : Suppress informational messages, only show warnings and errors.
   --disabled-login  : Do not run passwd to set the password.
  deluser <username> : Delete a user.
   --remove-home     : Remove the home directory of the user and its mailspool.
   --remove-all-files: Remove all files from the system owned by this user.
   --backup          : Backup all files contained in the userhome and the mailspool-file to a file named /$user.tar.bz2 or /$user.tar.gz.
  usermod            : Modify a user account.
   -e EXPIREDATE     : The date on which the user account will be disabled. The date is specified in the format YYYY-MM-DD.
   -L, --lock        : Lock a user's password.
   -U, --unlock      : Unlock a user's password
  groupadd           : Create a new group.
  groupdel           : Delete a group.
  groupmod           : Modify a group definition on the system.

Changing Group/Owner/Permission
-------------------------------

::

  chown              : Change file owner and group.
   -reference=RFILE  : use RFILE's owner and group rather than specifying OWNER:GROUP values.
   -R, --recursive   : operate on files and directories recursively.
  chmod              : change file mode bits.
  chgrp              : change group ownership.
  SUID bit           : SetUID bit specifies that an executable should run as its owner instead of the user executing it.
                     : SUID is mostly commonly used to run an executable as root, allowing users to perform tasks such as changing their passwords.
                     : If there is a flaw in a SUID root executable, you can run arbitrary code as root.

Mounting/ Unmounting
--------------------

::

  mount <device> <dir> : Mount a filesystem.
     -r, --read-only   : Mount the filesystem read-only.
  unmount {dir|device} : Unmount file systems.

Mounting Windows share on Linux
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:: 

  mount -t cifs -o username=<share user>,password=<share password>,domain=example.com //WIN_PC_IP/<share name> /mnt

Linux Directories
-----------------

::

  /home                             : users home directories.
  /etc                              : system-wide configuration files.
  /bin, /usr/bin, /usr/local/bin    : directories with executable files.
  /lib, /usr/lib, /usr/local/lib    : shared libraries needed to upport the applications.
  /sbin, /usr/sbin, /usr/local/sbin : directories with executables supposed to be run by the Superuser.
  /tmp, /var/tmp                    : temporary directories, watch out as /tmp is, by default, cleaned out on each reboot.
  /usr/share/doc, /usr/share/man    : complete system documentation.
  /dev                              : system device files. In Unix, hardware devices are represented as files.
  /proc                             : "virtual" directory containing files through which you can query or tune Linux kernel settings.

Runlevels and Kernel Configurations
-----------------------------------

Linux Boot Process
^^^^^^^^^^^^^^^^^^

:: 
      
  1. BIOS start the boot loader. 
  2. Boot loader loads the kernel into memory.
  3. The Kernel mounts disks/partitions and starts the init daemon. 
  4. The init daemon starts services based on the runlevel.

Linux has six runlevels 0-6. Scripts are contained in /etc/rc[0-6,S].d/. Each folder contains the scripts which are followed by either K or S. If the first letter is K that script is not executed. If S, that script is executed. /etc/inittab contains the default run level.

====   ========================================================   =============================================================================
ID     Name                                                       Description
====   ========================================================   =============================================================================
0      Halt                                                       Shuts down the system.                                                      
1      Single-user Mode                                           Mode for administrative tasks.                     
2      Multi-user Mode                                            Does not configure network interfaces and does not export networks services      
3      Multi-user Mode with Networking                            Starts the system normally.                       
4      Not used/User-definable                                    For special purposes.                        
5      Start system normally with display manager (with GUI).     Same as runlevel 3 + display manager               
6      Reboot                                                     Reboot the system                              
====   ========================================================   =============================================================================

Sysctl - configure kernel parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

  /etc/sysctl.conf                : Contains the variables for kernel parameters.
  sysctl -a                       : Display all the kernel parameters
  sysctl -w <kernel parameter>    : Change a sysctl setting.

.. Note:: To make permanent changes to the kernel, edit the /etc/sysctl.conf file.

Kernel Modules
^^^^^^^^^^^^^^

Kernel modules are contained in /lib/modules/$(uname -r)/

:: 
 
  lsmod      : list all loaded modules
  modprobe   : load kernel modules
  lspci      : list all pci devices
  lsusb      : list all usb devices
  hal-device : list all the Hardware Abstraction layer devices

Manage Runlevels
^^^^^^^^^^^^^^^^

Debian GNU provides a convenient tool to manage runlevels (to control when services are started and shut down);

* update-rc.d and there are two commonly used invocation methods:

 :: 

   update-rc.d -f <service name> remove : Disabling a service.
   update-rc.d <service name> defaults  : Insert links using defaults, start in runlevel 2-5 and stop in runlevels 0,1 and 6.

* Systemctl : Control the systemd system and service manager. systemctl may be used to introspect and control the state of the "systemd" system and service manager.

 :: 

   systemctl : Present a detailed output about the different services running.

   e.g.
   
   systemctl status <service_name> - Status of the service.
   systemctl start <service_name>  - Start the service

Screen Multiplexer
------------------

tmux
^^^^

::

 tmux new -s myname            : start new with session name:
 tmux list-sessions            : show sessions
 tmux ls                       : show sessions
 tmux list-windows             : show windows
 tmux attach-session -t myname : Attach to session named "myname"
 tmux a -t myname              : Attach to session named "myname"
 (Prefix) + d                  : detach

**Windows (Tabs)**

::

 (Prefix Key) + 
 c  create window
 w  list windows
 n  next window
 p  previous window
 f  find window
 ,  name window
 &  kill window
 "  split pane horizontally.
 %  split pane vertically.
 arrow key — switch pane.
 Hold Ctrl+b, don’t release it and hold one of the arrow keys — resize pane.


**tmux.conf**

::

 # Enable mouse mode (tmux 2.1 and above)
 set -g mouse on

**Reloading tmux config**

If we have made changes to tmux configuration file in the ~/.tmux.conf file, it shouldn’t be necessary to start the server up again from scratch with kill-server. Instead, we can prompt the current tmux session to reload the configuration with the source-file command.
This can be done either from within tmux, by pressing Ctrl+B or Prefix key and then : to bring up a command prompt, and typing:

::

 :source-file ~/.tmux.conf

Or simply from a shell:

::

 $ tmux source-file ~/.tmux.conf

This should apply your changes to the running tmux server without affecting the sessions or windows within them.

**Copy Paste**

For copying, Press the Shift key; i.e., Shift-MouseHighlight properly selects text and - still holding down the shift key

* we can right-click and get the standard bash context menu with Copy, Paste, etc.
* or Ctrl-Shift-C and Ctrl-Shift-V does work to copy and paste text.

File System Superblock
----------------------

Superblock is stores the metadata of the file system such as

* Blocks in the file system
* No of free blocks in the file system
* Inodes per block group
* Blocks per block group
* No of times the file system was mounted since last fsck.
* Mount time
* UUID of the file system
* Write time
* File System State (ie: was it cleanly unounted, errors detected etc)
* The file system type etc(ie: whether its ext2,3 or 4).
* The operating system in which the file system was formatted

View superblock information
^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

 dumpe2fs -h /dev/sda4
 dumpe2fs 1.42.9 (4-Feb-2014)
 Filesystem volume name:   cloudimg-rootfs
 Last mounted on:          /
 Filesystem UUID:          f75f9307-27dc-xxxx-87b7-xxxxxxxxx
 Filesystem magic number:  0xEF53
 Filesystem revision #:    1 (dynamic)
 Filesystem features:      has_journal ext_attr resize_inode dir_index filetype needs_recovery extent flex_bg sparse_super large_file huge_file uninit_bg dir_nlink extra_isize
 Filesystem flags:         signed_directory_hash
 Default mount options:    (none)
 Filesystem state:         clean
 Errors behavior:          Continue
 Filesystem OS type:       Linux
 .....sniped.......

Programming
===========

GIT
---

Version Control System, really useful for tracking your changes.
 
.. Todo :: 
      `try.github.com <https://try.github.com>`_ 15 mins tutorial.


Command-line substitute for gitk

::

 git log --graph --abbrev-commit --pretty=oneline --decorate

List all commits for a specific file

::

 git log --follow -- filename

See the changes in a Git commit?

::

 git show <COMMIT>

cc - GNU Compile Collection
---------------------------

:: 

  To Compile: gcc -Wall -pedantic -g <C source file> -o <Executable file>
  -Wall -pedantic : to check for all the warnings and errors if any.
  -g              : to create the symbol file to be used by gdb 
  -o              : to create the executable file.


GDB: GNU debugger
-----------------

::

  gdb -tui <Program name>

  tui               : for listing the source while debugging
  <linenumber>      : to set the break point
  p <variable name> : to print the value of the variable
  bt                : to print the stack call, mainly useful to find segmentation fault when multiple functions are called.


Gathering Information
=====================

From Files
----------

::
        
  /etc/issue     : Contains the message which is displayed on terminal before login.
  /etc/motd      : Contains the message which is displayed on terminal after login.
  /proc/cpuinfo  : provides information about CPU.
  /proc/meminfo  : provides information about memory/ RAM.
  /proc/version  : provides information about the version of your system. 

From Commands
-------------

::

  last      : shows all the login attempts and the reboot occurred.
  lastb     : shows all the bad login attempts. 
  lastlog   : shows the list of all the users and when did they login.
  id        : print real and effective user and group IDs.
  whoami    : whoami - print effective userid.
  uname     : print system information.
    -a      : print all the information (Kernel name, nodename, kernel-release, kernel-version, machine, processor, hardware-platform)
  pstree    : display a tree of processes.
  hostname  : prints out the hostname of the machine which is stored in /etc/hostname.


Useful Utilities/ Commands
==========================

Grep - Global Regular Expression Print
--------------------------------------

Two ways to provide input to Grep:

* search a given file or files on a system (including a recursive search through sub-folders).

 :: 

  grep bitvijays /etc/passwd

* Grep also accepts inputs (usually via a pipe) from another command or series of commands.

 ::

   cat /etc/passwd | grep bitvijays

Syntax
^^^^^^

::

 grep [options] [regexp] [filename]

    -i, --ignore-case        : 'it DoesNt MatTTer WhaT thE CAse Is'
    -v, --invert-match       : 'everything , BUT that text'
    -A <NUM>                 : Print NUM lines of trailing context after matching lines.
    -B <NUM>                 : Print NUM lines of trailing context before matching lines.
    -C <NUM>                 : Print additional (leading and trailing) context lines before and after the match.
    -a, --text               : Process a binary file as if it were text; this is equivalent to the --binary-files=text option.
    -w                       : Whole-word search
    -L --files-without-match : which outputs the names of files that do NOT contain matches for your search pattern.
    -l --files-with-matches  : which prints out (only) the names of files that do contain matches for your search pattern.

    -H <pattern> filename    : Print the filename for each match.
	example: grep -H 'a' testfile
		 testfile:carry out few cyber-crime investigations

	Now, let’s run the search a bit differently:
		cat testfile | grep -H 'a'
		(standard input):carry out few cyber-crime investigations

.. Note :: Regular expression should be enclosed in single quotation marks or double quotes (allows environment variables to be used), to prevent the shell (Bash or others) from trying to interpret and expand the expression before launching the grep process.

Using regular expressions
^^^^^^^^^^^^^^^^^^^^^^^^^

::
 
 grep 'v.r' testfile
 thank you very much

In the search above, . is used to match any single character - matches “ver” in “very”. 

A regular expression may be followed by one of several repetition operators:

* The period (.) matches any single character.
* ? means that the preceding item is optional, and if found, will be matched at the most, once.
* \* means that the preceding item will be matched zero or more times.
* \+ means the preceding item will be matched one or more times.
* Matching with times

 * {n} means the preceding item is matched exactly n times, 
 * {n,} means the item is matched n or more times. 
 * {n,m} means that the preceding item is matched at least n times, but not more than m times. 
 * {,m} means that the preceding item is matched, at the most, m times.


**grep -e / grep -E**

::

  Matcher Selection
   -E, --extended-regexp        :  Interpret PATTERN as an extended regular expression.

  Matching Control
   -e PATTERN, --regexp=PATTERN :  Use  PATTERN  as the pattern.  If this option is used multiple times or is combined with the -f (--file) option, search for all patterns given.  This option can be used to protect a pattern beginning with “-”.

Example:

::

 grep -E '^[0-9a-zA-Z]{30,}'

Grep anything which is starting with string containing characters from 0-9,a-z or A-Z and has matched 30 or more times

Search a specific string
^^^^^^^^^^^^^^^^^^^^^^^^
Scan files for a text present in them Find a way to scan my entire linux system for all files containing a specific string of text. Just to clarify, I'm looking for text within the file, not in the file name.

:: 
        
  grep -rnw 'directory' -e "pattern" --include={*.c,*.h} --exclude=*.o

    -r                    : search recursively
    -n                    : print line number
    -w                    : match the whole word. 
    --include={*.c,*.h}   : Only search through the files which have .c or .h extensions.
    --exclude=*.o         : Exclude searching in files with .o extensions.
 
.. Note :: --exclude or --include parameter could be used for efficient searching.

Line and word anchors
^^^^^^^^^^^^^^^^^^^^^

* The ^ anchor specifies that the pattern following it should be at the start of the line:

 ::

  grep '^th' testfile
  this

* The $ anchor specifies that the pattern before it should be at the end of the line.

 ::
  
  grep 'i$' testfile
  Hi

* The operator \< anchors the pattern to the start of a word.

 ::
 
  grep '\<fe' testfile
  carry out few cyber-crime investigations

* \> anchors the pattern to the end of a word.

 ::

  grep 'le\>' testfile
  is test file

* The \b (word boundary) anchor can be used in place of \< and \> to signify the beginning or end of a word:

 ::
  
  grep -e '\binve' testfile
  carry out few cyber-crime investigations

Shell expansions - input to Grep
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If we don’t single-quote the pattern passed to Grep, the shell could perform shell expansion on the pattern and actually feed a changed pattern to Grep. 

::

 grep "$HOME" /etc/passwd
 root:x:0:0:root:/root:/bin/bash

We used double quotes to make the Bash shell replace the environment variable $HOME with the actual value of the variable (in this case, /root). Thus, Grep searches the /etc/passwd file for the text /root, yielding the two lines that match.

::

 grep `whoami` /etc/passwd
 root:x:0:0:root:/root:/bin/bash

Here, back-tick expansion is done by the shell, replacing `whoami` with the user name (root) that is returned by the whoami command.

    
Copy - Copy files and directories
---------------------------------

::

  cp <SOURCE> <DIRECTORY>
    -r        : recursive.
    -a        : similar to preserve,
    -p        : preserve
    -v        : verbose.

cut - remove sections from each line of files
---------------------------------------------

::  

 cut OPTION... [FILE]...
  -d        : use DELIM instead of TAB for field delimiter.
  -f        : select only these fields.

Pipes
-----

::

  >         : direct normal output.
  2>        : direct error output.
  &>        : direct all output.

tar - Archiving utility
-----------------------
    
::

 tar
  -c        : create archive
  -t        : list the content of the file
  -x        : extract the files
  -j        : bzip2 format
  -z        : gzip format

find - Searching files
----------------------

::

  find / -name somename 

  -user       : File is owned by user uname (numeric user ID allowed).
  -group      : File belongs to group gname (numeric group ID allowed).
  -size       : File uses n units of space. c/k/M/G: bytes/Kilobytes/Megabytes/Gigabytes.
  -name       : Base  of  file  name

Delete empty file and directories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

  find -empty -type d -delete
  find -empty -type f -delete

Find each file in the current directory and tell it's type and grep JPEG files.

::

  find . -type f -exec file {} + | grep JPEG

Other commands
--------------

:: 

  nm-applet : a applet for network manager.
  wc        : print newline, word, and byte counts for each file.
   -c       : print the bytes count.
   -l       : print the lines count.
   -w       : print the word count.
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
   -d       : delete characters in the text.
  tee       : saves output in file as well as forward it.
  touch     : Create zero byte files, mainly used for changing the timestamps of the file.
  make      : If your program source file name is test.c/cpp, then you can directly write make test, this would compile the test.c/cpp program. Remember this it's a faster way.
  stat      : View detailed information about a file, including its name, size, last modified date and permissions.
  uniq      : Report or omit repeated lines.
    -c      : prefix lines by the number of occurrences. (--count)

Special Characters
------------------

::

  *(asterik)          : A wildcard used to represent zero or more characters in a filename. For example: ls *.txt will list all the names ending in ".txt" such as "file1.txt" and "file23.txt".
  ?(question mark)    : A wildcard used to represent a single character in a filename. For example ls pic?.jpg would match "pic1.jpg" and "pic2.jpg" but not "pic24.jpg" or "pic.jpg".
  [](square brackets) : These are used to specify a range of values to match. For example, "[0-9]" and "[a-z]".
  ;(semi colon)       : Command separator that can be used to run multiple commands on a single line unconditionally.
  &&(double ampersand): Command separator which will only run the second command if the first one is successful (does not return an error.)
  ||(double pipe)     : Command separator which will only run the second command if the first command failed (had errors). Commonly used to terminate the script if an important command fails.
  # (Comments)        : Lines beginning with a # (with the exception of #!) are comments and will not be executed.



Bash 
====

Equality Tests
--------------

:: 

  test      : checks file types and compare values
    -d      : check if the file is a directory
    -e      : check if the file exists
    -f      : check if the file is a regular file
    -g      : check if the file has SGID permissions
    -r      : check if the file is readable
    -s      : check if the file's size is not 0
    -u      : check if the file has SUID permissions
    -w      : check if the file is writeable
    -x      : check if the file is executable

Example
  
:: 

  if test -f /etc/foo.txt
  then 

It can also be written as 

::  

  if [ -f /etc/foo.txt ]; then

  --square brackets [] form test.
  -- There has to be white space surrounding both square bracket

List of equality tests
----------------------

Checks equality between numbers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::
    
  x -eq y         : Check is x is equals to y
  x -ne y         : Check if x is not equals to y
  x -gt y         : Check if x is greater than y
  x -lt y         : Check if x is less than y

Checks equality between strings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

  x = y           : Check if x is the same as y
  x != y          : Check if x is not the same as y
  -n x            : Evaluates to true if x is not null
  -z x            : Evaluates to true if x is null.
  ##Check in the following way --> if [ -z "$VAR" ];

Bash Command Substitution
-------------------------

Command substitution allows the output of a command to replace the command itself. Command substitution occurs when a command is enclosed as follows:
  
.. code-block :: bash 

  $(command)

or 

.. code-block :: bash 

  `command`

Bash performs the expansion by executing command and replacing the command substitution with the standard output of the command, with any trailing newlines deleted.

Bash Case Modification
----------------------

Taken from `Case Modification <http://wiki.bash-hackers.org/syntax/pe#case_modification>`_

::

 ${PARAMETER^}
 ${PARAMETER^^}
 ${PARAMETER,}
 ${PARAMETER,,}
 ${PARAMETER~}
 ${PARAMETER~~}

These expansion operators modify the case of the letters in the expanded text.

The ^ operator modifies the first character to uppercase, the , operator to lowercase. When using the double-form (^^ and ,,), all characters are converted.

The operators ~ and ~~ reverse the case of the given text (in PARAMETER).~ reverses the case of first letter of words in the variable while ~~ reverses case for all.

Example: Parameter ^
^^^^^^^^^^^^^^^^^^^^

::

 VAR="hack the PLANET"

 echo ${VAR^}
 Hack the PLANET

 echo ${VAR^^}
 HACK THE PLANET

Example: Parameter ,
^^^^^^^^^^^^^^^^^^^^

::

 VAR="HACK THE PLANET"

 echo ${VAR,}
 hACK THE PLANET

 echo ${VAR,,}
 hack the planet

Example: Parameter ~
^^^^^^^^^^^^^^^^^^^^

::

 VAR="hack the PLANET"

 echo ${VAR~}
 Hack The pLANET

 echo ${VAR~~}
 HACK THE planet

Bash Programming
----------------

Bash For Loop
^^^^^^^^^^^^^

.. code-block :: bash 

  for i in $( ls ); do
      echo item: $i
  done

Bash If Statement
^^^^^^^^^^^^^^^^^

.. code-block :: bash 

  if [ "foo" = "foo" ]; then
         echo expression evaluated as true
  else
         echo expression evaluated as false
  fi

Bash loop thru array of strings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block :: bash 

  ## declare an array variable
  declare -a arr=("element1" "element2" "element3")

  ## now loop through the above array
  for i in "${arr[@]}"
     do
         echo "$i"
         # or do whatever with individual element of the array
     done

The value of the variable whose name is in this variable can be found by

.. code-block :: bash 

  echo ${!n}

For example:

.. code-block :: bash 

  eth0="$(ip -o -4 address | grep eth0 | awk '{print $4}')"
  wlan0="$(ip -o -4 address | grep wlan0 | awk '{print $4}')"
  ##eth0 and wlan0 contains the subnet of the eth0 and wlan0.

  for interfaces in "eth0" "wlan0"
   do
     ##var would actually get the value of that variable
     var="${!interfaces}"
   done

Sample Output with ${!interfaces}:

.. code-block :: bash 

  10.233.113.136/23

Sample Output with ${interfaces}:

.. code-block :: bash 

    eth0
    wlan0

Virtualization?
===============

Docker
------

# Stop all containers

::

 docker stop $(docker ps -a -q)

# Delete all containers

::

 docker rm $(docker ps -a -q)

# Delete all images

::

 docker rmi $(docker images -q)

Important Definitions
=====================

Information
-----------

Confidentiality, Integrity, Availability
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We want our information to 

* be read by only the right people (confidentiality).
* only be changed by authorized people or processes (integrity)
* be available to read and use whenever we want (availability).

Non-repudiation
^^^^^^^^^^^^^^^
Non-repudiation is about ensuring that users cannot deny knowledge of sending a message or performing some online activity at some later point in time. For example, in an online banking system the user cannot be allowed to claim that they didn’t send a payment to a recipient after the bank has transferred the funds to the recipient’s account.

Difference between su and sudo
-------------------------------

su
^^

Change users or become superuser. The difference between "su -" and "su" is that former "su -" would switch to the new user directory. It would also change the environment variable according to the changed user. Whereas "su" would only change the user but will stay in the same directory.

Example: "su -" 

::

 root@Kali-Home:~# su - bitvijays
 bitvijays@Kali-Home:~$ pwd
 /home/bitvijays

Example: "su"

::

 root@Kali-Home:~# su bitvijays
 bitvijays@Kali-Home:/root$ pwd
 /root

su -c
^^^^^

Executing command as another user

:: 

  su -c "command" : Specify a command that will be invoked by the shell using its -c.

Example:

::

 su bitvijays -c id
 uid=1000(bitvijays) gid=1001(bitvijays) groups=1001(bitvijays)

sudo
^^^^

Execute a command as another user. The difference between su and sudo is 'su' forces you to share your root password to other users whereas 'sudo' makes it possible to execute system commands without root password. 'sudo' lets you use your own password to execute system commands i.e. delegates system responsibility without root password.

Important File Formats
----------------------

/etc/passwd
^^^^^^^^^^^

The **/etc/passwd** file is a colon-separated file that contains the following information:

* User name
* Encrypted password
* User ID number (UID)
* User's group ID number (GID)
* Full name of the user (GECOS)
* User home directory
* Login shell

::
 
  root:!:0:0::/:/usr/bin/ksh
  daemon:!:1:1::/etc:
  bin:!:2:2::/bin:
  sys:!:3:3::/usr/sys: 
  adm:!:4:4::/var/adm:
  uucp:!:5:5::/usr/lib/uucp: 
  guest:!:100:100::/home/guest:
  nobody:!:4294967294:4294967294::/:
  lpd:!:9:4294967294::/:
  lp:*:11:11::/var/spool/lp:/bin/false 
  invscout:*:200:1::/var/adm/invscout:/usr/bin/ksh
  nuucp:*:6:5:uucp login user:/var/spool/uucppublic:/usr/sbin/uucp/uucico
  paul:!:201:1::/home/paul:/usr/bin/ksh
  jdoe:*:202:1:John Doe:/home/jdoe:/usr/bin/ksh

/etc/shadow
^^^^^^^^^^^

The **/etc/shadow** file contains password and account expiration information for users, and looks like this:

:: 

  smithj:Ep6mckrOLChF.:10063:0:99999:7:xx:

As with the passwd file, each field in the shadow file is also separated with ":" colon characters, and are as follows:

* Username, up to 8 characters. Case-sensitive, usually all lowercase. A direct match to the username in the /etc/passwd file.
* Password, 13 character encrypted. A blank entry (eg. ::) indicates a password is not required to log in (usually a bad idea), and a \* entry (eg. :\*:) indicates the account has been disabled.
* The number of days (since January 1, 1970) since the password was last changed.
* The number of days before password may be changed (0 indicates it may be changed at any time)
* The number of days after which password must be changed (99999 indicates user can keep his or her password unchanged for many, many years)
* The number of days to warn user of an expiring password (7 for a full week)
* The number of days after password expires that account is disabled
* The number of days since January 1, 1970 that an account has been disabled
* A reserved field for possible future use

/etc/group
^^^^^^^^^^

The **/etc/group** file stores group information or defines the user groups. There is one entry per line, and each line has the following format (all fields are separated by a colon (:)

:: 

  cdrom:x:24:john,mike,yummy

Where,

* group_name: Name of group.
* Password: Generally password is not used, hence it is empty/blank. It can store encrypted password. This is useful to implement privileged groups. 
* Group ID (GID): Each user must be assigned a group ID. You can see this number in your /etc/passwd file. 
* Group List: It is a list of user names of users who are members of the group. The user names, must be separated by commas.

Tips and tricks
===============

Apt-get error?
--------------

We often do mistakes while updating using apt-get which just leaves us with command line access to the system (GUI messed up). Possibly we unintentionally removed some necessary packages.

In this case, look for /var/log/apt/history.log, look for the time around which your system was broken. Copy the removed packages which would be in the format of

::

  libapt-inst1.5:amd64 (0.9.7.9+deb7u5, 0.9.7.9+deb7u6), apt-utils:amd64 (0.9.7.9+deb7u5, 0.9.7.9+deb7u6).

To reinstall these packages you just need the package name such as

:: 

  libapt-inst1.5, apt-utils.

  *Step1* : Use sed to search for pattern "), " and replace it with "), \n". This would separate the packages by new line. Within vi ":%s/), /\n/g"
  *Step2* : Use cut -d ":" -f 1 to remove :amd64 and anything after that.
  *Step3* : Now we have to get them back in one line rather than multiple lines. Within vi ":%s/\n/ /g" 
  
Track /etc directory
--------------------
    
Etckeeper may be a bit more advanced, and it is used to put your whole /etc directory under revision control. To install and initialize it,

:: 
  
  apt-get install etckeeper
  etckeeper init
  cd /etc
  git commit -am Initial

After that, you can see pending changes in /etc by cd-ing into it and running

:: 
  
  git status or git diff

at any time, and you can see previous, committed changes by running

::

  git log or git log -p

You can override pending changes to any file with the last committed version with

:: 

  git checkout FILENAME
  
ls showing full path
--------------------

:: 

  ls -R /path | awk '/:$/&&f{s=$0;f=0} /:$/&&!f{sub(/:$/,"");s=$0;f=1;next} NF&&f{ print s"/"$0 }'

Keyboard shortcuts
------------------

Moving
^^^^^^

:: 

  Ctrl + a : Move to the start of line.
  Ctrl + e : Move to the end of line.
  Alt  + b : Move to the start of the current word
  Alft + f : Move to the end of the current word

Erasing
^^^^^^^

::

  Ctrl + w : Cut from cursor to previous whitespace.
  Ctrl + u : Cut from cursor to the start of line.
  Ctrl + k : Cut from cursor to the end of line.
  Ctrl + y : Paste the last cut text.

Window
^^^^^^

::

 WinKey + H              : Minimize/ Hide the Window
 WinKey + Up Arrow Key   : Maximize the current windows
 WinKey + Down Arrow Key : Return to original

Searching History
-----------------

:: 

  Search as you type. Ctrl + r and type the search term;

Read `Command Line Editing <http://www.gnu.org/software/bash/manual/bashref.html#Command-Line-Editing>`_ for more information.

Awk converting to normal output to csv
--------------------------------------

:: 

  A B --> "A","B"
  awk '{print "\"" $1 "\",\"" $2"\""}'

Finding most open ports in nmap scan
------------------------------------

::

  grep "^[0-9]\+" <nmap file .nmap extension> | grep "\ open\ " | sort | uniq -c | sort -rn | awk '{print "\""$1"\",\""$2"\",\""$3"\",\""$4"\",\""$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13"\""}' > test.csv

cat
---

When cat sees the string - as a filename, it treats it as a synonym for stdin. To get around this, we need to alter the string that cat sees in such a way that it still refers to a file called -. The usual way of doing this is to prefix the filename with a path - ./-, or /home/Tim/-. This technique is also used to get around similar issues where command line options clash with filenames, so a file referred to as ./-e does not appear as the -e command line option to a program.

Practice
========

That was most probably a lot of information, to practice all the it’s always better to do some hands on.

Programming, Debugging and Git
------------------------------

Task 1 : Git
^^^^^^^^^^^^
Learn git, would suggest to do a 15 min tutorial on try.github.com.

Task 2 : Vi/ gcc/ make
^^^^^^^^^^^^^^^^^^^^^^

Create a small program using vi with syntax on, compile it using gcc using make.

Task 3 : gdb
^^^^^^^^^^^^
Debug it using gdb -tui option to see the source code, experiment with breakpoints, and printing values.

.. Tip:: Track that program using git, upload them to a remote server, then pull your code, check if its the same.

System administration
---------------------

Task 1 : Login/ Logout Messages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Change the messages before login, after login. Remember the escapes sequences used in the /etc/issue. man agetty lists them.

Task 2 : Gather Information
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Supposed you got access via shell to a linux system and extract some information from it. Create a script.

Task 3 : Add User
^^^^^^^^^^^^^^^^^

* Create a Alice, Bob, eve with the password "password" HINT: set password using chpasswd, look some examples in google to change from cmdline.

* Login from eve

 * Copy and preserve all the configuration files from /etc and save it in eve home directory in the folder etc-backup-YYYYMMDD, direct all errors to cp.err
 * Change the owner of all the files in the folder just created to Bob and the group of all the files to Alice and change the permission of all the files to 440 i.e r--r----- HINT: would have to be logined as root
 * Provide me all the unique shells used by the user present in the system in CAPS. HINT: /etc/passwd file contains all the shells, three four commands would be used.
 * Cover your tracks, clear out the /var/log/auth.log (Have a look at this file and create a backup before clearing), clean your terminal history HINT: man pages would help you.
 * Delete all the user Bob, Alice, eve. Make sure you delete their files too.

 * Turn off the ping responses for your system permanently and turn on the Syn-cookies protection mechanism. {Search on Google}

* Use your previous script to create three users Alice, Bob, eve.

 * create a folder dept inside it two folder hr, web.
 * create two group hr and web.
 * change group of web folder to web and hr to hr.
 * add Alice and Bob user to web group
 * add Alice to hr group.
 * check that Bob is not able to enter in the hr folder and Alice is able to enter in both hr and web folder
 * add user Bob to sudo group and check if it is able to run sudo ifconfig ?

Bash Scripting
--------------

Task 1 : Gather IP Addresses
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Objective to get few IP addresses of Microsoft.com Domains.

* Download the index.html page of microsoft.com
* Every link in html is referred by href. Filter all the href (which would contain the link to different domains for Microsoft)
* Sort and find unique list. Get their ip addresses
* HINT: Tools such as cut, grep, wget, sort, uniq, host and little bit of bash scripting would be used.

Interesting Stuff
=================

* Linux Monitoring Tools : Server density has written most comprehensive list of `80 Linux Monitoring Tools <https://www.serverdensity.com/monitor/linux/how-to/>`_

* Windows Monitoring Tools : Server density has written similar list for Windows too `60+ Windows Monitoring Tools <https://www.serverdensity.com/monitor/windows/how-to/>`_

Changelog
=========
.. git_changelog::
  :filename_filter: docs/LFF-ESS-P0B-LinuxEssentials.rst
  :hide_date: false


.. disqus::
