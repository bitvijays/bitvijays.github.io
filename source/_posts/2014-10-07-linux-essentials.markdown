---
layout: post
title: "Linux Essentials"
date: 2014-10-07 23:07:48 +0100
comments: true
categories: 
---
This post lists essential commands and concepts which would be helpful to a Linux user.
<ol>
<li>Vi : Powerful Editor:
{% codeblock Vi Commands%}
:q                      - quit.
:wq                     - Save and close.
:syntax on              - Turn on Syntax highlighting for C programming and other languages.
:set number             - Turn on the line numbers.
:set nonumber           - Turn off the line numbers.
:u                      - Undo one change.
dd                      - Delete current line. 
d$                      - Delete the text from where your cursor is to the end of the line.
dnd                     - Delete n lines.
yy                      - yank or copy current line.
y$, yny                 - Similar to delete lines.
p                       - paste the line in the buffer in to text after the current line.
{% endcodeblock %}

Two configurations files which are important:
<ul>
<li>.vimrc - Contains optional runtime configuration settings to initialize Vim when it starts. Example: If you want Vim to have syntax on and line numbers on, whenever you open vi, enter syntax on and set number in this file.</li>
<li>.viminfo - Viminfo file stores command-line, search string, input-line history and other stuff. Useful if you want to find out what user has been doing in vi.</li>
</ul> 
<br>  
PS: Both files are present in user home directory.   
</li>
<br>
<li>Few Different Commands:</li>
<ul>
<li> whatis - Provides a one line description of the commands.</li>
<li> su     - Change users or become superuser: The difference between su - <username> and su <username> is that former su - would switch to the new user directory. It would also change the environment variable according to the changed user.</li>
<li> touch  - Create zero byte files, mainly used for changing the timestamps of the file.</li>
</ul>
</ol>
