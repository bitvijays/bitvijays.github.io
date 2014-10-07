---
layout: post
title: "Linux Essentials"
date: 2014-10-06 19:21:11 +0100
comments: true
categories: 
---

This post lists essential commands and concepts which would be helpful to a Linux user.

1. Vi : Powerful Editor 
<!---
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
