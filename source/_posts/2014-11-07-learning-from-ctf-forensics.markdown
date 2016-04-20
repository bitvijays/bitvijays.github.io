---
layout: post
title: "Learning from CTF : Forensics"
date: 2014-11-07 22:07:09 +0000
comments: true
categories: 
---
This post (Work in Progress) lists the tips and tricks while doing Forensics challenges during various CTF's.
<!-- more -->
<ol>
<li>If you are provided a <strong>jar</strong> file in the challenge, JAR (Java ARchive) is a package file format typically used to aggregate many Java class files and associated metadata and resources (text, images, etc.) into one file to distribute application software or libraries on the Java platform. It can be extracted using 

```
jar xf jar-file

x : extract files from the JAR archive.
f : JAR file from which files are to be extracted is specified on the command line, rather than through stdin.
The jar-file argument is the filename (or path and filename) of the JAR file from which to extract files.
```
</li>

<li>Wireshark - Searching for answers in pcap file? 
<ul>
<li>Searching passwords in HTTP Web traffic in wireshark? http.request.method == "POST" filter might help, based on concept that server is asking for LOGIN prompt and user is POSTing his password in cleartext.</li>
<li>If the challenge says IP address has been spoofed, then you should look for MAC address as it wouldn't have changed. You would find packets with two different IP address having same MAC address. In another scenario, if the MAC address has been spoofed, IP address might be the same. In both cases display filter "arp" (to only show arp requests) and "ip.addr==<IP address>" (to show only packets with either source or destination being the IP address). might be helpful.</li>
<li>Sometimes, it is better to check which objects we are able to export, (File --> Export Objects --> HTTP/DICOM/SMB/SMB2) export the http/DICOM/SMB/SMB2 object </li>
<li>Sometimes, you need to find all the unique ip address in the network capture, for that you can use 
```
tshark -T fields -e ip.src -r < pcap file> | sort | uniq

-T fields|pdml|ps|psml|text : Set the format of the output when viewing decoded packet data.
-e <field>     		    : Add a field to the list of fields to display if -T fields is selected.
-r <pcap file> 		    : Read packet data from infile, can be any supported capture file format (including gzipped files).
-R <Read filter>            : Cause the specified filter (which uses the syntax of read/display filters, rather than that of capture filters) to be applied
```</li>
<li>wireshark can not reassamble HTTP fragmented packets to generate the RAW data,we can use Dshell to reassemble http partial contents. A blog mentioning how to do it is <a href="https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md">here</a></li>
</ul>
</li>
<br>
<li>If in a challenge, you are provided a setgid program which is able to read a certain extension files and flag is present in some other extension, create a symbolic link to the flag with the extension which can be read by the program. For example: In picoCTF 2014 Supercow challenge, a program named supercow was able to read files with .cow extension only and flag was present with flag.txt. So we created a symbolic link like ln -s flag.txt flag.cow</li>
<br>
<li>If in a challenge, you are provided with a <b>APK</b> file. There are three ways to decompile it as described below:
<ul>
<li>Apktool:
It is used to decode resources to nearly original form (including resources.arsc, XMLs and 9.png files) and rebuilding them. Also, used for smali debugging.
```
apktool d file.apk output-dir
d : decode to output-dir
```
apktool converts the apk file in to smali format. smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation.
</li>
<li>Dex2jar: To see the java code (approx)
```
1. Change the extension of file.apk from .apk to .zip
2. Unzip the file.zip 
3. After unzip, you would get classes.dex file.
4. Use dex2jar classes.dex (It would create classes_dex2jar.jar file)
5. Extract jar file by jar xf classes_dex2jar.jar
6. This would provide you with .class files which could be open by jd-gui (Java Decompiler) tool. 
```
</li>

<li>Use online services such as <a href="http://www.decompileandroid.com/">Decompile Android</a>. Once it's decompiled, we can download the decompiled files and unpack them. </li>

</ul>
</li>
<br>
<li>If you are provided a <b>disk.img</b> file, from which files have to recovered, you could use foremost tool used to recover files using their headers, footers, and data structures.</li>
<br>
<li>If you are having a source code of evil program, check the source code of the real program, do a comparision and find the added evil code.</li>
<br>
<li>If you are looking for <b>hidden flag in an image</b> first check with file, exiftool command, and make sure the extension is correctly displayed. After that check the image file with hexdump -C and look for interesting pattern may be? If you get 7z or PK they represent Zipped files. If so, you can extract those file with 7z x <image_file>. If somehow, you get a passphrase for the image, then you might have to use steghide tool as it allows to hide data with a passphrase.</li>
<br>
<li>Sometimes, if you extract some files, if you wuld see a blank name, you know there is some file but can't see a name, like file name could be spaces?, then 
```
ls -lb might be of help.
-b, --escape :   print C-style escapes for nongraphic characters

``` 

How to open a filename named "-"

We can create a file named "-" by 
```
echo hello > -
```
and this file can be opened by
```
cat ./-
```
This is needed because lot of programs use "-" to mean stdin/stdout.
</li>

<li>If you have a hex dump of something and you want to create the binary version of the data?
```
xxd -r <data>
<data> is the hexdump of the binary file.
``` </li>

<li>Excel Document: You may try unzipping it and check VBA macros in it. There are tools to extract VBA from excel listed here <a href="http://www.decalage.info/vba_tools">ools to extract VBA Macro source code from MS Office Documents
</a> </li>
<li> Correct Headers:
SQLite3
```
0000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
0000010: 0400 0101 0040 2020 0000 000b 0000 000b  .....@  ........
0000020: 0000 0000 0000 0000 0000 0002 0000 0004  ................
```

</li>

<li>GIF to JPG
```
convert animation.gif target.png
```</li>
<li>If the pdf-parser contains
```
        /ProcSet [/PDF/Text/ImageC/ImageI]
        /ProcSet [/PDF/Text/ImageC/ImageI]
```
It means it will contain text which can be extracted by using
```
pdf2txt Untitled-1_1a110935ec70b63ad09fec68c89dfacb.pdf 
PCTF{how_2_pdf_yo}
```</li>
</ol>


