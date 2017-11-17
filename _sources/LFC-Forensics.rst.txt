********************************
CTF Series : Forensics
********************************

This post (Work in Progress) lists the tips and tricks while doing Forensics challenges during various CTF's.

Steganography
=============

Images
------
If you are looking for hidden flag in an image first check with 

* file, exiftool command, and make sure the extension is correctly displayed. 
* strings 
 * Sometimes, it is better to see lines only greater than x length.

  ::

    strings RainingBlood.mp3 | awk 'length($0)>20' | sort -u

* binwalk the file, just to make sure, there's nothing extra stored in that image.
* hexdump -C and look for interesting pattern may be? If you get 7z or PK they represent Zipped files. If so, you can extract those file with 7z x . If somehow, you get a passphrase for the image, then you might have to use steghide tool as it allows to hide data with a passphrase.
* stegsolve - check all the planes. There's a data-extracter, we may try to extract all the values of RGB and see if there's any flag in that.
* stegosuite 
* steghide : If there's any text present in the Image file or the filename of the image or any link ( maybe to youtube video; video name can be the password ) that can be a passphrase to steghide. Sometimes, you may have to try all lowercase/ uppercase combinations.


Sound Files
-----------

* Open the file in Audacity or `Spectrum Analyzer <https://academo.org/demos/spectrum-analyzer/>`_ and probably analyze the Spectogram

 * Arrow next to the track name to switch from waveform (top) to logarithmic spectrogram (bottom).
 * Morse code possible? As all the morse data appears to be below 100 Hz, we can use a low pass filter (effects menu, cutoff 100 Hz) to ease transcription  
 * `Golang mp3 Frame Parser <https://github.com/tcolgate/mp3>`_ 

* If you are provided a jar file in the challenge, JAR (Java ARchive) is a package file format typically used to aggregate many Java class files and associated metadata and resources (text, images, etc.) into one file to distribute application software or libraries on the Java platform. It can be extracted using

 :: 

   jar xf jar-file
   x : extract files from the JAR archive.
   f : JAR file from which files are to be extracted is specified on the command line, rather than through stdin.
   The jar-file argument is the filename (or path and filename) of the JAR file from which to extract files.

* Wireshark - Searching for answers in pcap file?

 * Searching passwords in HTTP Web traffic in wireshark?

  ::

    http.request.method == "POST" filter might help, based on concept that server is asking for LOGIN prompt and user is POSTing his password in cleartext.
 
 * If the challenge says IP address has been spoofed, then you should look for MAC address as it wouldn't have changed. You would find packets with two different IP address having same MAC address. In another scenario, if the MAC address has been spoofed, IP address might be the same. In both cases display filter "arp" (to only show arp requests) and "ip.addr==" (to show only packets with either source or destination being the IP address). might be helpful.

 * Sometimes, it is better to check which objects we are able to export, (File --> Export Objects --> HTTP/DICOM/SMB/SMB2) export the http/DICOM/SMB/SMB2 object
 
 * Sometimes, you need to find all the unique ip address in the network capture, for that you can use 

  .. code-block :: bash

    tshark -T fields -e ip.src -r <pcap file> \| sort \| uniq

    -T fields\|pdml\|ps\|psml\|text : Set the format of the output when viewing decoded packet data. 
    -e : Add a field to the list of fields to display if -T fields is selected. 
    -r : Read packet data from infile, can be any supported capture file format (including gzipped files). 
    -R : Cause the specified filter (which uses the syntax of read/displayfilters, rather than that of capture filters) to be applied

 * Wireshark can not reassamble HTTP fragmented packets to generate the RAW data,we can use Dshell to reassemble http partial contents. A blog mentioning how to do it is `here <https://github.com/naijim/blog/blob/master/writeups/asis-quals-ctf-2015_broken_heart_writeup.md>`_.

* If in a challenge, you are provided a setgid program which is able to read a certain extension files and flag is present in some other extension, create a symbolic link to the flag with the extension which can be read by the program. For example: In picoCTF 2014 Supercow challenge, a program named supercow was able to read files with .cow extension only and flag was present with flag.txt. So we created a symbolic link like ln -s flag.txt flag.cow

* If in a challenge, you are provided with a **APK** file. There are three ways to decompile it as described below:
 
 * Apktool: It is used to decode resources to nearly original form (including resources.arsc, XMLs and 9.png files) and rebuilding them. Also, used for smali debugging. apktool converts the apk file in to smali format. smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation.

  .. code-block :: bash

    apktool d file.apk output-dir 
    d : decode to output-dir

 * Dex2jar: To see the java code (approx)

  * Change the extension of file.apk from .apk to .zip
  * Unzip the file.zip
  * After unzip, you would get classes.dex file.
  * Use dex2jar classes.dex (It would create classes\_dex2jar.jar file)
  * Extract jar file by jar xf classes\_dex2jar.jar
  * This would provide you with .class files which could be open by jd-gui (Java Decompiler) tool.

 * Use online services such as Decompile Android. Once it's decompiled, we can download the decompiled files and unpack them.

* If you are provided a disk.img file, from which files have to recovered, you could use foremost tool used to recover files using their headers, footers, and data structures.

* If you are having a source code of evil program, check the source code of the real program, do a comparision and find the added evil code.

* If you are looking for hidden flag in an image first check with file, exiftool command, and make sure the extension is correctly displayed. After that check the image file with hexdump -C and look for interesting pattern may be? If you get 7z or PK they represent Zipped files. If so, you can extract those file with 7z x . If somehow, you get a passphrase for the image, then you might have to use steghide tool as it allows to hide data with a passphrase.

* Sometimes, if you extract some files, if you wuld see a blank name, you know there is some file but can't see a name, like file name could be spaces?, then

 .. code-block :: bash

   ls -lb might be of help.
   -b, --escape :   print C-style escapes for nongraphic characters

* How to open a filename named "-" : We can create a file named "-" by

 .. code-block :: bash

   echo hello > -

 and this file can be opened by

 .. code-block :: bash

   cat ./-

 This is needed because lot of programs use "-" to mean stdin/stdout.

* If you have a hex dump of something and you want to create the binary version of the data?

 .. code-block :: bash 

   xxd r data
   data is the hexdump of the binary file.

* Excel Document: You may try unzipping it and check VBA macros in it. There are tools to extract VBA from excel listed here ools to extract VBA Macro source code from MS Office Documents 


* Correct Headers: SQLite3

 ::

   0000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
   0000010: 0400 0101 0040 2020 0000 000b 0000 000b  .....@  ........
   0000020: 0000 0000 0000 0000 0000 0002 0000 0004  ................

* GIF to JPG 

 .. code-block :: bash

   convert animation.gif target.png

* If the pdf-parser contains

 .. code-block :: bash

   /ProcSet [/PDF/Text/ImageC/ImageI]
   /ProcSet [/PDF/Text/ImageC/ImageI]

 It means it will contain text which can be extracted by using 

 .. code-block :: bash
	
   *pdf2txt Untitled-1_1a110935ec70b63ad09fec68c89dfacb.pdf  
    PCTF{how_2_pdf_yo}*
