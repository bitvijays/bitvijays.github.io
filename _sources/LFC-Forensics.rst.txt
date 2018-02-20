********************************
CTF Series : Forensics
********************************

This post (Work in Progress) lists the tips and tricks while doing Forensics challenges during various CTF's.

This might be a good reference `Useful tools for CTF <http://g33kinfo.com/info/archives/6261>`_

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
* `zsteg <https://github.com/zed-0xff/zsteg>`_ : detect stegano-hidden data in PNG & BMP
* `pngcheck <http://www.libpng.org/pub/png/apps/pngcheck.html>`_ : pngcheck verifies the integrity of PNG, JNG and MNG files (by checking the internal 32-bit CRCs [checksums] and decompressing the image data); it can optionally dump almost all of the chunk-level information in the image in human-readable form. 
* `Mediaextract <https://github.com/panzi/mediaextract>`_ : Extracts media files (AVI, Ogg, Wave, PNG, ...) that are embedded within other files.
* Comparing two similar images to find the difference

 ::

  compare hint.png stego100.png -compose src diff.png

* `Image Arithmetic <http://homepages.inf.ed.ac.uk/rbf/HIPR2/arthops.htm>`_ We can do image addition, subtraction, multiplication, division, blending, logical AND/NAND, logical OR/NOR, logical XOR/XNOR, Invert/ Logical NOT, Bitshift Operators. 

* We can use `gmic <http://gmic.eu/>`_ to perform XOR of the images.

 ::

   gmic a.png b.png -blend xor -o result.png




QRCodes?
^^^^^^^^

Install `zbarimg <http://manpages.ubuntu.com/manpages/wily/man1/zbarimg.1.html>`_

::

 apt-get install zbar-tools

Usage

Read a QR-Code

::

 zbarimg <imagefile>

Got a QR-Code in Binary 0101?, convert it into QR-Code by `QR Code Generator <https://bahamas10.github.io/binary-to-qrcode/>`_

Sound Files
-----------

* Open the file in Audacity or `Spectrum Analyzer <https://academo.org/demos/spectrum-analyzer/>`_ and probably analyze the Spectogram

 * Arrow next to the track name to switch from waveform (top) to logarithmic spectrogram (bottom).
 * Morse code possible? As all the morse data appears to be below 100 Hz, we can use a low pass filter (effects menu, cutoff 100 Hz) to ease transcription  
 * `Golang mp3 Frame Parser <https://github.com/tcolgate/mp3>`_ 

USB Forensics
=============

Probably, we would be provided with the USB-based PCAP file, now as there are USB-Mouse/ Keyboard and Storage devices. There would be data related to that. Now, to figure what device is connected. Check the below packets in the wireshark

::

 1	0.000000	host	1.12.0	USB	36	GET DESCRIPTOR Request DEVICE
 2	0.000306	1.12.0	host	USB	46	GET DESCRIPTOR Response DEVICE

In the GET DESCRIPTOR Response packet, there would be a idVendor and idProduct, searching for that. We can figure out that whether it's a Keyboard, mouse or storage device.

::

 DEVICE DESCRIPTOR
    bLength: 18
    bDescriptorType: 0x01 (DEVICE)
    bcdUSB: 0x0200
    bDeviceClass: Device (0x00)
    bDeviceSubClass: 0
    bDeviceProtocol: 0 (Use class code info from Interface Descriptors)
    bMaxPacketSize0: 8
    idVendor: Razer USA, Ltd (0x1532)
    idProduct: BlackWidow Ultimate 2013 (0x011a)
    bcdDevice: 0x0200
    iManufacturer: 1
    iProduct: 2
    iSerialNumber: 0
    bNumConfigurations: 1

USB-Keyboard
-------------

If the device connected is the keyboard, we can actually, check for the "interrupt in" message

::

 51	8.808610	1.12.1	host	USB	35	URB_INTERRUPT in

and check for the Leftover Capture Data field

::

 Frame 159: 35 bytes on wire (280 bits), 35 bytes captured (280 bits)
 USB URB
    [Source: 1.12.1]
    [Destination: host]
    USBPcap pseudoheader length: 27
    IRP ID: 0xffffa5045d1653c0
    IRP USBD_STATUS: USBD_STATUS_SUCCESS (0x00000000)
    URB Function: URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (0x0009)
    IRP information: 0x01, Direction: PDO -> FDO
    URB bus id: 1
    Device address: 12
    Endpoint: 0x81, Direction: IN
    URB transfer type: URB_INTERRUPT (0x01)
    Packet Data Length: 8
    [bInterfaceClass: HID (0x03)]
 Leftover Capture Data: 0000500000000000

Now, we can use tshark to take out, usb.capdata out

::

 tshark -r usb-keyboard-data.pcap -T fields -e usb.capdata
 00:00:08:00:00:00:00:00
 00:00:00:00:00:00:00:00
 00:00:0e:00:00:00:00:00
 00:00:00:00:00:00:00:00
 00:00:16:00:00:00:00:00

Here there are 8 bytes

Keyboard Report Format
^^^^^^^^^^^^^^^^^^^^^^

* Byte 0: Keyboard modifier bits (SHIFT, ALT, CTRL etc)
* Byte 1: reserved
* Byte 2-7: Up to six keyboard usage indexes representing the keys that are currently "pressed". Order is not important, a key is either pressed (present in the  buffer) or not pressed.

USB HID Keyboard Scan Codes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

MightyPork has created a gist mentioning USB HID Keyboard scan codes as per USB spec 1.11 at `usb_hid_keys.h <https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2>`_

The above can be referred and utilized to convert the usb.capdata to know what was the user typing using the USB Keyboard!

whoami has written a script to figure out the keyboard strokes

::

 usb_codes = {
    0x04:"aA", 0x05:"bB", 0x06:"cC", 0x07:"dD", 0x08:"eE", 0x09:"fF",
    0x0A:"gG", 0x0B:"hH", 0x0C:"iI", 0x0D:"jJ", 0x0E:"kK", 0x0F:"lL",
    0x10:"mM", 0x11:"nN", 0x12:"oO", 0x13:"pP", 0x14:"qQ", 0x15:"rR",
    0x16:"sS", 0x17:"tT", 0x18:"uU", 0x19:"vV", 0x1A:"wW", 0x1B:"xX",
    0x1C:"yY", 0x1D:"zZ", 0x1E:"1!", 0x1F:"2@", 0x20:"3#", 0x21:"4$",
    0x22:"5%", 0x23:"6^", 0x24:"7&", 0x25:"8*", 0x26:"9(", 0x27:"0)",
    0x2C:"  ", 0x2D:"-_", 0x2E:"=+", 0x2F:"[{", 0x30:"]}",  0x32:"#~",
    0x33:";:", 0x34:"'\"",  0x36:",<",  0x37:".>", 0x4f:">", 0x50:"<"
    }
 lines = ["","","","",""]

 pos = 0
 for x in open("data1.txt","r").readlines():
    code = int(x[6:8],16)

    if code == 0:
        continue
    # newline or down arrow - move down
    if code == 0x51 or code == 0x28:
        pos += 1
        continue
    # up arrow - move up
    if code == 0x52:
        pos -= 1
        continue
    # select the character based on the Shift key
    if int(x[0:2],16) == 2:
        lines[pos] += usb_codes[code][1]
    else:
        lines[pos] += usb_codes[code][0]


 for x in lines:
    print x

USB-Mouse
----------

If we take the USB-Mouse Leftover Capture data, we have around four bytes

Format of First 3 Packet Bytes

Even if your mouse is sending 4 byte packets, the first 3 bytes always have the same format. 
* The first byte has a bunch of bit flags. 

 ::

  byte 1:
  Y overflow	X overflow	Y sign bit	X sign bit	Always 1	Middle Btn	Right Btn	Left Btn

* The second byte is the "delta X" value -- that is, it measures horizontal mouse movement, with left being negative. 

 ::

  byte 2:
  X movement

* The third byte is "delta Y", with down (toward the user) being negative. Typical values for deltaX and deltaY are one or two for slow movement, and perhaps 20 for very fast movement. Maximum possible values are +255 to -256 (they are 9-bit quantities, two's complement).

 ::

  byte 3:
  Y movement

Let's say we capture this data into a file, we can eventually capture the mouse movements,

::

 tshark -r challenge.pcapng usb.capdata and usb.device_address==12 -T fields -e usb.capdata > mouse_data.txt

This can be plotted using GNUplot as shown in a writeup of `Riverside <https://github.com/ctfs/write-ups-2015/tree/master/boston-key-party-2015/school-bus/riverside>`_

::

 awk -F: 'function comp(v){if(v>127)v-=256;return v}{x+=comp(strtonum("0x"$2));y+=comp(strtonum("0x"$3))}$1=="01"{print x,y}' mouse_data.txt > click_coordinates.txt

GNUplot

::

 gnuplot -e "plot 'click_coordinates.txt'"

If the mouse movement shows a on-screen keyboard, probably, we can use 

::

 awk 'BEGIN{split("          zxcvbnm  asdfghjkl qwertyuiop",key,//)}{r=int(($2-20)/-100);c=int(($1 - 117 + (r % 2 * 40)) / 85);k=r*10+c;printf "%s",key[k]}END{print""}' click_coordinates.txt 

USB-Storage-Device
------------------

If the device found in the PCAP is a USB-Storage-Device, check for the packets having size greater than 1000 bytes with flags URB_BULK out/in. Select the stream and press Ctrl + h or you can use File->Export Packet Bytes.

* If you are provided a jar file in the challenge, JAR (Java ARchive) is a package file format typically used to aggregate many Java class files and associated metadata and resources (text, images, etc.) into one file to distribute application software or libraries on the Java platform. It can be extracted using

 :: 

   jar xf jar-file
   x : extract files from the JAR archive.
   f : JAR file from which files are to be extracted is specified on the command line, rather than through stdin.
   The jar-file argument is the filename (or path and filename) of the JAR file from which to extract files.

Esoteric Languages
==================

This would be the best page to refer `Esoteric programming language <https://en.wikipedia.org/wiki/Esoteric_programming_language>`_ 

* Piet : Piet is a language designed by David Morgan-Mar, whose programs are bitmaps that look like abstract art. (Steganography - Challenges)

* `Malbolge <https://en.wikipedia.org/wiki/Malbolge>`_ : Malbolge is a public domain esoteric programming language invented by Ben Olmstead in 1998, named after the eighth circle of hell in Dante's Inferno, the Malebolge.

Volatility
==========

`Command Reference <https://github.com/volatilityfoundation/volatility/wiki/Command-Reference>`_

Important commands to try

* imageinfo/ pslist / cmdscan/ consoles/ consoles/ memdump/ procdump/ filescan/ connscan/

* Extract files using filescan and `dumpfiles <https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#dumpfiles>`_

Extracting RAW pictures from memory dumps
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`Extracting RAW pictures from Memory Dumps <https://w00tsec.blogspot.in/2015/02/extracting-raw-pictures-from-memory.html>`_

Probably, dump the process running MSRDP, MSPAINT

* Rename the file extensions from *.dmp to *.data, download/install GIMP and open them as "RAW Image Data":
* We can use GIMP to navigate within the memory dump and analyse the rendered pixels/bitmaps on their corresponding offsets

Interesting Blog
^^^^^^^^^^^^^^^^

* `APT-Incident-Response <https://github.com/ctfs/write-ups-2015/tree/master/camp-ctf-2015/forensics/APT-incident-response-400>`_
* `Securityfest CTF - Coresec challenge writeup <https://dubell.io/securityfest-ctf-coresec-challenge-writeup/>`_
* `SHX7 - for300 <http://dann.com.br/shx7-for300-go_deeper/>`_
  
* Wireshark - Searching for answers in pcap file?

 * Searching passwords in HTTP Web traffic in wireshark?

  ::

    http.request.method == "POST" filter might help, based on concept that server is asking for LOGIN prompt and user is POSTing his password in cleartext.
 
 * If the challenge says IP address has been spoofed, then you should look for MAC address as it wouldn't have changed. You would find packets with two different IP address having same MAC address. In another scenario, if the MAC address has been spoofed, IP address might be the same. In both cases display filter "arp" (to only show arp requests) and "ip.addr==" (to show only packets with either source or destination being the IP address). might be helpful.

 * Sometimes, it is better to check which objects we are able to export, (File --> Export Objects --> HTTP/DICOM/SMB/SMB2) export the http/DICOM/SMB/SMB2 object

 * SSL Traffic? and have a key? Visit Wireshark->Edit->Preferences->Protocols->SSL->RSA Key List. SSL Traffic with forward secretcy ->SSL->Pre-Master-Secret-Log filename
 
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

* Morse code, utilize `Transator <https://morsecode.scphillips.com/translator.html>`_

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

Others
======

* The Konami Code is a cheat code that appears in many Konami video games, although the code also appears in some non-Konami games. The player could press the following sequence of buttons on the game controller to enable a cheat or other effects:

 ::

  [38, 38, 40, 40, 37, 39, 37, 39, 66, 65, 66, 13] is actually: UP UP DOWN DOWN LEFT RIGHT LEFT RIGHT B A ENTER

* A000045 would bring up the fibonacci numbers.

Python
------

* Read the RGB value of a given pixel in Python?

 ::

  from PIL import Image
  im = Image.open("dead_parrot.jpg") #Can be many different formats.
  pix = im.load()
  print im.size #Get the width and hight of the image for iterating over
  print pix[x,y] #Get the RGBA Value of the a pixel of an image
  pix[x,y] = value # Set the RGBA Value of the image (tuple)
  im.save("alive_parrot.png") # Save the modified pixels as png

* Convert Text to Binary and back?
  
  ::

    >>> import binascii
    >>> bin(int(binascii.hexlify('hello'), 16))
    '0b110100001100101011011000110110001101111'

 In reverse:

 ::

    >>> n = int('0b110100001100101011011000110110001101111', 2)
    >>> binascii.unhexlify('%x' % n)
    'hello'

* function ord() would get the int value of the char. And in case you want to convert back after playing with the number, function chr() does the trick.

 ::

    >>> ord('a')
    97
    >>> chr(97)
    'a'
    >>> chr(ord('a') + 3)
    'd'

* Insert a newline character every 64 characters using Python

 ::

  s = "0123456789"*100 # test string
  import re
  print re.sub("(.{64})", "\\1\n", s, 0, re.DOTALL)

* `Unicode <http://www.utf8-chartable.de/unicode-utf8-table.pl?start=917376&number=1024>`_ 

* In a TCP Dump, you see a telnet session entering login username and password and those creds are not valid. Maybe check the value in HEX. If it contains 0x7F, that's backspace.
