###This is NOT Completed!


Layers in IoT
=============

* Controlling Device
 * Insecure network communication
 * Insecure authentication and authorization
 * Business and Logical Flaws
 * Hardcoded sensitive information
 * Outdated and/ or insecure 3rd party libraries and SDKs

* Cloud Service (IoT Platform)
 * Insecure API communication
 * Improper protection against sensitive resources
 * Ability to modify sensitive data
 * Side channel data leakage
 * Injection based attacks

* Global network and Local network (Gateway Platforms?)
 * Man in the middle attack
 * Replay based attacks
 * Jamming attacks
 * Sensitive data in clear text
 * Insecure encryption and authentication

* Things (Devices)
 * Exposed serial interfaces
 * Ability to dump sensitive information and firmware from the flash chips
 * Insecure integrity and signature verification
 * Insecure OTA update mechanism
 * External media attack vectors


IoT Pentest
===========

Attack Surface Mapping
----------------------

- Understand the architecture of the IoT solution.
- Read documentation of the device, online resources.
- Note down various components used in device, communication protocols, mobile application details, firmware upgrade process, hardware ports, external media support on devices.

IoT Architecture can be divided into three categories

* Embedded Device
* Firmware, Software, and Applications
* Radio Communications

Embedded Devices Vulns
^^^^^^^^^^^^^^^^^^^^^^

* Serial ports exposed
* Insecure authentication mechanism used in serial ports
* Ability to dump the firmware over JTAG or via Flash Chips
* External media based attacks
* Power analysis and Side Channel based attacks

Firmware, Software and Applications
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Firmware

* Ability to modify firmware
* Insecure signature and integrity verification
* Hardcoded sensitive values in firmware - API keys, passwords, staging URLs etc.
* Private certificates
* Ability to understand the entire functionality of the device through the firmware.
* File system extraction from the firmware
* Outdated components with known vulnerabilities

Mobile Application
* Reverse engineering the mobile app
* Dumping source code of the mobile application
* Insecure authentication and authorization checks
* Business and logic flaws
* Side channel data leakage
* Runtime manipulation attacks
* Insecure network communication
* Outdated 3rd party libraries and SDKs

Web Application
* OWASP Top 10.

Radio Communications
^^^^^^^^^^^^^^^^^^^^

Major categories in radio communication

* Software Defined Radio (SDR)
* ZigBee exploitation
* BLE (Bluetooth Low Energy) Exploitation

Vulns

* Man in the middle attack
* Replay based attacks
* Insecure CRC verification
* Jamming based attacks
* Denial of Service
* Lack of Encryption
* Ability to extract sensitive information from radio packets
* Live radio communication interception and modification.

Stuff to keep in mind while creating an Attack Surface Map for radio communication

* What are the roles of various components involved?
* Which component initiates authentication and pairing mechanism?
* How many devices can each component handle simultaneously?
* Which frequency does the device operate on?
* What protocols are being used by different components? Is it custom or preprietary protocol?
* Are there any similar devices operating on around the same frequency range as this devices?

Creating Attack Surface Map 

* Prepare an architecture diagram
* Label components and communication between them.
* Identify attack vectors for each component and the communication channel/ protocol used
* Categorize the attack vectors based on the varying criticality.

Frequency of the device can be found from fccid.io where we can enter FCC ID of an IoT device and find information about it.

FCC stands for Federal Communication Commission, a general body to regulate various devices emitting radio communications.

Analyzing Hardware
------------------

Visual Inspection
^^^^^^^^^^^^^^^^^

* What are how many buttons are present?
* External interfacing options - Ethernet port, SD Card slot, etc.
* What kind of display does the device has?
* Power and voltage requirements for the device.
* Does the device carry any certifications - If Yes, what do they mean?
* Does the device has any FCC ID labels on the back?
* Does the device look like any other devices with similar functionalities (that you have seen in market)(maybe it's just a rebranded model of the same).

www.datasheets360.com or www.alldatasheet.com might provide good datasheets.

Debug Ports and Interfaces? -- we can communicate with the device using UART and JTAG.

Component Package
^^^^^^^^^^^^^^^^^

Packaging Type/ Options. Based on what packaging a component is using, for analysis, we would require corresponding hardware adapters and other components to interact with them.

Most commonly used packaging is below

* DIL
 * Single in-line package
 * Dual in-line package
 * TO-220

* SMD
 * CERPACK
 * BGA
 * SOT-23
 * QFP
 * SOIC
 * SOP

UART Communication
------------------

Universal Asynchronous Receiver/ Transmitter is a way of serial communication allowing two different components on a device to talk to each other without the requirement of a clock.

From a security standpoint, the ability to interact with UART will be useful to read device debug logs, get unauthenticated root shell, bootloader access.

Serial communication is used to transfer one bit at a time through a given medium. Examples RS232, USB, PCI, HDMI, Ethernet, SPI, I2C, CAN.

UART Data Packet
^^^^^^^^^^^^^^^^

UART data packet consists of 

* Starting Bit: Symbolizes that the UART data is going to be followed next. Usually a low pulse (0).
* Message : Actual message that is to be transferred as an 8-bit format.
* Parity bit : is used to perform error and data corruption checking by counting the number of high or low values in the message, and based on whether it's an odd parity or an even parity, it would tell that the data is not correct.
* Stop bit: Final bit which symbolizes that the message has now completed. Usually done by a high pulse (1).

Devices may have configuration of 8N1 - means 8 data bits, no parity bits and 1 stop bit. We may connect a Logic Analyzer to device's UART interfaces.

A logic analyzer is a device which helps display various signals and logic levels from a digital circuit. Saleae Logic Analyzer or Open Workbench Logic Sniffer is a good logic analyzer.

Type of UART Ports
^^^^^^^^^^^^^^^^^^

UART port could either be hardware or software based. Atmel microcontrollers - AT89S52 or ATMEGA328 has one hardware serial port and a user can emulate more software UART ports on specific GPIOs (General Purpose Input Output). Software based UART
may be required to connect multiple devices via UART to a given device.

UART, JTAG, SPI, I2C are mainly present either to provide additional functionality to the developer or facilitate component to component communication. 

Baud Rate
^^^^^^^^^

Baud rate specifies the rate at which data is transferred between devices, or the number of bits per second that are being transferred. As there is no clock line, both the devices need to have mutual understanding of speed of data communication.

Security research first step is to identify the baud rate of the target device. The common baud rates are 9600, 38400, 19200, 57600 and 115200. We can use a script written by Craig Heffner `baudrate.py <https://github.com/devttys0/baudrate/blob/master/baudrate.py`_ 
which allows us to change baud rates while maintaining a serial connection, to identify what is the correct value of the baud rate by looking at the output and visually inspecting for readable output.

Connections for UART Exploitation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To perform UART based exploitation, we need two primary components - target device and a device which could emulate a serial connection to access the end device. 

Identifying UART ports can be done visually by looking for 3 or 4 pins close to each other.

UART consists of four pins 

* Transmit (Tx) : Transmits data from the device to the other end.
* Receive (Rx) : Receives data from the other end to the device
* Ground (GND) : Ground reference pin
* Voltage (Vcc) : Voltage, usually 3.3V or 5V.

We can use multi-meter/ logic analyzer to identify the pins based on either the continuity test (for GND) or by looking at the voltage difference (for the remaining three pins).

* Ground will constant low voltage?
* Vcc would have constant high voltage
* Tx pin would have high/ low voltage during the bootup process because of the initial data transfer.
* Rx might have low voltage during start-up.

Either screen or minicom can be used to connect with the device after finding the baud rate.

::

 screen /dev/ttyUSB0 (COM port used by the connector) (baudrate).

Things to remember

* Connections are correct. e.g. Tx from one device goes to the Rx of other and Rx of other device goes to the Tx.
* GND is connected to other device's Ground.
* Vcc is not connected to anything.
* Baudrate is correctly identified.

Once, we have access to the UART, interaction with bootloader, modification of certain values and dumping of firmware over UART is possible.

Exploitation using I2C and SPI
==============================

Both SPI and I2C are useful bus protocols used for data communication between different components in an Embedded device circuit. We can SPI and I2C exploitation techniques to dump contents (including firmware and other sensitive secrets)
from a device's flash chip, or write content (such as malicious firmware image) to the flash chip.

I2C (Inter-Intergrate Circuit)
------------------------------

I2C is a multi-master protocol with only two wires being required to enable data exchange - Serial Data (SDA) and Serial Clock (SCL). I2C is only half-duplex which means it can only send or receive data at a given point of time.
I2C and SPI are meant for communicating with other peripherals located on the same circuit board. The SDA is for the data exchange, whereas the SCL (Clock line) is controlled by master and determines the speed at which the data exchange takes place.
The master also holds the address and memory location of all the various slaves devices which are used during any communication.

In I2C, there can be multiple masters, interacting with various slaves. That configuration is called a multi-master mode. Imagine what would happen if two masters wanted to take control over I2C bus at the same time, So, whichever master
pulls the SDA to LOW(0) first will gain the control of the bus.


SPI has faster data transmission rates compared to I2C, however it requires 3 pins for data transfer and one pin for Chip/ Slave select. 

Understading EEPROM
^^^^^^^^^^^^^^^^^^^

EEPROM stands for Electrically Erasable Programmable Read Only Memory. Serial EEPROMs typically have 8 pins:

* Pin Name - Function
-  #CS - Chip Select
- SCK - Serial Data Clock
- MISO - Serial Data Input
- MOSI - Serial Data Output
- GND - Ground
- VCC Power Supply
- #WP - Write Protect
- #HOLD Suspends Serial Input

Chip Select : Both SPI and I2C (and other protocols) usually have multiple slaves, it is required to select one slave amongst others for any given action. Chip Select an EEPROM when the #CS is low. When a device is not selected, there will
be no communication happening between the master and the slave and the Serial Data Output pin remains in a high impedence state.

Clock: The clock or SCK determines the speed with which data exchange and communication take place. In case of I2C, the slaves can modify and slow down thte clock in case the clock speed selected by master is too fast for the slaves. Process is known as Clock Streching.

MISO/ MOSI : Master-In-Slave-Out and Master-Out-Slave-In. In case of I2C, (half-duplex), it can either read or write data at a given point of time. In case of SPI, both read and write data happends at the same time.

Write Protect - Pin allows normal read/ write operations when it is HIGH. When #WP is active LOW, all write operations are inhibited.

HOLD: When a device is selected and a serial sequence is underwayone slave amongst others for any given action. Chip Select an EEPROM when the #CS is low. When a device is not selected, there will
be no communication happening between the master and the slave and the Serial Data Output pin remains in a high impedence state.


Exploiting I2C Security
^^^^^^^^^^^^^^^^^^^^^^^

By exploiting I2C, we mean reading or writing data of the devices using an I2C EEPROM. 

Basically, here read the datasheet of the component, of which we want to read the data, check the PINs connections.

To work with I2C, we can use `i2ceeprom.py <https://github.com/devttys0/libmpsse/blob/master/src/examples/i2ceeprom.py`_ by Craig Heffner.

Stuff such as Size of EEPROM chip, speed to be used might needs to be changed, so read and understand the script.

Summarize
---------

* Open the device
* Identify the I2C chip on the PCB
* Note the component number printed on I2C chip
* Look up online for the datasheet to figure out the pinouts
* Make the required connections
* Use the i2ceeprom.py script to read or write data to the I2C EEPROM.

SPI
---

SPI or Serial Peripheral Interface is full-duplex and consists of 3 wires - SCK, MOSI, MISO and additional chip select/ slave select. SPI is pretty loosely defined and different manufactures can modify the implementatiion in their own way, 
To understand communication for any given chip on the target device, the best way is to lookup the datasheet and analyse how our target has implemented the SPI protocol for communication.


How does SPI work?
^^^^^^^^^^^^^^^^^^

* Master first configures the clock frequency according to the slave device clock frequency - typically up to a few MHz.
* Fastest clock speed in SPI is half the speed of the master clock.
* To start communication, the master selects the slave device with a logic level 0 on the SS line. Remember for every clock cycle, a full-duplex data transmission occurs.
* The master initiates the communication by sending a bit on the MOSI line, which is read by the slave, whereas the slave sends a bit on the MISO line which is read by the master.
* The most significatnt bit (MSB) is shifted first while a new least significant bit (LSB) is shifted into the same register. Once the register bit has been shifted out and in, the master and slave have successfully exchanged the register value.

Reading and Writing from SPI EEPROM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To read and write data from/ to an SPI EEPROM, we can use `spiflash.py <https://github.com/devttys0/libmpsse`_

JTAG
====

JTAG is not a standard or protocol but rather a way of testing different chips present on the device and debugging them. JTAG uses a technique known as Boundary Scan which enables the manufactures to test and diagose the assembled PCBs.

Boundary Scan
-------------

Boundary Scan is a technique to debug and test various pins of the different chips present in a circuit. This is done by adding a piece of component call Boundary Scan Cells near each pin of the chip which needs to be tested.
The various I/O pins of the device are connected serially to form a chain. This chain could then be accessed by Test Access Port (TAP).

The Boundary Scan happens by sending data into one of the chips and matching the output to the input to verify if everything is functioning properly. An external file known as Boundary Scan description language file defines the 
capabilities of any single device's Boundary Scan logic.

Test Access Port
----------------

Test Access Point is a collective name given to the JTAG interfaces present on a device. There are five signals which TAP uses which control a state machine

* Test Clock (TCK) - used to synchronize the internal state machine operation and to clock serial data into the various boundary cells.
* Test Data In (TDI) - The Serial Input Data pin to the Scan cells.
* Test Data Out (TDO) - sends the serial output data from the Scan cells.
* Test Mode Select (TMS) - used to control the state of the TAP controller.
* Test Reset (TRST, optional) - the reset pin which is active low. When it is driven low, it will reset the internal state machine.

The TCK, TMS, TRST pins drive a 16-bit TAP controller machine which manages the overall exchange of data and instructions.

The TAP controller is a 16-stage FSM (Finite State Machine) that proceeds from state to state, based on TMS and TCK signal. The TAP controller controls the test data register and the instruction register with the control signals. 
If an instruction is to be sent, then the clock (TCK) is activated and the reset is set to active-low for the clock cycle. Once that is done, the reset signal is then deactivaed and the TMS is toggled to traverse the state machine for 
further operation.

Boundary Scan Instructions
^^^^^^^^^^^^^^^^^^^^^^^^^^

Set of instructions defined by IEEE 149.1 standard which must be made availalbe for a device in case of Boundary Scan

* Bypass : BYPASS instruction places the BYPASS register in the DR chain, so that the path from TDI and TDO involves only a single flip-flop (Shift-Resistor). This allows a specific chip to be tested in a serial chain without any overhead or
  or interference from other chis.

* SAMPLE/ PRELOAD: The SAMPLE/PRELOAD instruction places the Boundary Scan register in the DR chain. This instruction is used to preload the test data into the BSR. It is also used to copy the chip's I/O value into the data register which can
  then be moved out in successive shift-DR states.

* EXTEST: The EXTEST instruction allows the user to test the off-chip circuitry. It is like the sample/ preload but also drives the value from the data register onto output pads.

Test process
^^^^^^^^^^^^

Below is the overall test process would like for a Boundary Scan process:

* The TAP controller applies test data on the TDI pins.
* The BSR (Boundary Scan Register) monitors the input to the device and the data is captured by Boundary Scan cell.
* The Data then goes in the device through the TDI pins.
* The Data comes out of the device through the TDO pins.
* The tester can verify the data on the output pin of the device and confirm if everything is working fine.

These tests can be used to find things ranging from a simple manufacturing defect, to missing components in a board, to unconnected pins or incorrect placement of the device, and even device failures conditions.

Debugging with JTAG
^^^^^^^^^^^^^^^^^^^

As a pentester with access to JTAG, we would be able to 
* dump the contents from the flash chip via JTAG.
* set breakpoints and analyse the entire stack, instruction sets and registers while debugging with JTAG and integrating it with a debugger.

Identifying JTAG pinouts
^^^^^^^^^^^^^^^^^^^^^^^^

We would use additional tools JTAGulator to effectively determine the individual pinouts present in our target device. Another important thins is in most of the devices, we will find the JTAG pads, instead of 
JTAG pins or pads with holes, which makes it important to have a bit of soldering experience.

In JTAG, we have four pins

* TDI 
* TDO
* TMS
* TCK

We can identify JTAG pinouts using two approaches which differ based on hardware used

* Using JTAGulator
* Using Ardunio flashed with JTAGEnum

Using JTAGulator

- Open source hardware which helps us identify JTAG pinouts for a given target device. It has 24 I/O channels which can be used for pinout discovery and can also be used to detect UART pinouts.
- It uses a FT232RL chip which allows it to handle entire USB protocol on a single chip and enables us to plug in the device and have it appear as a virtual serial port with which we can then interact using screen.

To use JTAGulator, we need to connect all the various pins on our target device to the  JTAGulator channels, while connecting the ground to ground. Once done, we simply need to connect the JTAGulator to our system and run 
screen with 

::

 screen /dev/ttyUSB0 115200

* Once, we are in the JTAGulator screen, the next step would be to set the target system voltage by hitting V to select the target voltage.
* After selecting the voltage, the next step is to select a BYPASS scan to find out the pinouts. On selecting this, you wil lbe required to specify how many channels you have selected for the pinouts.
* Once we have selected everything, JTAGulator will detect the various JTAGs pinouts.

Using Ardunio flashed with JTAGEnum

To use JTAGEnum with Ardunio, download the code from `JTAGEnum <https://github.com/cyphunk/JTAGenum`_

This is a cheaper option, however extremely slow and not having the ability to detect the UART pinouts like JTAGulator does.

* Copy the code sample, open the Ardunio IDE and paste the code into the editor window. Select the correct port and Ardunio type from the menus options and Upload the code.
* Interface with Ardunio via serial connection. 

*Incomplete*

What is OpenOCD
^^^^^^^^^^^^^^^

OpenOCD is a utility which allows us to perform On Chip Debugging with our target device via JTAG. Opensource software that interfaces with a hardware debugger's JTAG port. Some of the things we can do 

* Debug the various chips present on the device.
* Set breakpoints and analyse registers and stack at a given time
* Analyse flashes located on the device
* Program and interact with the flashes
* Dump firmware and other sensitive information.

Installing software for JTAG debugging
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* OpenOCD - apt-get install openocd
* GDB-Multiarch - apt-get install gdb-multiarch

Hardware for JTAG Debugging

* Bus Pirate or Segger J-Link? 

Use OpenOCD to connect via Bus Pirate/ Segger J-link or Attify Badge to connect?


--> Writing Data/ Firmware to Device?

::

 flash banks
 flash write_image erase firmware.bin 0x08000000

Dumping data/ firmware from the device

::
 
 flash banks
 dump_image dump.bin starting_point (0x08000000), size(0x0001000)

Reading data from device

:: 

 mdw
 mdw 0x00 0x20

mdw followed by the address and the number of blocks to read.

Debugging over JTAG with GDB
^^^^^^^^^^^^^^^^^^^^^^^^^^^^


Firmware Reverse Engineering and Exploitation
---------------------------------------------

Firmware is a piece of code residing on the Non-Volatile section of the device, allowing and enabling the device to perform different tasks required for functioning of the device. It consists of various 
components such as kernel, bootloader, file system and additional resources. 

File system in Embedded or IoT device firmware can be of different types, depending on the manufacturer's requirements and the device functionality. 

Common file systems include
* Squashfs
* Cramfs
* JFFS2
* YAFFS2
* ext2

Common compression in IoT devices

* LZMA
* Gzip
* Zip
* Zlib
* ARJ

Depending on what file system type and compression type a device is using, the set of tools we will use to extract it will be different.

How to get Firmware Binary
--------------------------

1. Getting it online : Check manufactures website, Support page or downloads section of their website or various community support, discussion forums for the device might include the link for the firmware.
2. Extracting from the device : If we have physical access to the device, we can use various hardware exploitation techniques to dump the firmware from the device flash chip and run additional analysis.
3. Sniffing OTA ?
4. Reversing applications? 

unsquashfs?

binwalk?

Binwalk also allows to do entropy analysis. Entropy analysis - A line with a bit of variation in the middle indicates that data is simply compressed and not encrypted, whereas completely flat line indicates that the data is encrypted.

::

 binwalk E image.bin

Firmware Internals
-------------------

Firmware may contain

1. Bootloader : Responsible for initializing of various critical hardware components and allocating the required resources.
2. Kernel : intermediary layer between hardware and the software.
3. File System : is where all the individual files are stored necessary for the embedded device runtime. Includes components such as web-servers and network services.

Typical Embedded device boot ups

1. Bootloader initiates required hardware and system components for bootup.
2. Bootloader is passed in the physical address of the kernel as well as the loading up of the device tree.
3. Kernel is loaded from the above address which then initiates all the required processes and aditional services for the embedded device to operate.
4. Bootloader dies as kernel gets loaded.
5. Root file system is mounted
6. As root file system is mounted, a Linux Kernel spawns a program called init.

Hardcoded Secrets
^^^^^^^^^^^^^^^^^

1. Hardcoded credentials
2 .Backdoor access
3. Sensitive URLs
4. Access tokens
5. API and Encryption keys
6. Encryption algorithms
7. Local pathnames
8. Environment details
9. Authentication and Authorization mechanisms.

Encrypted Firmware?
-------------------

Firmware might be encrypted with XOR encryption or even AES encryption?

XOR Encryption - Simply perform a hexdump and see if there are any recurring strings, which is a good indication of usage of XOR encryption. Recurring pattern may be the key. Use decryptxor.py and decrypt the encrypted firmware.

Emulating a Firmware Binary
^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are different platforms such as ARM, MIPS, PowerPC etc.

We can utilize Qemu to emulate the binaries on specific platforms.

To emulate entire firmware, we have to solve specific challenges,

* The firmware is meant to run on another architecture.
* The firmware during bootup might require configurations and additional information from NVRAM.
* The firmware might be dependent on physical hardware components to run.

To solve the second NVRAM challenge, we can setup a interceptor which listens to all the calls being made by firmware to NVRAM and return our custom values.

We can use Firmware Analysis Toolkit (FAT) which is a script build on top of Firmadyne - a tool for emulating firmware.

Backdooring a Firmware
^^^^^^^^^^^^^^^^^^^^^^

Backdooring a firmware is one of the security issues which a firmware faces if the device has no secure integrity checks and signature validation. We can extract the filesystem from a firmware and then modify the firmware
by adding our own backdoor. The modified firmware can be flashed to the real IoT device, which would then give us backdoored access to the device.

Instead of binwalk, we would use `Firmware Mod Kit <https://github.com/brianpow/firmware-mod-kit.git>`_ 

We have two tasks
* Creating a backdoor and compiling it to run on specific platform (MIPS etc.)
* Modifying entries and placing the backdoor in a location so that it could be started automatically at bootup.

We can use backdoor by OsandaMalith.

We can use BuildRoot to compile programs for a different target architecture that what we are on.

Running Automated firmware scanning tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We can use firmwalker by Craig Smith . Inside the data folder, it contains the entries which firmwalker looks for.

Firmware Diffing
^^^^^^^^^^^^^^^^

Diffing can help to understand the various security issues which might have existed in the previous version of the firmware, even if they are not publicily informed.

Kdiff3 or meld and other tools can be used.

Software Defined Radio
----------------------

Software defined radio allows to implement radio processing functionalities which otherwise would need hardware implementatiion to be performed with the use of sofware.

Setting up the lab
^^^^^^^^^^^^^^^^^^

* GNURadio
* GQRX
* Rtl-sdr utilities
* HackRF tools

We would need hardware too, cheapest RTL-SDR or HackRF,

Limitation of RTL-SDR is it will only allow you to sniff and look at various frequencies and not actually transmit your own data.

::

 apt-get install gqrx, gnuradio, rtl-sdr, hackrf


- Data which needs to be transmitted from the Wi-Fi router is being modulated with the carrier signal of 2.4 GHz. This data is passed through the air (transmitting medium) which is being recieved on the other end. Once it is recived,
  it is decoded and the final data is obtained from the signal. The modulation process is essential for noise reduction, multiplexing, working with various bandwidth and frequencies, cable properties. etc.

In modulation, the baseband signal, considered as main information source is carried by higher frequency wave called the carrier signal. Based on the properties of the carrier signal and the type of modulation being used,
 the properties of the final signal, which travels throught the air changes.

Modulation can be 

*  Analog Modulation : Amplitude, Frequency, SSB and DSB Modulation
* Digital Modulation : FSK, PSK and QAM.

Can also be divided based on component being modulated

* Amplitude Modulation
* Frequency Modulation
* Phase Modulation

Common Terminologies

* Transmitter
* ADC
* Sample Rate
* FFT
* Bandwidth
* Wavelength
* Frequency
* Antenna
* Gain
* Filters ( Low Pass, High Pass, Band Pass )


Working with GNURadio

* Signal Source (Found under Waveform Generator )
* Sink?
* WX GUI FFT Sikn

We can use GQRX to identify and confirm the frequency spectrum of the devices.

Once launched, click devices RTL-SDR

Once, we have confirmed the frequency, we can use utility provided with RTL_SDR ; rtl_433 to analyse the data.

::

 rtl_433 -f 43392000 (Exact frequency)

Now, we can use HackRF to transmit the same packets?

RC-Switch? Ardunio? We can recieve the data sent by ardunio, change that and resend that?

Using GNURadio to decode data?

RTL-SDR Source? Complex to Mag^2 ; Wave file Sink? 

If might happen that data is sent by shorter pulses (representing 0) and longer pulses (representing 1)? On-Off Keying (OOK) form of Amplitude-Shift-Keying?

HackRF
^^^^^^

::

 hackrf_info
 hackrf_transfer? - to store the packets captures in a file, later used to replay? -s sample rate, -r specify read file, -f frequency to work with.

ZigBee
------

Wireless communication networking standard used for low-power devices.
ZigBee allows devices to communicate using mesh network topology, which enables it to be used both for small and large networks. ZigBee is based on 802.15.4 MAC and PHY layer and have 
basic message handling, congestion control 

Understading ZigBee Communication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ZigBee network may have various kind of devices

* Coordinator : single device in the network responsible for number of actions such as selecting the correct channel, creating a network, forming security settings, handling authentication or even acting as router.
* Router : which provides routing services to the various network devices
* End devices : perform operations such as reading the temperature or performing actions such as turning on the lights.

Total number of channels in Zigbee is 16, we first need to figure out which channel device is operating?

Hardware for Zigbee

- Assuming, we have a setup running Zigbee

Hardware for exploitation?

KillerBee? tool supports hardware devices such as Atmel RzRaven USB Stick, API Mote, MoteIV Tmote Sky, TelosB mote and Sewino Sniffer. 

killerBee/Tools

zbid?
* zbstumbler
* zbdump?
* zbwireshark?

BLE
---

GATT
ATT
GAP

BLE provides four different ways to handle pair?

* JustWorks
* Numeric Comparison
* Passkey
* Out of Band

Hardware
^^^^^^^^

Gatttool?
hciconfig?

hcitool lescan?

gatttool -I -b target_device?

We can do primary services discovery and list all the various characteristics of the target device

::

 primary

and read the characteristics with 

::

 char-read-hnd 0x000c (char hex value)


`GATT Services <https://www.bluetooth.com/specifications/gatt/services>`_


char-desc we can get a list of all the handles optionally also specifiying the attr and end group handles.

::

 char-desc 0x0021 0x0032

::

 char-write-req 0x003a 01

Sniffing BLE Packets
^^^^^^^^^^^^^^^^^^^^^

Ubertooth One and Adafruit BLE Sniffer

::

 ubertooth-btle? 

SCAN_REQ

SCAN_RES

-c 

BTLEJuice?
