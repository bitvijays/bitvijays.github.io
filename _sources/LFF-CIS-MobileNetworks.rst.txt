The Essentials
--------------





Network Structure
-----------------

In general, every telecommunications network conceptually consists of three parts, or planes (so called because they can be thought of as being, and often are, separate overlay networks):

The data plane (also user plane, bearer plane, or forwarding plane) carries the network's users' traffic, the actual payload.
The control plane carries control information (also known as signaling).
The management plane carries the operations and administration traffic required for network management. The management plane is sometimes considered a part of the control plane.

A  cellular network or mobile network is a communication network where the last link is wireless. The network is distributed over land areas called cells, each served by at least one fixed-location transceiver, but more normally three cell sites or base transceiver stations. These base stations provide the cell with the network coverage which can be used for transmission of voice, data and others.

Structure of the mobile phone cellular network
-----------------------------------------------
A simple view of the cellular mobile-radio network consists of the following:

A network of radio base stations forming the base station subsystem.
The core circuit switched network for handling voice calls and text
A packet switched network for handling mobile data
The public switched telephone network to connect subscribers to the wider telephony network
This network is the foundation of the GSM system network. There are many functions that are performed by this network in order to make sure customers get the desired service including mobility management, registration, call set-up, and handover.

Any phone connects to the network via an RBS (Radio Base Station) at a corner of the corresponding cell which in turn connects to the Mobile switching center (MSC). The MSC provides a connection to the public switched telephone network (PSTN). The link from a phone to the RBS is called an uplink while the other way is termed downlink.


Terms
-----

BRAS
^^^^

A broadband remote access server (BRAS, B-RAS or BBRAS) routes traffic to and from broadband remote access devices such as digital subscriber line access multiplexers (DSLAM) on an Internet service provider's (ISP) network. BRAS can also be referred to as a Broadband Network Gateway (BNG).

The BRAS is also the interface to authentication, authorization and accounting systems (see RADIUS).

The Diameter base protocol provides authentication, authorization, and accounting (AAA) services in 3G, IMS, and 4G networks for applications such as network access and data mobility. AAA protocols form the basis for service administration within the telecommunications industry, such as deciding which services a user can access, at what quality of service (QoS), and at what cost.

There might be FixedAAA and MobileAAA

Wi-Fi Offload? : Aims to maintain the mobility of end user by seamlessly switching them from 2G/3G/LTE network to WiFi Network.

BNG
^^^

The Broadband Network Gateway (BNG) is a subscriber management system that provides the means by which residential wireline subscribers connect tobroadband services provided either by the wireline broadband network operator (retail services) or through an Internet Service Provider (wholesale services). 

BNG - Enterprise/ FTTX/ WiFi
UGW - 2G/3G/4G

DPI - Deep Packet Inspection

PacketLogic Real-Time Enforcement/ Subscriber Manager/ Intelligence Center

Enhanced Subscriber Management ESM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

BGP/ LDP (Label Distribution Protocol/ T-LDP Targeted Label Distribution Protocol)
D
DNS
^^^

A-DNS - Authoritative DNS
C-DNS - Caching DNS
ADP - Advanced DNS Protection

LI
^^


Lawful interception (LI) refers to the facilities in telecommunications and telephone networks that allow law enforcement agencies with court order or other legal authorization to selectively wiretap individual subscribers.

The governments require all phone service providers to install a Legal Interception Gateway (LIG), along Legal Interception Nodes (LIN), which allow them to intercept in real-time the phone calls, SMS-es, emails and some file transfers or instant messages

IPoE
^^^^

Internet Protocol over Ethernet (IPoE) is a method of delivering an IP payload over an Ethernet-based access network or an access network using bridged Ethernet over Asynchronous Transfer Mode (ATM) without using PPPoE. It directly encapsulates the IP datagrams in Ethernet frames, using the standard RFC 894 encapsulation.

The use of IPoE addresses the disadvantage that PPP is unsuited for multicast delivery to multiple users. Typically, IPoE uses Dynamic Host Configuration Protocol and Extensible Authentication Protocol to provide the same functionality as PPPoE, but in a less robust manner.

PPoE
^^^^

The Point-to-Point Protocol over Ethernet (PPPoE) is a network protocol for encapsulating PPP frames inside Ethernet frames. Most DSL providers use PPPoE, which provides authentication, encryption, and compression.

NSS
---

Network switching subsystem (NSS) (or GSM core network) is the component of a GSM system that carries out call switching and mobility management functions for mobile phones roaming on the network of base stations.

MSC
^^^

The mobile switching center (MSC) is the primary service delivery node for GSM/CDMA, responsible for routing voice calls and SMS as well as other services (such as conference calls, FAX and circuit switched data).

The MSC sets up and releases the end-to-end connection, handles mobility and hand-over requirements during the call and takes care of charging and real time prepaid account monitoring.

There are various different names for MSCs in different contexts which reflects their complex role in the network, all of these terms though could refer to the same MSC, but doing different things at different times.

* The gateway MSC (G-MSC) is the MSC that determines which "visited MSC" (V-MSC) the subscriber who is being called is currently located at. It also interfaces with the PSTN. All mobile to mobile calls and PSTN to mobile calls are routed through a G-MSC. The term is only valid in the context of one call, since any MSC may provide both the gateway function and the visited MSC function. However, some manufacturers design dedicated high capacity MSCs which do not have any base station subsystems (BSS) connected to them. These MSCs will then be the gateway MSC for many of the calls they handle.

* The visited MSC (V-MSC) is the MSC where a customer is currently located. The visitor location register (VLR) associated with this MSC will have the subscriber's data in it.

* The anchor MSC is the MSC from which a handover has been initiated. The target MSC is the MSC toward which a handover should take place.

Home location register (HLR) 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The home location register (HLR) is a central database that contains details of each mobile phone subscriber that is authorized to use the GSM core network. There can be several logical, and physical, HLRs per public land mobile network (PLMN), though one international mobile subscriber identity (IMSI)/MSISDN pair can be associated with only one logical HLR (which can span several physical nodes) at a time.

The HLRs store details of every SIM card issued by the mobile phone operator. Each SIM has a unique identifier called an IMSI which is the primary key to each HLR record.

Another important item of data associated with the SIM are the MSISDNs, which are the telephone numbers used by mobile phones to make and receive calls. The primary MSISDN is the number used for making and receiving voice calls and SMS, but it is possible for a SIM to have other secondary MSISDNs associated with it for fax and data calls. Each MSISDN is also a primary key to the HLR record. The HLR data is stored for as long as a subscriber remains with the mobile phone operator.

Examples of other data stored in the HLR against an IMSI record is:

GSM services that the subscriber has requested or been given.
General Packet Radio Service (GPRS) settings to allow the subscriber to access packet services.
Current location of subscriber (VLR and serving GPRS support node/SGSN).
Call divert settings applicable for each associated MSISDN.

The HLR connects to the following elements:

The G-MSC for handling incoming calls
The VLR for handling requests from mobile phones to attach to the network
The SMSC for handling incoming SMSs
The voice mail system for delivering notifications to the mobile phone that a message is waiting
The AuC for authentication and ciphering and exchange of data (triplets)

Authentication center (AuC)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
The authentication center (AuC) is a function to authenticate each SIM card that attempts to connect to the GSM core network (typically when the phone is powered on). Once the authentication is successful, the HLR is allowed to manage the SIM and services described above. An encryption key is also generated that is subsequently used to encrypt all wireless communications (voice, SMS, etc.) between the mobile phone and the GSM core network.

If the authentication fails, then no services are possible from that particular combination of SIM card and mobile phone operator attempted. There is an additional form of identification check performed on the serial number of the mobile phone described in the EIR section below, but this is not relevant to the AuC processing.

Proper implementation of security in and around the AuC is a key part of an operator's strategy to avoid SIM cloning.



Visitor location register (VLR)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Visitor Location Register (VLR) is a database of the MSs (Mobile Stations) that have roamed into the jurisdiction of the MSC (Mobile Switching Center) which it serves. Each main base station in the network is served by exactly one VLR (one BTS may be served by many MSCs in case of MSC in pool), hence a subscriber cannot be present in more than one VLR at a time.

Data stored include:

IMSI (the subscriber's identity number).
Authentication data.
MSISDN (the subscriber's phone number).
GSM services that the subscriber is allowed to access.
access point (GPRS) subscribed.
The HLR address of the subscriber.
SCP Address(For Prepaid Subscriber).

Equipment identity register (EIR)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The equipment identity register is often integrated to the HLR. The EIR keeps a list of mobile phones (identified by their IMEI) which are to be banned from the network or monitored. This is designed to allow tracking of stolen mobile phones.

Billing center (BC)[edit]
The billing center is responsible for processing the toll tickets generated by the VLRs and HLRs and generating a bill for each subscriber. It is also responsible for generating billing data of roaming subscriber.

Multimedia messaging service center (MMSC)[edit]
The multimedia messaging service center supports the sending of multimedia messages (e.g., images, audio, video and their combinations) to (or from) MMS-enabled Handsets.

Voicemail system (VMS)[edit]
The voicemail system records and stores voicemail. which may have to pay


Subscriber Profile Repository?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
EliteAAA SPR??


Network and Transport
---------------------

P(Core Routers) - Core Routing Node
Distribution/ N-PE - Edge Routing Node
Transit Node - Transit Routing Node
POI Node - Point of Interconnect
Route Reflectors - IPv4 Route Reflector
AGG - Aggregation Switch
ACC - Access Switch 

Carrier Ethernet Architecture
-----------------------------

CPE - 
U-PE - User-facing node in the network where CPE is connected to the Service Provider Network.; Bandwith monitoring may happen by applying traffic classification, policing and queuing
PE-AGG - Optional intermediate layer that sits between U-PE and the N-PE devices. Primary role is to allow the network to scale to larger number of U-PE devices within a particular Ethernet Access Domain  (EAD)
N-PE
P - The core is the device that performs high-speed, low-latency MPLS Switching; typically the SP Core consists of multiple N-PE and P routers connected in full or partial mesh.

Others?
--------

IGW - Internet Gateway
SCE Appliances? - network element designed for carrier grade deployments requiring, high-capactity stateful application and session-based classification and control of applications-level IP traffic per subscriber - Typically inserted into a network by using a bump-in-the-wire approach. Like cutting a network link and inserting a SCE platform. For SCE to inspect/ classify traffic before it goes out to the internet, the traffic has to pass thru SCE devices. This is done using VLAN Mapping

ACE Module?  - Application Control Engine - Next Generation load-balancing and application delivery solution


Solutions
----------

NetBoss NMS

OSIX -- Polystar --
-- Performs detailed root-cause analyis on call, session and protocol levels using unique drill-down capabilities
-- Monitor network performance and Quality of Service
-- Generate real-time alarms on abnormal network behavior
-- Detect poor network performance and prevent customer-affecting services.


LTE
---

Diameter Routing Agent - DRA or Probe DRA?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A Diameter Routing Agent (DRA) is a functional element in a 3G or 4G (such as LTE) network that provides real-time routing capabilities to ensure that messages are routed among the correct elements in a networ


NTR
^^^

Network Traffic Redirection -- Global Operators groups can tremendously benefit from this service by retaining roamers within their group properties globally, thus preventing roaming revenue leakge to their competitos. Roamers also benefit via access to familar romaing services and attractive call costs by bein hon their home operator preferred partner networks

NTR7-TDA - Traffic Decision Assistant
NTR-Shield
NTR-BRG Border Roaming Gateway
T
OM - Outreach Messaging - Roamer relationship and marketing management tool that empoewrs mobile operators to acquire and retain roamers by pro-actively reaching out to inbound and outbound roamers via a suite of personalized multi-modal messgin delivery mechanisms.
Examples
-- Welcome Message in the VPMN
--Messages in subscriber's native language
--LTE,GSM, combined registration notifications
-- Roaming Tariff messages to outbound roamers
-- Heldesk and local voice mail access numbers in the visited network.

Possible Messages

-Inbound Roamers
-- Welcome Message
-- Theme Message
-- Winback Message
-- Good Bye Message

- Outbound Roamers
--Bon-Voyage Message
--Preferred Partner Network Message
--Theme Message
--Tariff Message
-- Welcome Back Message


-- Vendor -- Mobileum

Signaling Point Code?

SMSC - Short Message Service Center is used for sending out welcome SMS for roamers!
SMPP - Short Message Peer to Peer
ESME - External Short Messaging Entities

Similar their is SS7 NTR

iOM - Outreach Messaging - 

SIGTRAN
-------

SS7 Extension?

A Signal Transfer Point (STP) is a router that relays SS7 messages between signaling end-points (SEPs) and other signaling transfer points (STPs). 

SCTP - Stream Control Transmission Protocol


SCA - Smart Call Assistance : Service significantly eases local and internaltional call dialing for roaming Subscribers by automatically correcting dialing mistakes introduced to new and unfamilar dialing codes and patterns int the visited network.
SC - Short Codes - Roaming short codes is a service which allows operators to let their roamers (inbound as well as outbound) to avail of the famillar short codes of their home networks. A short code is a short number between 2-to-6 digits length, that operators provide their subscribers for easy acccess to value-added services asuch as voicemail , emergency numbers, worldwide numbers, customer carer numbers and other services such as taxi, hotel and information


Type of Update Locations
------------------------

GSM Update Location: This message is sent by the VLR to the HLR to update the HLR about the location of the subscriber. This is sent so that subscriber can make and receive voice calls.

GPRS Update Location: This message is sent by the SGSN to the HLR to update the HLR about the location of the subscriber. This is sent so that subscriber can use the data services.


VMCC -- Voicemail Call Completion enables mobile operators to optimally route "Late Call Forwarding" calls to voicemail.


RAN
---

Radio Access Network

A radio access network (RAN) is part of a mobile telecommunication system. It implements a radio access technology. Conceptually, it resides between a device such as a mobile phone, a computer, or any remotely controlled machine and provides connection with its core network (CN).

BTS
^^^
A base transceiver station (BTS) is a piece of equipment that facilitates wireless communication between user equipment (UE) and a network. One of the BTS is Huawei 3900 BTS

BTS may have SMT (Site Maintainence Terminal) which is usually used to commision, maintain and troubleshoot a BTS.

BTS may also have LMT (Local Maintainence Terminal) which is used to assist with the base station deployment and locally locate and fix faults.


RNC
^^^
The Radio Network Controller (or RNC) is a governing element in the UMTS radio access network (UTRAN) and is responsible for controlling the Node Bs that are connected to it. The RNC carries out radio resource management, some of the mobility management functions and is the point where encryption is done before user data is sent to and from the mobile. The RNC connects to the Circuit Switched Core Network through Media Gateway (MGW) and to the SGSN (Serving GPRS Support Node) in the Packet Switched Core Network.

BSC
^^^
The base station controller (BSC) provides, classically, the intelligence behind the BTSs. Typically a BSC has tens or even hundreds of BTSs under its control. The BSC handles allocation of radio channels, receives measurements from the mobile phones, and controls handovers from BTS to BTS.

eGBTS/NodeB/eNodeB is approx GSM/ UMTS/ LTE respectively.

BTS may contact to below servers
* M2000 Server - to conduct tests, execute MML commands, manage tracing tasks and process alarms.
* DHCP Server - 
* FTP Server
* MME, MBSE or serving gateway(S-GW)
* Router
* Clock Server
* PKI Server
* Cascaded Base Station
* OM Tool
* LMT Server 
* NTP Server
* LMT
* Peer traffic


GGSN? SGSN?
AOIP?
IUPS? IUCS? IUR? IUB_UP, IUB_CP, O&M
AOIP?


PGW
---

Payment Gateway

Postilion Realtime

SPS

