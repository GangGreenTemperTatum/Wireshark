### Ads Dawson - July 2022

<u># WireShark-Profiles</u>
<p>
Wireshark Profiles - Containing DFilters, CFilters (BPF Syntax), Coloring Rules, Preferences, IOGraphs
When you create a new Profile, Wireshark makes a copy of the Global Configurations to the destination profile and folder
Wireshark Personal Preferences override Global Preferences

##**Example of profile folder contents:**
```
ads@-XXXX WireShark Profiles % cd "Better Default + Packet Diagram" 
ads@-XXXX Better Default + Packet Diagram % ls -halt 
total 536 drwxr-xr-x 94 ads staff 2.9K 16 Jun 09:21 .. 
drwxr-xr-x@ 13 ads staff 416B 16 Jun 09:14 . 
-rw-rw-r--@ 1 ads staff 4.1K 18 May 06:51 recent 
-rw-rw-r--@ 1 ads staff 240B 18 May 06:51 decode_as_entries 
-rw-rw-r--@ 1 ads staff 2.9K 18 May 06:51 dfilter_buttons 
-rw-rw-r--@ 1 ads staff 221K 18 May 06:51 preferences 
-rw-rw-r--@ 1 ads staff 1.1K 10 Jan 14:17 netsci.txt 
-rw-rw-r--@ 1 ads staff 1.9K 15 Nov 2021 cfilters 
-rw-rw-r--@ 1 ads staff 1.6K 11 Mar 2021 colorfilters 
-rw-rw-r--@ 1 ads staff 79B 11 Mar 2021 dfilter_macros 
-rw-rw-r--@ 1 ads staff 934B 11 Mar 2021 dfilters 
-rw-rw-r--@ 1 ads staff 419B 11 Mar 2021 hosts 
-rw-rw-r--@ 1 ads staff 783B 11 Mar 2021 io_graphs
```
</p>
### Wireshark Capture Filters Use BPF (Berkley Packet Filter) Syntax, same as TCPDump
### Wireshark Display Filters use Wireshark custom syntax / Wireshark's specialized display filter format
### A BPF virtual machine lives inside the kernel
## Comparison Operators
<p>
Symbol Expression | Text Expression | Definition
```
* == | eq | 'EQUAL TO'
* || | or | 'OR'
* && | and | 'AND'
* > | gt | 'GREATER THAN'
* < | lt | 'LESS THAN'
* >= | ge | 'GREATER THAN OR EQUAL TO'
* <= | le | 'LESS THAN OR EQUAL TO'
* ! | not | 'NOT'
* != | ne | 'NOT EQUAL TO'
* NA | contains | 'CONTAINS'
* NA | matches | 'MATCHES'
```
</p>
# Matches Comparison Operator
<p>
The Matches Operator (within a Display Filter) is used with Perl regular expressions (REGEX) to search for a string within a field which the functionality is provided through libpcre (Perl Compatible Regular Expressions Library - regexlib.com/cheatsheet.aspx), I.E:
```
http.request.method=="GET" && (http matches "\.(?i) (zip|exe)</i> 
```
.. If we are interested in all HTTP requests for files ending in .zip or .exe
OR
<i>$ http matches "\.(?i) (zip|exe|jar)</i> .. If we want to look at HTTP packets containing .zip, .exe or .jar in either upper or lower case
<i>"\"</i> Looks for a dot
<i>(?i)</i> Indicates the search is case insensitive
<i>(zip|exe|jar)</i> provides or conditions for those strings

# Look for email addresses anywhere in the frame:
```
$ frame matches "(?i)[A-Z0-9._%-]+@[A-Z0-9.-}+\.[A-Z\>] {2,4}"
```
# Look for someone using HTTP to connect to a website ending in a string other than ".com":
```
$ http.host && !http.host matches "\.com$"</i>
```
</p>

<u># Wireshark Best Practices for Packet Heads:</u>
## Remember to setup default packet capture type as PCAP-NG (Next-Generation) Format which are backwards compatible and also store them as trace files which includes packet comments. We recommend saving your trace files in .pcapng format to support packet and trace file annotations
## Remember to setup default Packet Capture Location Folder for ease of saving traces 
## MaxMind Geo-IP DB's are stored in '/Users/ads/.config/wireshark' personal configuration files
## Expert Info Button is in Wireshark's Status Bar 
### Use the Expert Info Summary to view all Packet Comments, or recommended to add as "pk_comments" a column to view Packet comments inline with the entire capture 
### Use the following Display Filter to filter on all TCP Expert notifications as a Display Filter
```
$ tcp.analysis.flags
```
## By default, switches forward all broadcast packets, multicast packets (unless configured to block multicast forward) packets destined to the Wireshark hosts hardware address and packets destined to unknown hardware addresses
## File Sets are used to create contiguous set of trace files during a capture process, instead of navigating through one large trace file
## Packet marking is temporary after reloading the trace file, whereas coloring rules are automatically applied to the traffic each time you open the trace file where coloring is enabled
## Coloring rules are processed in Top->Down fashion/order
## Sync your Wireshark machine with an NTP source
## Beware of sharing Preferences Files within Wireshark profiles which may be specific to the original Wireshark system such as default directory setting for opening new trace files and default capture device setting
## Beware of also exposing internal company IP addresses and recommended to sanitize trace files by using a hex editor and performing a search and replace function for all IP addresses in the trace file
### Bit-Twiste - bittwist.sourceforge.net can be used to automatically change the IP addresses and calculate the new checksum values if you wish to recalculate the checksum values after changing IP's
### Bit-Twist is a simple yet powerful libpcap-based Ethernet packet generator. It is designed to complement tcpdump, which by itself has done a great job at capturing network traffic.
```
$ bittwiste -I ftp-ioupload-partial.pcap -O ftpmod.pcap -T ip -s 67.161.19.78,10.10.19.78 -d 67.161.19.78,10.10.19.78
```
## If you want to save the TCP header as a text file, expand the TCP header in a packet and choose File | Export Packet Dissections | Choose as | Plain Text File

## **RFC3514** Security Flag
```
"evil" bit == 0 - OK
"evil" bit == 1 - Malicious
```
## A Display Filter to search for possible MTU problems: 
<p>
```
$ icmp.type==3 && icmp.code==4
```
</p>
## When Wireshark detects that an IPv6 header follows an IPv4 header, it adds two notes to the packet:
Source 6to4 Gateway IPv4:
```
$ ipv6.src_6to4_gw_ipv4
```
Source 6to4 SLA IA:
```
$ ipv6.src_6to4_sla_id
```

<u># Wireshark Libraries and Traffic Capture Process</u>
https://www.wireshark.org/docs/wsdg_html_chunked/ChapterLibraries.html#:~:text=Like%20most%20applications%2C%20Wireshark%20depends,import%20libraries%2C%20and%20related%20resources.
# Libpcap #
## The libpcap library is the industry standard link-layer interface for capture traffic on *NIX hosts. - www.tcpdump.org
These hosts also support Monitor Mode ##
# WinPCAP #
## WinPCAP is the Windows port of the libpcap link-layer interface. WinPcap consists of a driver that provides low-level network access and the Windows version of the libpcap API. - www.winpcap.org 
WinPap does not support Monitor Mode and therefore does not work with Wireshark or Tsharj in Windows ##
# AirPcap #
## AirPCAP is a link-layer interface and network adapter to capture 802.11 traffic on Windows operating systems. 
AirPcap adapaters operate in passive mode to capture WLAN data, management and control frames. - www.riverbed.com/us/products/cascase/aipcap.php ##

<u>## Wireless Traffic Monitoring</u>
Wireshark cannot identify unmodulated RF energy of interference and requires a spectrum analyzer such as MetaGeek - www.metageek.net/wiresharkbook
## Promiscuous Mode 
<p>
1. Promiscuous Mode enables a network card and driver to capture traffic that is addressed to other devices on the network and not just the local hardware address
2. In Promiscuous Mode only without Monitor Mode, an 802.11 adapter only captures packets of the SSID the adapter has joined
3. Although at the radio level it can receive packets on other SSID's, those packets are not forwarded to the host
</p>
## Monitor Mode .. AKA "rfmon mode"
<p>
<u>In Monitor Mode, an adapter does not associate with any SSID and all packets from all SSID's on the selected channel are captured</u>
1. In order to capture all-SSID traffic that the adapter at the radio level can receive, the adapter must be put into "Monitor Mode"
2. AKA "rfmon mode"
3. In this mode, the driver does not make the adapter a member of any service set
4. In monitor mode, the adapter won't support general network communications. It only supplies received packets to a packet capture mechanism such as Wireshark, not to the network stack.
5. Test to see if your network interfac cards/drivers support Monitor Mode 
</p>
## Monitor Mode vs Promiscuous Mode"
<p>
In Monitor Mode, the driver doesn't make the adapater a member of any service set and the adapter and driver pass ALL packets of ALL SSID's from the currently selected channel up to Wireshark
Promiscuous Mode enables a network card and driver to capture traffic that is addressed to other devices on the network and not just to the local hardware address
</p>

## Promiscuous Mode On / Monitor Mode Off
**Capture Capabilities:** Fake Ethernet header prepended to packet, no MGMT or control packets captured
**Issues to consider?:** Disable Promiscuous Mode
## Promiscuous Mode Off / Monitor Mode Off
**Capture Capabilities:** Fake Ethernet header prepended to packet, no MGMT or control packets captured
**Issues to consider?:** Need to capture traffic on the host you are interested in
## Promiscuous Mode Off / Monitor Mode On
**Capture Capabilities:** 802.11 header;Management and Control packets captured
**Issues to consider?:** Need to capture traffic on the host you are interested in
<u>## Promiscuous Mode On / Monitor Mode On
**Capture Capabilities:** 802.11 header;Management and Control packets captured
**Issues to consider?:** GREAT! Can capture traffic on various channels and from all SSID's</u>

<u># Wireshark Wiretap Library </u>
## The Wireshark Wiretap Library processes opened traced files for visibility and analysis within the UI for a selected amount of file types.

<u># How Wireshark Processes Packets and Wireshark Architecture #</u>
## Wireshark Architecture Flow Diagram ##

```
*---------------------------------------*
*---------------------------------------*
Capture Engine | Wiretap Library
       ↓       |        ↓
*---------------------------------------*
          Core Engine
*---------------------------------------*
Dissectors - Plugins - Display Filters
       ↓                ↓
*---------------------------------------*
    Gimp Graphical Toolkit (GTK+)
*---------------------------------------*
*---------------------------------------*
```

## Core Engine
The Core Engine is the 'glue code that holds the other blocks togather'

# Wireshark Wiretap Library
The Wireshark Wiretap Library processes opened traced files for visibility and analysis within the UI for a selected amount of file types.

## Dissectors - Plugins - Display Filters ##
<p>
Dissectors AKA decodes... Wireshark > Preferences > Protocols
Dissectors, plugins and display filters are applied to traffic at this time
Dissectors decode packets to display field contents and interpreted values
You may edit a dissector such as HTTP when dealing with HTTP traffic on non-default port of TCP80

1. When a packet comes in, Wireshark detects the frame type first and hands the packet off to the correct frame dissector (E.G Ethernet)
2. After breaking down the contents of the frame header, the dissector looks for an indiciation of what is coming next (E.G, an Ethernet header the value of 0x0800 indicates that the IP is coming up next
3. The Wireshark Ethernet Dissector hands off the packet to the IP Dissector
4. The IP Dissector analyzes the IP header and looks to the protocol field in the IP header to identify the next portion of the packet (E.G the value is 0x06 for TCP, then the IP Dissector hands the packet off to the TCP Dissector)
5. This same process occurs until no further indications of another possible dissection
</p>

## Gimp Graphical Toolkit (GTK+) ##
<p>
GIMP GTK+ is the graphical toolkit used to create the GUI for Wireshark and offers cross-platform compatibility
</p>

# How a **TCP Stream** is created in Wireshark?
<p>
```
$ tcp.stream eq X
```
Wireshark creates a filter based on the stream number
</p>
# How a **UDP Stream** is created in Wireshark?
<p>
```
$ ((((ipv6.src == 2001:569:5752:600:9915:c408:a195:d51c) && (ipv6.dst == 2001:568:ff09:10c::67))) && (udp.srcport == 49671)) && (udp.dstport == 53)
```
Wireshark creates a filter based on source/destination IP addresses and source/destination port numbers
</p>
# How an **SSL Stream** is created in Wireshark?
<p>
```
$ tcp.stream eq X
```
Wireshark creates a filter based on the stream number
A stream window may be empty until you successfully apply decryption keys to the SSL stream
</p>

<u># Practical Packet Analysis</u>

## IPv4 (Internet Protocol v4)
<p>
32-bit addressing scheme, represented in decimal notation
Display Filter = "<u>$ ip</u>"
</p>
## IPv6 (Internet Protocol v6)
<p>
128-bit addressing scheme, represented in hexadecimal notation
Display Filter = "<u>$ ipv6</u>"
Capture Filter = "<u>$ ip6</u>"
</p>

## EtherTypes
<p>
EtherType is a two-octet field in an Ethernet frame. It is used to indicate which protocol is encapsulated in the payload of an Ethernet Frame
EtherType numbering generally starts from 0x0800.
EtherType for some notable protocols:

EtherType     Protocol
0x0800 Internet Protocol version 4 (IPv4)
0x0806 Address Resolution Protocol (ARP)
0x0842 Wake-on-LAN
0x8035 Reverse Address Resolution Protocol
0x809B AppleTalk (Ethertalk)
0x8100 VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq
0x86DD Internet Protocol Version 6 (IPv6)
0x8847 MPLS unicast
0x8848 MPLS multicast
0x8863 PPPoE Discovery Stage
0x8864 PPPoE Session Stage
0x8870 Jumbo Frames (proposed)
0x888E EAP over LAN (IEEE 802.1X)
0x88CC Link Layer Discovery Protocol (LLDP)
</p>

## TCP - Transmission Control Protocol
<p>
Connection-orientated protocol
Flow Control
Error Checksum Recovery and Validation
TCP Header Size == 20 bytes
</p>
## UDP - User Datagram Protocol
512 bytes maximum payload
Connectionless protocol
No error validation
UDP Header Size == 8 bytes and variable-length data
<p>
Connection-orientated protocol
Flow Control
Error Checksum Validation
</p>

### ICMP ###
## Example ICMP Types ##
<p>
```
Type 0 == Echo Reply
Type 3 == Destination Unreachable - RFC792
Type 5 == Redirect
Type 8 == Echo
Type 9 == Router Advertisement
Type 10 == Router Solicitation
Type 11 == Time Exceeded
Type 30 == Traceroute
Type 37 == Domain Name Request
Type 38 == Domain Name Reply
```
</p>
## Example ICMP Codes ##
<p>
Many ICMP packet types have several possible Code field values
```
Code 0 == Net Unreachable
Code 1 == Host Unreachable
Code 2 == Protocol Unreachable
Code 3 == Port Unreachable
Code 4 == Fragmentation Needed and DNF (Do Not Fragment) was Set
Code 6 == Desintation Network Unknown
Code 7 == Destination Host Unknown
Code 11 == Destination Network Unreachable for ToS (Type of Service)
Code 12 == Destination Network Unreachable for ToS (Type of Service)
```
</p>

### FTP (TCP21) ACTIVE vs PASSIVE mode
<p>
In *Passive* Mode, the FTP server waits for the FTP client to send it a port and IP address to connect to. The client initiates the connection.
In *Active* mode, the server assigns a port and the IP address will be the same as the FTP client making the request. Within *Active* mode, the FTP PORT command is used.
In other words, Passive mode lets the client dictate the port used, and active mode lets the server set the port.
</p>

### HTTP Response Codes
<p>
Informational responses *(100–199)*
Successful responses *(200–299)*
Redirection messages *(300–399)*
Client error responses *(400–499)*
Server error responses *(500–599)*

```
Status code   Meaning
1xx Informational     
100    Continue
101    Switching protocols
102    Processing
103    Early Hints
        
2xx Succesful  
200    OK
201    Created
202    Accepted
203    Non-Authoritative Information
204    No Content
205    Reset Content
206    Partial Content
207    Multi-Status
208    Already Reported
226    IM Used
        
3xx Redirection       
300    Multiple Choices
301    Moved Permanently
302    Found (Previously "Moved Temporarily")
303    See Other
304    Not Modified
305    Use Proxy
306    Switch Proxy
307    Temporary Redirect
308    Permanent Redirect
        
4xx Client Error      
400    Bad Request
401    Unauthorized
402    Payment Required
403    Forbidden
404    Not Found
405    Method Not Allowed
406    Not Acceptable
407    Proxy Authentication Required
408    Request Timeout
409    Conflict
410    Gone
411    Length Required
412    Precondition Failed
413    Payload Too Large
414    URI Too Long
415    Unsupported Media Type
416    Range Not Satisfiable
417    Expectation Failed
418    I'm a Teapot
421    Misdirected Request
422    Unprocessable Entity
423    Locked
424    Failed Dependency
425    Too Early
426    Upgrade Required
428    Precondition Required
429    Too Many Requests
431    Request Header Fields Too Large
451    Unavailable For Legal Reasons
        
5xx Server Error      
500    Internal Server Error
501    Not Implemented
502    Bad Gateway
503    Service Unavailable
504    Gateway Timeout
505    HTTP Version Not Supported
506    Variant Also Negotiates
507    Insufficient Storage
508    Loop Detected
510    Not Extended
511    Network Authentication Required
```
</p>

<u># Wireshark Best Practices for System Performance</u>
<p>
Disable Name Resolution or add manual DNS host files to refer to, rather than recursive lookups
Beward of firewalls blocking DNS packets via UDP >512bytes in length and use TCP as an alternate
Beware of Proxy-ARP, ARP packets are not forwarded over L3 boundaries as they do not contain an IP header
Use File Sets instead of one large trace file which may be slow performance related
</p>