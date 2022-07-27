### Ads Dawson _Scratchpad July 2022_ & [WCNA](https://www.wcnacertification.com/) Study Notes
Kudos to [Dillinger](https://dillinger.io/) for the Markdown tips!
* Whilst MAC OS ships with 'tcpdump' application, it does not package or default install tshark.
* If you install tshark by downloading and extracting the .dmg, it does not include tshark.
* To resolve this, use brew installer: 

```
~ % brew install wireshark
~ % brew install --cask wireshark
```
> Note, after doing so you will need to install chmodBPF to allow capturing on local interfaces
* Of course, MAC OS driver used to capture packets is libpcap.

### `WireShark-Profiles`

* `Wireshark Profiles` - Containing DFilters, CFilters (BPF Syntax), Coloring Rules, Preferences (including font size and style, layout, Protocol preferences E.G {{TCP Relative SEQ Numbers}}), IOGraphs
* When you create a new Profile, Wireshark makes a copy of the Global Configurations to the destination profile and folder
* Wireshark Personal Preferences override Global Preferences
* `Display Filter Macros` are saved in `{dfilters_macros}` in your Personal Configuration Folder and if created under a profile other than the default, the `{dfilters_macros}` is saved in the Profile's directory. 
* Wireshark does not contain Capture Filter macros and is only for Display Filters
* Display Filters (default file = `dfilters`) can be created based on the contents of fields that do not actually exist in the packet such as "Time Since Referenced" or "First Packet Field", which is not the same for cfilters
* dfilters (Display Filters, using Wireshark custom syntax) can be applied during the capture process

* The syntax used for this file is:

```
"name","filter_string"
```

## Example of profile folder contents:

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

### Wireshark Capture Filter Use BPF (Berkley Packet Filter) Syntax, same as TCPDump and are written in [libpcap filter language](https://www.tcpdump.org/manpages/)
* Use Capture Filters sparingly, as using them will remove packets from your entire PCAP, but Capture filters significantly reduce the captured file size and thus can be used to spare resources + the use of disk capacity from big trace files.
* Capture filters use Berkley Packet Filtering (BPF) format and Wireshark includes a default set of capture filters.
* Capture filters default capture filter filename is `cfilters`

* `ctrl+E` (key commands) = keyboard shortcut to start/stop capturing in Wireshark
* Wireshark can capture only the packets that the packet capture library - libpcap on UNIX-flavored OSes, and the Npcap port to Windows of libpcap on Windows - can capture, and libpcap/Npcap can capture only the packets that the OS’s raw packet capture mechanism (or the Npcap driver, and the underlying OS networking code and network interface drivers, on Windows) will allow it to capture.
* Unless the OS always supplies packets with errors such as invalid CRCs to the raw packet capture mechanism, or can be configured to do so, invalid CRCs to the raw packet capture mechanism, Wireshark - and other programs that capture raw packets, such as tcpdump - cannot capture those packets
* Within Wireshark, to export as CSV.. **File > Export Packet Dissections > a "CSV"**. WireShark can import CSV (comma separated value) format files * for further analysis.
* Automatic packet capture to one or more files feature is available in Wireshark
* Capturing packets within Wireshark is recommended between two routers.
* A purpose of installing a TAP in the network is to **provide a copy of the network traffic without compromising network integrity**
* Wireshark can also decode Netflow packets
* Database record transfers including Microsoft Sharepoint can be a nightmare for packet capture analysis and displays a single connection for each record but with multiple small packet sizes

* Tshark uses Berkeley Packet Filter syntax "**-f**" “<filter>”, which is also used by tcpdump. - I.E the Capture Filter syntax with "**-f**" parameters.. Using display filters with Tshark during a live capture does not limit the packets you are capturing, but the packets visible once applying the filter. Using these display filters with Tshark on previously saved captures allows you to create a subset of the original trace file.
* Tshark can be used with display filters using the "**-R**" parameter ... Other useful parameters are "**-r**" for read a PCAP and **-w** parameters for write to a PCAP file.. "**-h**" to list the Tshark parameters and "**-t**" to specify time format

```
ads@<hostname> ~ % tshark -n -w Downloads/sid.pcap -Y 'string(ip.src) contains "^192\\.168\\.(1)\\.[0-255]"'
tshark: Display filters aren't supported when capturing and saving the captured packets.
```

* "**-Y**" Parameter is used as the old "**-R**" Parameter for Tshark Display filters is deprecated
* This is known as [Bug 2234](https://wiki.wireshark.org/ReportingBugs) where Display Filters do not work if you are:
1) Running a live capture
2) Saving packets to a file
* A workaround is to capture without a display filter, run Tshark against that new file with the Display Filter set and then write to a new file
* There are three primary operators available for Capture Filters:

> Negation (not or !) - When using this operator, each packet must match only one side of the operator to pass through the filter
> Concatentation (and or &)
> Alternation (or or |)

* Here is an example of the [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) Help Syntax:


```
adamdawson@SL-1788 ~ % tshark -h
TShark (Wireshark) 3.6.6 (Git commit 7d96674e2a30)
Dump and analyze network traffic.
See https://www.wireshark.org for more information.

Usage: tshark [options] ...

Capture interface:
  -i <interface>, --interface <interface>
                           name or idx of interface (def: first non-loopback)
  -f <capture filter>      packet filter in libpcap filter syntax
  -s <snaplen>, --snapshot-length <snaplen>
                           packet snapshot length (def: appropriate maximum)
  -p, --no-promiscuous-mode
                           don't capture in promiscuous mode
  -I, --monitor-mode       capture in monitor mode, if available
  -B <buffer size>, --buffer-size <buffer size>
                           size of kernel buffer (def: 2MB)
  -y <link type>, --linktype <link type>
                           link layer type (def: first appropriate)
  --time-stamp-type <type> timestamp method for interface
  -D, --list-interfaces    print list of interfaces and exit
  -L, --list-data-link-types
                           print list of link-layer types of iface and exit
  --list-time-stamp-types  print list of timestamp types for iface and exit

Capture stop conditions:
  -c <packet count>        stop after n packets (def: infinite)
  -a <autostop cond.> ..., --autostop <autostop cond.> ...
                           duration:NUM - stop after NUM seconds
                           filesize:NUM - stop this file after NUM KB
                              files:NUM - stop after NUM files
                            packets:NUM - stop after NUM packets
Capture output:
  -b <ringbuffer opt.> ..., --ring-buffer <ringbuffer opt.>
                           duration:NUM - switch to next file after NUM secs
                           filesize:NUM - switch to next file after NUM KB
                              files:NUM - ringbuffer: replace after NUM files
                            packets:NUM - switch to next file after NUM packets
                           interval:NUM - switch to next file when the time is
                                          an exact multiple of NUM secs
Input file:
  -r <infile>, --read-file <infile>
                           set the filename to read from (or '-' for stdin)

Processing:
  -2                       perform a two-pass analysis
  -M <packet count>        perform session auto reset
  -R <read filter>, --read**-f**ilter <read filter>
                           packet Read filter in Wireshark display filter syntax
                           (requires -2)
  -Y <display filter>, --display filter <display filter>
                           packet displaY filter in Wireshark display filter
                           syntax
  -n                       disable all name resolutions (def: "mNd" enabled, or
                           as set in preferences)
  -N <name resolve flags>  enable specific name resolution(s): "mnNtdv"
  -d <layer_type>==<selector>,<decode_as_protocol> ...
                           "Decode As", see the man page for details
                           Example: tcp.port==8888,http
  -H <hosts file>          read a list of entries from a hosts file, which will
                           then be written to a capture file. (Implies -W n)
  --enable-protocol <proto_name>
                           enable dissection of proto_name
  --disable-protocol <proto_name>
                           disable dissection of proto_name
  --enable-heuristic <short_name>
                           enable dissection of heuristic protocol
  --disable-heuristic <short_name>
                           disable dissection of heuristic protocol
Output:
  -w <outfile|->           write packets to a pcapng**-f**ormat file named "outfile"
                           (or '-' for stdout)
  --capture-comment <comment>
                           add a capture file comment, if supported
  -C <config profile>      start with specified configuration profile
  "**-f**" <output file type>    set the output file type, default is pcapng
                           an empty "-f" option will list the file types
  -V                       add output of packet tree        (Packet Details)
  -O <protocols>           Only show packet details of these protocols, comma
                           separated
  -P, --print              print packet summary even when writing to a file
  -S <separator>           the line separator to print between packets
  -x                       add output of hex and ASCII dump (Packet Bytes)
  -T pdml|ps|psml|json|jsonraw|ek|tabs|text|fields|?
                           format of text output (def: text)
  -j <protocolfilter>      protocols layers filter if -T ek|pdml|json selected
                           (e.g. "ip ip.flags text", filter does not expand child
                           nodes, unless child is specified also in the filter)
  -J <protocolfilter>      top level protocol filter if -T ek|pdml|json selected
                           (e.g. "http tcp", filter which expands all child nodes)
  -e <field>               field to print if -Tfields selected (e.g. tcp.port,
                           _ws.col.Info)
                           this option can be repeated to print multiple fields
  -E<fieldsoption>=<value> set options for output when -Tfields selected:
     bom=y|n               print a UTF-8 BOM
     header=y|n            switch headers on and off
     separator=/t|/s|<char> select tab, space, printable character as separator
     occurrence=f|l|a      print first, last or all occurrences of each field
     aggregator=,|/s|<char> select comma, space, printable character as
                           aggregator
     quote=d|s|n           select double, single, no quotes for values
  -t a|ad|adoy|d|dd|e|r|u|ud|udoy
                           output format of time stamps (def: r: rel. to first)
  -u s|hms                 output format of seconds (def: s: seconds)
  -l                       flush standard output after each packet
  -q                       be more quiet on stdout (e.g. when using statistics)
  -Q                       only log true errors to stderr (quieter than -q)
  -g                       enable group read access on the output file(s)
  -W n                     Save extra information in the file, if supported.
                           n = write network address resolution information
  -X <key>:<value>         eXtension options, see the man page for details
  -U tap_name              PDUs export mode, see the man page for details
  -z <statistics>          various statistics, see the man page for details
  --export-objects <protocol>,<destdir>
                           save exported objects for a protocol to a directory
                           named "destdir"
  --export-tls-session-keys <keyfile>
                           export TLS Session Keys to a file named "keyfile"
  --color                  color output text similarly to the Wireshark GUI,
                           requires a terminal with 24-bit color support
                           Also supplies color attributes to pdml and psml formats
                           (Note that attributes are nonstandard)
  --no-duplicate-keys      If -T json is specified, merge duplicate keys in an object
                           into a single key with as value a json array containing all
                           values
  --elastic-mapping**-f**ilter <protocols> If -G elastic-mapping is specified, put only the
                           specified protocols within the mapping file
Diagnostic output:
  --log-level <level>      sets the active log level ("critical", "warning", etc.)
  --log**-f**atal <level>      sets level to abort the program ("critical" or "warning")
  --log-domains <[!]list>  comma separated list of the active log domains
  --log-debug <[!]list>    comma separated list of domains with "debug" level
  --log-noisy <[!]list>    comma separated list of domains with "noisy" level
  --log**-f**ile <path>        file to output messages to (in addition to stderr)

Miscellaneous:
  -h, --help               display this help and exit
  -v, --version            display version info and exit
  -o <name>:<value> ...    override preference setting
  -K <keytab>              keytab file to use for kerberos decryption
  -G [report]              dump one of several available reports and exit
                           default report="fields"
                           use "-G help" for more help
```

### `Wireshark Display Filters` use Wireshark custom **propietary** syntax, AKA Wireshark's specialized display filter format
* A BPF (Berkley Packet Filter) virtual machine lives inside the kernel

### `Capinfos.exe` prints information about trace files:

```
$ capinfos [options] <infile> ..
```

### `Comparison Operators` for Display Filters (Wireshark custom **propietary** syntax, AKA Wireshark's specialized display filter format) 
* Using Operators, you can create display filters based on the contents of a field.

| Symbol Expression | Text Expression & Definition |
| ------ | ------ |
| `==` | eq 'EQUAL TO' |
| `||`| or 'OR AKA Alternation' |
| `^^`| xor 'XOR' (Only one of multiple conditions must match) | 
| `&&`| and 'AND' |
| `gt`| 'GREATER THAN' |
| `<` | lt 'LESS THAN' |
| `=` | ge 'GREATER THAN OR EQUAL TO' |
| `<=` | le 'LESS THAN OR EQUAL TO' |
| `!` | not/negate 'NOT' |
| `!=` | ne | 'NOT EQUAL TO' |
| `NA` | contains 'CONTAINS' |
| `NA` | matches 'MATCHES' |
| `""` | Text/String Search 'String/Text Search - Substring Operator' |

### `Matches` Comparison Operator and `Regex`

The Matches Operator (within a Display Filter) is used with Perl regular expressions (REGEX) to search for a string within a field which the functionality is provided through libpcre [Perl Compatible Regular Expressions Library](regexlib.com/cheatsheet.aspx), I.E: _(Display filter)_

```
http.request.method=="GET" && (http matches "\.(?i) (zip|exe)}` 
```

> If we are interested in all HTTP requests for files ending in .zip or .exe (Capture filter)
OR:

```
$ http matches "\.(?i) (zip|exe|jar)" .. 
# If we want to look at HTTP packets containing .zip, .exe or .jar in either upper or lower case
# `{"\"}` Looks for a dot
# `{(?i)}` Indicates the search is case insensitive
# `{(zip|exe|jar)}` provides or conditions for those strings
```
* Look for email addresses anywhere in the frame:
```
$ frame matches "(?i)[A-Z0-9._%-]+@[A-Z0-9.-}+\.[A-Z\>] {2,4}"
```
* Look for someone using HTTP to connect to a website ending in a string other than ".com":
```
$ http.host && !http.host matches "\.com$"}`
```

* Using Tshark and "**-Y**" for BPF display filter, look for any host within _192.168.1.X_ subnet:
* We have to convert this IPv4 address type field to a string and build out our filter at the same time, because 

> "ip.src (type=IPv4 address) cannot participate in 'matches' comparison.":

```
tshark -i en6 -n -Y 'string(ip.addr) matches "192\\.168\\.1\\.[0-9]"' -T fields -e ip.src | sort | uniq
tshark -i en6 -n -Y 'string(ip.addr) matches "192\\.168\\.1\\.[0-255]{3}"' -T fields -e ip.src | sort | uniq
```

### `Offset Filters` (Applicable to both Display Filters and Capture Filters and use the same format of syntax) [Example YouTube](https://youtu.be/N3TXtmpxcws)
* Uses the offset and a value calculated from a specific point of a packet. The offset count always starts at zero (0).
* These types of display filters use the same format as offset capture filters:

```
proto[expression:size]
```

* Examples include:

```
$ eth.src[4:2]==22:1b 
# (Display Filter) for Ethernet source addresses that end with a specific two-byte value

$ ip[14:2]==96:2c (Display Filter) 
# Looks at the 15th and 16th bytes of the IP header (AKA the end of a source IP address) for a value of 0x962x (which would equate to a source IP address ending in 150.44)
# [14:2] means we count over 15 bytes (start counting at zero-0) and look for a two-byte value. 
# For reference, refer to an image of a IPv4 header breakdown which and signifies the byte values of the Source IP address (which is 12th byte through 15th byte) within 0-23 byte header value.

$ (tcp[2:2] > 100 and tcp[2:2] < 150)
# (Capture Filter) Captures only the traffic between 100 and 150. The destination port field is located at offset 2 from the start of the TCP header and the field is two bytes long
```

* Where the `{"proto"}` is one of the `{ether, fddi, tr, ip, arp, rarp, tcp, udp, icmp or ip6}`
* `{"Expr"}` identifies the offset of the field
* `{"size"}` defines the length (in bytes) you are interested
* This is followed by the operator and value, the `{"size"}` value is omitted, it is automatically set to 1

**Another I am fairly proud of calculating from answering a [Reddit Forum](https://www.reddit.com/r/wireshark/comments/vxjiq0/comment/ig1s2yk/?context=3) was a requirement to exclude common IP addresses/ranges from a Tshark Display Filter Query** with ("**-Y**")
* Any of the following queries are tested and working and each show differentiation of results

```
$ tshark -i en6 -n -Y 'ip[12:3]!=c0:a8:01'
$ tshark -i en6 -n -Y 'ip[12:3]==c0:a8:01'
$ tshark -i en6 -n -Y 'ip.src[12:3]!=c0:a8:01'
$ tshark -i en6 -n -Y 'ip.dst[12:3]==c0:a8:01'

# Using Capture Filters with "**-f**" and omitting to date/time-parsed file as Display Filters cannot write to a file
$ ~ % tshark -i en6 -n -w /Downloads/$date.pcap "**-f**" 'ip[12:3]!=c0:a8:00'
```

* For the first search above, this states that the first three octets _(byte count 12,13,14)_ should not equal **(!=)** 192.168.1 which in [Decimal notation for IPv4 to Hexadecimal conversion](https://www.binaryhexconverter.com/decimal-to-hex-converter) is _c0:a8:0_
* Run the following display filter in Wireshark with a copy of the capture (where equals) and **hover** over the "_Source IPv4 Address_" field to show the byte count and byte value which correlates to the offset filter: (thus proving the theory)

```
ip.src[12:3]==c0:a8:01
```

* One thing I identified from Tshark is that it does not allow "**-R**" parameter and Display Filter Syntax for a TCP Stream specifically and omits no response

```
adamdawson@SL-XXXX ~ % tshark -r ~/Downloads/ads-tcp-http_curl-three-way-handshake-example-neverssl.com.pcapng -Y "tcp.stream eq 4"

adamdawson@SL-XXXX ~ % tshark -r ~/Downloads/ads-tcp-http_curl-three-way-handshake-example-neverssl.com.pcapng -Y "tcp.stream==4"
adamdawson@SL-XXXX ~ %
```



### `{Tshark -qz Operator:}`
* Tshark can be used to quickly gather statistics on live traffic or trace files and filters can be applied to the packets to limit the statistics to specific packet types, not packets for capture (**-f**) and therefore Display (-Y)
* `{-q}` option if you only want the statistics and not want to see the packets while running Tshark
> Example of displaying PHS (Protocol Hierarchy Statistics) of traffic seen by Wireshark only, but not displayed on the screen
```
$ tshark -qz io,phs
```
* Most of the `{-q}` option's can be used multiple times in one command-line string
> Example of combine request for Ethernet, IP and TCP Conversation Statistics
```
$ tshark -qz conv,eth -z conv,ip -z conv,tcp
```
> Example of displaying IO statistics for IP, UDP and TCP traffic at 10 second intervals
```
$ tshark -qz io,stat,10,ip,udp,tcp
$ tshark -z io,stat,5,icmp -w allpakts.pcapng
```
> Example of omitting Tshark gathered information to stdout from capturing hosts on interface 1
```
$ tshark -i 1 -qz hosts -z conv,ip # Will display the IP conversation statistics and hosts information
$ tshark -i 1 -qz hosts > hostsinfo.txt
```

### `Wireshark Best Practices` for Packet Heads:
* Remember to setup default packet capture type as **PCAPNG** (Next-Generation) Format which are backwards compatible and also store them as trace files which includes packet comments. 
    * We recommend saving your trace files in .pcapng format to support packet and trace file annotations
* Remember to setup default Packet Capture Location Folder for ease of saving traces 
* [MaxMind Geo-IP DB's](https://www.maxmind.com/en/home) are stored in **'/Users/ads/.config/wireshark'** personal configuration files
* Expert Info Button is in Wireshark's Status Bar and **_"Analyze" > Expert Info_**
* Use the *_"Analyze" > Expert Info Summary_* to view all Packet Comments, or recommended to add as **_"pk_comments"_** a column to view Packet comments inline with the entire capture 
* Use the following Display Filter to filter on all TCP Expert notifications as a Display Filter:

```
$ tcp.analysis.flags
```

* By default, switches forward all broadcast packets, multicast packets (unless configured to block multicast forward) packets destined to the Wireshark hosts hardware address and packets destined to unknown hardware addresses
* File Sets are used to create contiguous set of trace files during a capture process, instead of navigating through one large trace file
* Packet marking is temporary after reloading the trace file, whereas coloring rules are automatically applied to the traffic each time you open the trace file where coloring is enabled
* `Coloring Rules` are processed in Top->Down fashion/order and are created using Display Filter (BPF) Syntax
* Sync your Wireshark machine with an NTP source for accurate timestamps
* Beware of sharing Preferences Files within Wireshark profiles which may be specific to the original Wireshark system such as default directory setting for opening new trace files and default capture device setting
* Beware of also exposing internal company IP addresses and recommended to sanitize trace files by using a hexadecimal editor and performing a search and replace function for all IP addresses in the trace file
* Bit-Twiste - bittwist.sourceforge.net can be used to automatically change the IP addresses and calculate the new checksum values if you wish to recalculate the checksum values after changing IP's
* `Bit-Twist` is a simple yet powerful libpcap-based Ethernet packet generator. It is designed to complement tcpdump, which by itself has done a great job at capturing network traffic.
```
$ bittwiste -I ftp-ioupload-partial.pcap -O ftpmod.pcap -T ip -s 67.161.19.78,10.10.19.78 -d 67.161.19.78,10.10.19.78
```
* If you want to save the TCP header as a text file, expand the TCP header in a packet and choose **_File | Export Packet Dissections | Choose as | Plain Text File_**

### `Baselining`, `Troubleshooting` and Network `Forensics`:

* `Baselining` is the process of creating a set of trace files that depict "nomal" communications on the network. 
    * Having baselines that we created before network problems or security breaches occur can speed up the investigation and remediation process. 
    * Ultimately, baselines enable you to resolve problems more effectively & efficient
    * Anything outside of a baseline pattern of traffic is usually tagged as anamolous, or an anomaly. 
    * Baselining idle traffic establishes an understanding of "background traffic" for BAU that typically occurs.

* Baselining can be beyond just trace files and include additional information such as images, screenshots, summary data, IO graph information and network maps.
    * For baselining, it is recommended to apply columns such as 
    * **RTT (round trip time - especially for initial TCP handshakes)** 
    * Looking at **_"Analyze" > Expert Info flags**_ _($`tcp.analysis.flags`)_
    * **Capture File Information**
    * **PHS (Protocol Hierarchy Statistics)**
    * **_Statistics > Packet Lengths Graph & Small Payload Sizes_**
    * **TCP Window Size Column** values 
    * **_"Statistics" > Packet/Protocol Summaries & Statistics._**
* When it comes to baselining, you may also need to tap into network traffic not destined to and from the capturing local machine (such as Monitor mode on Wireless). Also consider using an application such as iPerf to perform throughput tests and capture the file during the test to graph the IO Rate as well as analyze packet sizes.

* To identify delays such as `Latency` in a trace file, set the **'Time Column'** to **'Seconds Since Previous Displayed Packet'**, filter on a conversation.
    * Then sort the column to note the large gaps in time between packets in the trace file.
    * Alternatively, do the same but add a column for **"Delta Time"** (conversation) to identify large gaps in time between packets in a conversation.
* Packet `timestamps` are provided by the `WinPcap`, `libpcap` or `AirPcap` **libraries** at the time the packet is captured and saved with the trace file, they support microsecond resolution. 
    * Filtering on software may bear different results.

```
$ tcp.time_delta > 1
$ tcp.time_delta > 1 && tcp.flags.fin==0 && tcp.flags.reset==0
```
* The second part of the second filter identifies an explicit (**tcp.rst**) or implicit connection shutdown process.
* In a UDP-based application, the retransmission timeout value is dictated by the application itself. Whereas, TCP will automatically attempt to recover from the problem.

* `Packet Marking` is also recommended during troubleshooting for **_((Edit > Find Next Mark | Find Previous Mark))_**
* Being `"Upstream"` defines that you are closer to the sender of the data in the traffic flow.
* Being `"Downstream"` defines that you are closer to the recipient of the data in the traffic flow 
    * Move the analyzer (Wireshark) along the path to determine the point when you see original packet and re-transmission, moving downstream to identify at which layer 3 hop device the packets start to become delayed in forwarding and|or dropped.
* The key difference between hubs, switches and bridges is that hubs operate at Layer 1 of the OSI model
* Bridges and traditional L2 switches work with MAC addresses at Layer 2.
* VLANs separate broadcast domains
* Ports separate collision domains **(CSMA/CD)**

* If `Expert Info` detects **"NOP"** (_No Option / Operator_ - I.E disabling SACK - Selective ACK's) means an inline router may have removed some TCP options. Move the analyze to the other side of the routing device and compare the TCP options in the handshake.
* One way to capture with Wireshark under-the-radar and avoid detection is to disable the TCP/IP stack and disable network name resolution, but Wireshark will continue to capture traffic [Sec Tools](https://sectools.org) and [WireShark Wiki Tools](https://wiki.wireshark.org/tools)
* `Network Forensics` is the process of examining network traffic for evidence of unusual or unacceptable traffic which may include:
    * Reconnaissance (discovery) processes
    * Phone-home behavior
    * DoS (denial of service) attacks
    * MITM (man-in-the-middle) poisioning
    * Bot commands
* Consider using `Coloring Rules` for unusual or unexpected packets with Network Forensics to identify them faster in the Packet List pane.
* OS Fingerprinting involves sending traffic to the system in question and is therefore referred to as Active, not Passive
* Multiple SYN, ACK's with no data and|or port scans could interpret Active OS Fingerprinting

* You can always apply common troubleshooting filters to troubleshoot slow downloads/uploads or other application type problems. Here are some filters that are commonly used or applied as columns.

| Wireshark TCP Column | Description |
| ------ | ------ |
| `tcp.analysis.lost_segment` | Indicates we’ve seen a gap in sequence numbers in the capture. Packet loss can lead to duplicate ACKs, which leads to retransmissions
| `tcp.analysis.duplicate_ack` | Displays packets that were acknowledged more than one time. A high number of duplicate ACKs is a sign of possible high latency between TCP endpoints 
| `tcp.analysis.retransmission` | Displays all retransmissions in the capture. A few retransmissions are OK, excessive retransmissions are bad. This usually shows up as slow application performance and/or packet loss to the user
| `tcp.analysis.window_update` | Will graph the size of the TCP window throughout your transfer.  If you see this window size drop down to zero (or near zero) during your transfer it means the sender has backed off and is waiting for the receiver to acknowledge all of the data already sent. This would indicate the receiving end is overwhelmed. 
| `tcp.analysis.bytes_in_flight` | Number of unacknowledged bytes on the wire at a point in time. The number of unacknowledged bytes should never exceed your TCP window size (defined in the initial 3 way TCP handshake) and to maximize your throughput you want to get as close as possible to the TCP window size. If you see a number consistently lower than your TCP window size, it could indicate packet loss or some other issue along the path preventing you from maximizing throughput.
| `tcp.analysis.ack_rtt` | Measures the time delta between capturing a TCP packet and the corresponding ACK for that packet. If this time is long it could indicate some type of delay in the network (packet loss, congestion, etc)
| `tcp.len` | Easily see the payload size or even use this in an IO graph with {$ AVG(*)tcp.len} value in an Advanced IO Graph
| `tcp.window_size_value` | Identify TCP Window Size values to detect zero windows as part of TCP Windows Scaling Problems and indicate a TCP Receiver may not have buffer space available


#### **[RFC3514](https://datatracker.ietf.org/doc/html/rfc3514)** The Security Flag in the IPv4 Header
```
"evil" bit == 0 - OK
"evil" bit == 1 - Malicious
```
#### A Display Filter to search for possible MTU problems: 
```
$ icmp.type==3 && icmp.code==4
```
#### When Wireshark detects that an IPv6 header follows an IPv4 header, it adds two notes to the packet:
* Source 6to4 Gateway IPv4:
```
$ ipv6.src_6to4_gw_ipv4
```
* Source 6to4 SLA IA:
```
$ ipv6.src_6to4_sla_id
```

# [`Wireshark Libraries` and Traffic Capture Process](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterLibraries.html#:~:text=Like%20most%20applications%2C%20Wireshark%20depends,import%20libraries%2C%20and%20related%20resources.)

### [`Libpcap`](www.tcpdump.org)
* The libpcap library is the industry standard link-layer interface for capture traffic on *NIX hosts.
* These hosts also support Monitor Mode 
### [`WinPCAP`](www.winpcap.org)
* WinPCAP is the Windows port of the libpcap link-layer interface. WinPcap consists of a driver that provides low-level network access and the Windows version of the libpcap API.
WinPap does not support Monitor Mode and therefore does not work with Wireshark or Tshark in Windows 
### [`AirPcap`](www.riverbed.com/us/products/cascase/aipcap.php)
* AirPCAP is a link-layer interface and network adapter to capture 802.11 traffic on Windows operating systems. 
AirPcap adapaters operate in passive mode to capture WLAN data, management and control frames.

## `Wireless Traffic Monitoring`

> * How can you quickly identify all WLAN BSSIDs seen in a trace file? == **"Open Statistics | WLAN Traffic"**

> Wireshark cannot identify unmodulated RF energy of interference and requires a spectrum analyzer such as [MetaGeek](www.metageek.net/wiresharkbook)
### `Promiscuous Mode `
* Sets interface to capture all packets on a network segment to which it is associated to
    * In Promiscuous Mode, an 802.11 adapter only captures packets of the SSID the adapter has joined
1. **Promiscuous Mode** enables a network card and driver to capture traffic that is addressed to **other devices on the network and not just the local hardware address**
2. In **Promiscuous Mode** only without Monitor Mode, an 802.11 adapter only captures packets of the SSID the adapter has joined
3. Although at the radio level it can receive packets on other SSID's, those packets are not forwarded to the host

### `Monitor Mode` .. AKA "`rfmon mode`"

* In Monitor Mode, an adapter does not associate with any SSID and all packets from all SSID's on the selected channel are captured
    * In order to capture all traffic that the adapter can receive, the adapter must be put into Monitor Mode. 
    * When using Monitor Mode, the driver does not make the adapter a member of any service set on the network meaning that the adapter will not support general network communications such as web browsing, since it is busy monitoring and sniffing all RF-Energy on the selected channel. 
    * **Monitor Mode is not supported by WinPCAP.**
In `Monitor Mode`, **all packets of all SSIDs** from the currently **SELECTED CHANNEL** are captured.
> Setup the wirless interface to capture all traffic it can receive (Unix/ Linux only)
1. In order to capture all-SSID traffic that the adapter at the radio level can receive, the adapter must be put into **"Monitor Mode"**
2. AKA **"rfmon mode"**
3. In this mode, the driver does not make the adapter a member of any service set (meaning that the adapter will not support general network communications such as web browsing, since it is busy monitoring and sniffing all RF-Energy on the selected channel)
4. In monitor mode, the adapter won't support general network communications. It only supplies received packets to a packet capture mechanism such as Wireshark, not to the network stack.
5. Test to see if your network interface cards/drivers support Monitor Mode 

#### `Monitor Mode` vs `Promiscuous Mode` Summary

* In `Monitor Mode`, the driver doesn't make the adapater a member of any service set and the adapter and driver pass ALL packets of ALL SSID's from the currently selected channel up to Wireshark
* `Promiscuous Mode` enables a network card and driver to capture traffic that is addressed to other devices on the network and not just to the local hardware address

| Promiscuous Mode Setting | Monitor Mode Setting |
| ------ | ------ |
| `Promiscuous Mode On` | `Monitor Mode Off`
| **Capture Capabilities:** |Fake Ethernet header prepended to packet, no MGMT or control packets captured
| **Issues to consider?:** | Disable Promiscuous Mode
| `Promiscuous Mode Off` | `Monitor Mode Off`
| **Capture Capabilities:**  | Fake Ethernet header prepended to packet, no MGMT or control packets captured
| **Issues to consider?:** | Need to capture traffic on the host you are interested in
| `Promiscuous Mode Off` | `Monitor Mode On`
| **Capture Capabilities:** | 802.11 header;Management and Control packets captured
| **Issues to consider?:** | Need to capture traffic on the host you are interested in
| `Promiscuous Mode On` | `Monitor Mode On`
| **Capture Capabilities:** | 802.11 header;Management and Control packets captured
| **Issues to consider?:** | **GREAT!** Can capture traffic on various channels and from all SSID's}`

> WLAN Traffic Capture Filter:
```
$ wlan host <wlan_mac>
```
> WLAN Traffic Display Filter: 
```
$ wlan
```

### `Wireshark Wiretap Library`
* The Wireshark Wiretap Libraby processes opened traced files for visibility and analysis within the UI for a selected amount of file types.

# `Wireshark Processes Packets and Wireshark Architecture`
### Wireshark Architecture Flow Diagram:

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
### Core Engine
The Core Engine is the 'glue code that holds the other blocks togather'
### Wireshark Wiretap Library
The Wireshark Wiretap Library processes opened traced files for visibility and analysis within the UI for a selected amount of file types.
### Dissectors - Plugins - Display Filters ##

Dissectors AKA decodes... **_Wireshark > Preferences > Protocols_**
* Dissectors, plugins and display filters are applied to traffic at this time
    * Dissectors decode packets to display field contents and interpreted values
    * You may edit a dissector such as HTTP when dealing with HTTP traffic on non-default port of TCP80

> **1)** When a packet comes in, Wireshark detects the frame type first and hands the packet off to the correct frame dissector (E.G Ethernet)
> **2)** After breaking down the contents of the frame header, the dissector looks for an indiciation of what is coming next (E.G, an Ethernet header the value of 0x0800 indicates that the IP is coming up next
> **3)** The Wireshark Ethernet Dissector hands off the packet to the IP Dissector
> **4).** The IP Dissector analyzes the IP header and looks to the protocol field in the IP header to identify the next portion > of the packet (E.G the value is 0x06 for TCP, then the IP Dissector hands the packet off to the TCP Dissector)
> **5)** This same process occurs until no further indications of another possible dissection
### Gimp Graphical Toolkit (GTK+) ##
* GIMP GTK+ is the graphical toolkit used to create the GUI for Wireshark and offers cross-platform compatibility
### How a **`TCP Stream`** is created in Wireshark?
```
$ tcp.stream eq X
```
* Wireshark creates a filter based on the stream number
    * The Stream Index is not an actual field in the TCP header and is defined by Wireshark. This can be use to quickly filter a TCP conversation. 
    * As of Wireshark 1.8, the Stream Index value begins at 0 and increments by 1 for each TCP conversation seen in the trace file.
### How a **`UDP Stream`** is created in Wireshark?
```
$ ((((ipv6.src == 2001:569:5752:600:9915:c408:a195:d51c) && (ipv6.dst == 2001:568:ff09:10c::67))) && (udp.srcport == 49671)) && (udp.dstport == 53)
```
* Wireshark creates a filter based on source/destination IP addresses and source/destination port numbers
    * Prior to Wireshark 1.8, UDP conversations were assigned a Stream Index Value and this caused quite some confusion.
### How an **`SSL Stream`** is created in Wireshark?
```
$ tcp.stream eq X
```

* Wireshark creates a filter based on the stream number
  * A stream window may be empty until you successfully apply decryption keys to the SSL stream

# `Practical Packet Analysis`

### `Time Display Formats` and [Time References](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkTimeFormatsSection.html)
* `Absolute` vs `Relative` [time](https://www.quora.com/What-is-the-difference-between-absolute-and-relative-time)
    * Absolute time is cosmic time (I.E 60 million years ago || 12:00pm // specific points of reference)
        * Atomic time uses a bottom up approach, first determining the duration of a second. To do this, it uses atomic decay. Think carbon or plutonium decay. So, 60 seconds makes a minute. 60 minutes makes an hour and 24 hours makes a day.
    * Relative time is atomic time (Wen we compare the measures occurring in two different frames of reference that are moving relative to each other)
        * Relative time is atomic time, while absolute time is cosmic time. For example, the earth rotates on its axis, once per day. That day is divisible by 24 hours. An hour is divisible by 60 minutes and a minute is divisible by 60 seconds. That's cosmic time.

* Packet Timestamps are saved inside PCAP and PCAP-NG files so the packet timestamps can be displayed when the file is opened again
* The Time Reference setting is **NOT** saved permanently with the trace file
* The available Time **presentation formats** are:

* Date and Time of Day: 1970-01-01 01:02:03.123456 The absolute date and time of the day when the packet was captured.
* Time of Day: 01:02:03.123456 The absolute time of the day when the packet was captured.
* Seconds Since First Captured Packet: 123.123456 The time relative to the start of the capture file or the first “Time Reference” before this packet
* Seconds Since Previous Captured Packet: 1.123456 The time relative to the previous captured packet.
* Seconds Since Previous Displayed Packet: 1.123456 The time relative to the previous displayed packet.
* Seconds Since Epoch **(1970-01-01): 1234567890.123456 The time relative to epoch (midnight UTC of January 1, 1970)**

| Time Syntax | Description |
| ------ | ------ |
| `frame.time` | is Arrival Time, based on the system time at the time the packet was captured.
| `frame.time_delta` | is the Time Delta from Previous Captured Frame when a packet arrived, compared to the previous captured packet regardless of files.
| `frame.time_delta` | (Time Delta from Previous Displayed Frame) is NOT the same and must be filtered with a conversation first, then apply a filter.
| `frame.time_relative}` (Time Reference, Since Reference or First Packet) | Compares the current packet time to the first packet in the trace file `frame.time_relative==0` or the most recent packet that has the time reference set
* You can filter on TCP Conversation timestamps for detecting latency which requires no filtering.
    * **_Edit > Preferences > Protocols > TCP > Calculate Conversation Timestamps_**


[Serial Communication](https://learn.sparkfun.com/tutorials/serial-communication/all)
> `Parallel vs. Serial`
> * **Parallel interfaces** transfer multiple bits at the same time. They usually require buses of data - transmitting across eight, sixteen, or more wires. Data is transferred in huge, crashing waves of 1`s and 0`s.
> * **Serial interfaces** stream their data, one single bit at a time. These interfaces can operate on as little as one wire, usually never more than four.

| OSI (Open Systems Interconnect) Model (7 Layers) | Mnemonic
| ------ | ------ |
| 1) Physical | Processing
| 2) Data Link | Data
| 3) Network | Need
| 4) Transport | To
| 5) Session | Seem
| 6) Presentation | People
| 7) Application | All

| TCP/IP Model (4 Layers) | Mnemonic
| ------ | ------ |
| 1) Network Access Layer | New Ants 
| 2) Internet Layer | In
| 3) Transport Layer | Take
| 4) Application Layer | Armadillos

* `"Dark Addresses"` is a term for unassigned IP addresses

| [List of IP protocol numbers](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers) | Filter and Hex Value
| ------ | ------ |
| `ICMP` = | `ip.proto==1` `(0x01)`
| `TCP` = | `ip.proto==6` `(0x06)`
| `UDP` = | `ip.proto==17` `(0x11)`

> * Each fragment of a fragmented IP packet does **_NOT_** have a different ID (identification value), and is the same
```
 ip.flags.mf ==1 or ip.frag_offset gt 0
```
* **IGMP** (Internet Group Management Protocol) is a communicated used by a host to dynamically join a Multicast (IPv4 Destination = `224.0. 0.0 through 239.255. 255.255` and 01-00-5E in hexadecimal for MAC Address) group.
* The TTL (IP-layer) used within a Traceroute can be any set value from 1-255 and is deprecated (AKA subtracted) by a value of 1 (one) at a router or layer three boundary until the integer value reaches 0 and thus the packet has to be discarded which prevents looping layer three packets.
* ARP is a layer 2 protocol. The Address Resolution Protocol is a layer 2 protocol used to map MAC addresses to IP addresses.
> Beware of Proxy-ARP, ARP packets are not forwarded over L3 boundaries as they do not contain an IP header
> Proxy ARP is a technique by which a proxy server on a given network answers the Address Resolution Protocol (ARP) queries for an IP address that is not on that network.
> **Opcode field** in the `Address Resolution Protocol` (ARP) Message specifies the nature of the ARP message. 
* `1 for ARP request` (destined to IPv4 broadcast FF:FF:FF:FF:FF:FF:FF:FF and `2 for ARP reply`.

### `IPv4` (Internet Protocol v4)
> 32-bit addressing scheme, represented in decimal notation
> Display Filter = "`{$ ip}`"
> IPv4 Header Length == 20-60 bytes
* In IPv4, the Identification (ID) field is a 16-bit value that is unique for every datagram for a given source address, destination address, and protocol, such that it does not repeat within the maximum datagram lifetime (MDL).
* As currently specified, all datagrams between a source and destination of a given protocol must have unique IPv4 ID values over a period of this MDL, which is typically interpreted as two minutes and is related to the recommended reassembly timeout.

### `IPv6` (Internet Protocol v6)
> * 128-bit addressing scheme, represented in hexadecimal notation
> * Display Filter = "`{$ ipv6}`"
> * Capture Filter = "`{$ ip6}`"
> * IPv6 Header length == 40 bytes
> * IPv6 does not use TTL (time-to-live), but uses "Hop Limit"
### `EtherTypes`
> * EtherType is a two-octet field in an Ethernet frame. 
> * It is used to indicate which protocol is encapsulated in the payload of an Ethernet Frame
> * EtherType numbering generally starts from 0x0800.
> * EtherType for some notable protocols:

| EtherType | Protocol
| ------ | ------ |
| 0x0800  | Internet Protocol version 4 (IPv4)
| 0x0806  | Address Resolution Protocol (ARP)
| 0x0842  | Wake-on-LAN
| 0x8035  | Reverse Address Resolution Protocol
| 0x809B  | AppleTalk (Ethertalk)
| 0x8100  | VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq
| 0x86DD  | Internet Protocol Version 6 (IPv6)
| 0x8847  | MPLS unicast
| 0x8848  | MPLS multicast
| 0x8863  | PPPoE Discovery Stage
| 0x8864  | PPPoE Session Stage
| 0x8870  | Jumbo Frames (proposed)
| 0x888E  | EAP over LAN (IEEE 802.1X)
| 0x88CC  | Link Layer Discovery Protocol (LLDP)

### `TCP` - Transmission Control Protocol
1) **0-65535 bytes/OxFFFF** maximum payload/TCP Window field which is a two byte field
2) _Connection-orientated_ protocol
2) **Flow Control** using Sequence `SEQ` and Acknowledgement `ACK` numbers to ensure data arrives at the destination and offers automatic retransmission for lost segments and flow control mechanisms to avoid saturation of a network or TCP host. 
Three identical ACK's trigger a TCP Re-Transmission
3) Error **Checksum Recovery** and Validation (performed on the contents of the TCP header and data) as well as a psuedo header derived from the IP header.
4) TCP Header Size commonly == 20 bytes and variable-length data with supported TCP Options fields which can extend the header length `$ tcp.hdr_len > 20}`
5) **MSS** (Maximum Segment Size) is the agreed lowest value during the initial two packets of the TCP Three Way Handshake and defines what segment size the host and server will support. `$ tcp.options.mss_val < 1460`
6) TCP Timestamp column in Wireshark `tcp.time_delta}` is the time since previous frame in the TCP Stream and useful for troubleshooting TCP communications and conversations to see large gaps in time and potential packet loss and|or latency.

> Capture Filter Syntax == "`tcp`"
> Display Filter Syntax == "`tcp`"

> The Congestion Window == "**cwnd**"
> The Receive Window == "**rwin**" == The TCP buffer space on the receiving end of a TCP connection and maximum size is dependent on the settings and capabilities of the receiver. The current receive buffer size is based on the amount of available space to accept more data from a peer before handing the data up to an application.

```
$ !(tcp.flags.cwr==0) || !(tcp.flags.ecn==0)
$ tcp.options.wscale_val
```

## `TCP Sequence and Acknowledgement Process`
* Each TCP device assigns its own ISN (Initial Sequence Number) which is a randomly unique generated integer.
    * The Next Expected Sequence Number appears on packets that contain data and is not seen in SYN packets or simple ACK packets. 
    * Wireshark examines the current packet Sequence Number and adds the number of data bytes to provide this number.
```
Sequence Number In
+ Byes of Data Received
----------------------------
= Acknowledgement Number Out
```
> **1)** * The ACK number field indicates the next expected sequence number from the other side of the communication.
> **2)** An ACK number field that is never incremented by a host simply indicates that no data is being received by that host.
> **3)** Remember, the Acknowledgement Number field contains the value of the next sequence number expected from the other side which only increments when data is received.
> **4)** The initial SYN, SYN/ACK, ACK TCP Three-way handshake does not contain numbers in the SEQ's/ACK's as there is no payload here, but increments by 1 even though a byte of data was not sent.
> **5)** After the handshake is established, the sequence numbers only increment by the number of actual data bytes sent.
> **6)** The Sequence number increments by the number of data bytes contained in each packet by the sender.

Display Filters for TCP Flags:
```
$ tcp.flags.ack==1
$ tcp.flags.reset==1
$ tcp.flags.syn==1
```
Filter on the TCP Flags Summary Line:
```
$ tcp.flags==0x12
```

* TCP Splicing does *NOT* involve recomputing checksums
* TCP Performance Optimization "`Slow Start`" is related to **Congestion Control**
* The `TCP Expert Information` is contained within the `packet-tcp.c` file

### `TCP Sequence and Acknowledgement Process - Analysis:`

> * The ACK number field indicates the next sequence number expected from the other side of the connection.
* To test the TCP Sequence and Acknowledgement Process into Markdown format & for my own analysis, I conducted the following test...


1) Verify the IP address of a HTTP-based (non-TLS) website for the capture
2) Run a cURL using IPv4 and TCP (default) to simplify a HTTP GET request to exchange data after a TCP three-way handshake
3) Capture via Wireshark/Tshark with Relative Sequence Numbers Enabled, so for simplicity over analysis the ISN is not present which forces you to make mathematical calculations as difficult

```
ping neverssl.com
PING neverssl.com (34.223.124.45): 56 data bytes
adamdawson@SL-1788 ~ % curl --GET neverssl.com -4
```
* Display Filter: (Wireshark GUI)
```
tcp.stream eq 4
```

```
No.     | Time         | Delta           | Source       | Destination | tcp.len | Seq | Ack | Next Seq | Info                                 | Calculated Window Size     | Bytes in Flight | Bytes sent since last PSH Flag | Shift Count | Text Item
***********************************************************************************************************************************************************************************************************************
16  6.567059  0.000000  192.168.1.64  34.223.124.45 0 0 0 1 50475 → 80 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 TSval=900678328 TSecr=0 SACK_PERM=1 65535     6 ✓
20  6.587321  0.020262  34.223.124.45 192.168.1.64  0 0 1 1 80 → 50475 [SYN, ACK] Seq=0 Ack=1 Win=26847 Len=0 MSS=1460 SACK_PERM=1 TSval=2272420079 TSecr=900678328 WS=128  26847     7 ✓
21  6.587385  0.000064  192.168.1.64  34.223.124.45 0 1 1 1 50475 → 80 [ACK] Seq=1 Ack=1 Win=131712 Len=0 TSval=900678348 TSecr=2272420079  131712        ✓
22  6.587470  0.000085  192.168.1.64  34.223.124.45 76  1 1 77  GET / HTTP/1.1  131712  76  76    ✓
24  6.606022  0.018552  34.223.124.45 192.168.1.64  0 1 77  1 80 → 50475 [ACK] Seq=1 Ack=77 Win=26880 Len=0 TSval=2272420099 TSecr=900678348  26880       ✓
25  6.606172  0.000150  34.223.124.45 192.168.1.64  1448  1 77  1449  HTTP/1.1 200 OK  (text/html)  26880 1448  1448    ✓
26  6.606211  0.000039  192.168.1.64  34.223.124.45 0 77  1449  77  50475 → 80 [ACK] Seq=77 Ack=1449 Win=130304 Len=0 TSval=900678367 TSecr=2272420099  130304        ✓
27  6.606372  0.000161  34.223.124.45 192.168.1.64  1448  1449  77  2897  Continuation  26880 1448  2896    ✓
28  6.606373  0.000001  34.223.124.45 192.168.1.64  1365  2897  77  4262  Continuation  26880 2813  4261    ✓
29  6.606400  0.000027  192.168.1.64  34.223.124.45 0 77  4262  77  50475 → 80 [ACK] Seq=77 Ack=4262 Win=128256 Len=0 TSval=900678367 TSecr=2272420099  128256        ✓
30  6.607059  0.000659  192.168.1.64  34.223.124.45 0 77  4262  78  50475 → 80 [FIN, ACK] Seq=77 Ack=4262 Win=131072 Len=0 TSval=900678367 TSecr=2272420099 131072        ✓
31  6.623867  0.016808  34.223.124.45 192.168.1.64  0 4262  78  4263  80 → 50475 [FIN, ACK] Seq=4262 Ack=78 Win=26880 Len=0 TSval=2272420118 TSecr=900678367  26880       ✓
32  6.624066  0.000199  192.168.1.64  34.223.124.45 0 78  4263  78  50475 → 80 [ACK] Seq=78 Ack=4263 Win=131072 Len=0 TSval=900678385 TSecr=2272420118  131072        ✓
```
```
adamdawson@SL-XXXX ~ % tshark -r ~/Downloads/ads-tcp-http_curl-three-way-handshake-example-neverssl.com.pcapng -Y "ip.src==192.168.1.64 && ip.dst==34.223.124.45"
    1   0.000000 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com TCP 78 50475 → http(80) [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 TSval=900678328 TSecr=0 SACK_PERM=1
    3   0.020326 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com TCP 66 50475 → http(80) [ACK] Seq=1 Ack=1 Win=131712 Len=0 TSval=900678348 TSecr=2272420079
    4   0.020411 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com HTTP 142 GET / HTTP/1.1
    7   0.039152 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com TCP 66 50475 → http(80) [ACK] Seq=77 Ack=1449 Win=130304 Len=0 TSval=900678367 TSecr=2272420099
   10   0.039341 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com TCP 66 50475 → http(80) [ACK] Seq=77 Ack=4262 Win=128256 Len=0 TSval=900678367 TSecr=2272420099
   11   0.040000 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com TCP 66 50475 → http(80) [FIN, ACK] Seq=77 Ack=4262 Win=131072 Len=0 TSval=900678367 TSecr=2272420099
   13   0.057007 192.168.1.64 → ec2-34-223-124-45.us-west-2.compute.amazonaws.com TCP 66 50475 → http(80) [ACK] Seq=78 Ack=4263 Win=131072 Len=0 TSval=900678385 TSecr=2272420118
```

`TCP Retransmission` vs. `TCP Fast Retransmission`
> When a packet is sent using TCP, it has a sequence number transmitted with it. 
> When the receiver receives the packet, they send an acknowledgement to the sender with the sequence number showing that packet was received.

> * TCP Retransmission is just a packet that doesn't acknowledge within the timeout.
> * TCP Fast Retransmission is when the source gets confirmation that the packet wasn't received
> * Wireshark uses the term "Fast Retransmission" to define TCP retransmission that occur within 20ms of a Duplicate ACK
> Simply put:
> * TCP Retransmission is mostly dependent on the packet's timeout to detect a miss (Mostly 3 duplicate acknowledgment  `{{DUP ACK}}` for a packet is deduced as a packet miss)
> * In TCP Fast Retransmission, duplicate acknowledgement for a particular packet symbolizes it's miss.
> * The advantage of TCP Fast Retransmission is that it doesn't wait for the packet timeout to initiate a transmission and hence a faster retransmission of packet, as the name also suggests.

* The TCP window size field controls the flow of data and is limited to 2 bytes, or a window size of 65,535 bytes.

| TCP Flag | TCP Flags (Hex Values)
| ------ | ------ |
| NULL | 0x00 | 
| FIN | 0x01 | 
| SYN | 0x02 | 
| RST | 0x04 | 
| PSH | 0x08 | 
| ACK | 0x16 | 
| URG | 0x32 |

### `UDP` - User Datagram Protocol
> **1)** 0-65535 bytes maximum payload
> **2)** Connectionless protocol
> **3)** No error validation
> **4)** UDP Header Size == 8 bytes and variable-length data

> Capture Filter Syntax == "`udp`"
> Display Filter Syntax == "`udp`"

* UDP is a Transport Layer protocol used for Multicast traffic

### `ICMP` - Internet Control Message Protocol
* Example ICMP Types:

| ICMP Type | Usage
| ------ | ------ |
| Type 0 | Echo Reply --- Used for standard ICMP-based traceroute
| Type 3 | Destination Unreachable - RFC792
| Type 5 | Redirect
| Type 8 | Echo --- Used for standard ICMP-based traceroute
| Type 9 | Router Advertisement
| Type 10 | Router Solicitation
| Type 11 | Time Exceeded
| Type 30 | Traceroute
| Type 37 | Domain Name Request
| Type 38 | Domain Name Reply

* ICMP is treats as a L3 protocol. Linux default protocol for traceroute is UDP. An ICMP packet such as ICMP Echo Reply contains portions of the original packet which triggered the initial ICMP response.

* Example ICMP Codes
    * Many ICMP packet types have several possible Code field values

| ICMP Codes | Request
| ------ | ------ |
| Code 0 | Net Unreachable
| Code 1 | Host Unreachable
| Code 2 | Protocol Unreachable
| Code 3 | Port Unreachable
| Code 4 | Fragmentation Needed and DNF (Do Not Fragment) was Set
| Code 6 | Desintation Network Unknown
| Code 7 | Destination Host Unknown
| Code 11 | Destination Network Unreachable for ToS (Type of Service)
| Code 12 | Destination Network Unreachable for ToS (Type of Service)

### `FTP` (TCP21) `ACTIVE` vs `PASSIVE` mode
* FTP is a non-secure protocol and username/password are passed in clear text
    * In *`Passive`* Mode, the FTP server waits for the FTP client to send it a port and IP address to connect to. The client initiates the connection. In *`Passive`* Mode, the *`PASV`* command to establish a Passive Mode FTP Connection.
    * In *`Active`* mode, the Server connects to the FTP client to establish the Data channel IP address/dport. Within *Active* mode, the FTP *`PORT`* command is used to establish an Active Mode FTP Connection.
* In other words, Passive mode lets the client dictate the port used, and active mode lets the server set the port.
```
$ ftp.request.command==""
$ ftp.request.arg==""
```

* FTP Capture Filter == 
> "`$ tcp port 21`" (Communication/Command Channel) / "`$ tcp port <dport>`" (Data Channel)
* FTP Display Filter == 
> "`$ ftp`" (Communication/Command Channel) / "`$ ftp-data`" (Data Channel)

* FTP processes and maintains two parallel TCP connections whilst transferring files (The Communication Channel & The Data Channel)

### `DHCP` Traffic (UDP Broadcasts of Variable Length for IPv4 and Multicast for IPv6) - 
### `DHCP IPv4 DORA` is the default startup sequence for a DHCP Client
* As DHCP traffic is Broadcast traffic, it does not cross intra-VLAN boundaries by default
* DHCP Helper (DHCP Relay Agent) is used when the router acts a proxy to forward DHCP traffic via external VLANs
* DHCP requests are tracked using a unique Transaction ID
* DHCPv4 is based on BOOTP and you will not see BOOTP reference in any DHCPv6 packets

> `UDP 67`=Server Daemon (IPv4)
> `UDP 68`Client Process (IPv4)
> `UDP 546`Client Process (IPv6)
> `UDP 547`Server Daemon (IPv6)

* Capture Filter for IPv4 == 
> $ port 67 or port 68 .. (Even though the client port, traffic will always flow to or from port 67)
* Capture Filter for IPv6 == 
> $ port 546 or port 547..(Even though the client port, traffic will always flow to or from port 546)
* Display Filter for IPv4 == 
> $ dhcp .. or $ bootp 
* Display Filter for IPv6 == 
> $ dhcpv6

`DHCP DORA`
* `D=Discover` (0.0.0.0/0 -> 255.255.255.255:68)
* `O=Offer`
* `R=Request`
* `A=Acknowledge`

`DAD` = Duplicate Address Detection, is performed using ICMP Echo Requests.

* LT Lease Time = How long the client is allowed to use the IP address assigned
* T1 Renewal Time == `{.50 * LT}`
* T2 Rebind Time == `{.875 * LT}`

> * DHCP DORA includes a Transaction ID to track (this is not a Wireshark added field)

### `SIP` (Session Initiation Protocol)

* TCP5060 (dport) is most common for SIP communication channels and contains the URI (Uniform Resource Indicator - I.E, where to identify the SIP user's IP registration / response address)
* `RTP` (Real Time Protocol) is used to carry data through the data flow channel and contains the audio, dport is not fixed and uses UDP
* `SDP` is an Application-layer protocol
* Wireshark _*cannot_* playback encrypted VoIP conversations

| SIP Codes | Request
| ------ | ------ |
| `1xx`— | Provisional Responses (E.G, "180 RINGING")
| `2xx`— | Successful Responses
| `3xx`— | Redirection Responses
| `4xx`— | Client Failure Responses
| `5xx`— | Server Failure Responses
| `6xx`— | Global Failure Responses

```
sip.Method==INVITE
```

### HTTP (Hypertext Transfer Protocol)

> * HTTP is in the Application layer of the Internet protocol suite model and in the Session Layer of the OSI Model

### Common `HTTP` Response and Status Codes

> `Informational` responses *`(100–199)`*
> `Successful` responses *`(200–299)`*
> `Redirection` messages *`(300–399)`*
> `Client error responses` *`(400–499)`*
> `Server error responses` *`(500–599)`*

| `HTTP Status` Code | Meaning
| ------ | ------ |
| `1xx` | Informational  
| `2xx` | Succesful  
| `200` | OK
| `201` | Created
| `202` | Accepted
| `3xx` | Redirection  
| `301` | Moved Permanently
| `307` | Temporary Redirect
| `308` | Permanent Redirect
| `4xx` | Client Error   
| `400` | Bad Request
| `401` | Unauthorized
| `402` | Payment Required
| `403` | Forbidden
| `404` | Not Found
| `405` | Method Not Allowed
| `406` | Not Acceptable
| `429` | Too Many Requests
| `5xx` | Server Error   
| `500` | Internal Server Error
| `501` | Not Implemented
| `502` | Bad Gateway
| `503` | Service Unavailable
| `504` | Gateway Timeout
| `511` | Network Authentication Required

### `Wireshark Best Practices` for `System Performance`
* Disable Name Resolution or add manual DNS host files to refer to, rather than recursive lookups which prevents Wireshark potentially overloading a DNS server with PTR queries (A-Record lookups)
* Beward of firewalls blocking DNS packets via UDP **>512bytes** in length and use TCP as an alternate
* Beware of Proxy-ARP, ARP packets are not forwarded over L3 boundaries as they do not contain an IP header
* Use File Sets instead of one large trace file which may be slow performance related

### `Wireshark Graphs`
* Graphs are saved within the **current profile.**
* **_"Statistics > IO Graphs" and "Statistics > TCP Stream Graphs"_**
* `{Advanced IO (Input, Output)}` Graphs - 
    * Advanced IO (Input, Output) Graphs enable you to use CALC calues such as SUM(*), COUNT(*), MIN(*), MAX(*) and LOAD(*) on the traffic in which the entire packet is calculated including payload and headers. Display filters can also be placed on the traffic in the Advanced IO Graphs.
        * Wireshark’s `I/O Graph` window doesn’t distinguish between missing and zero values. For scatter plots it is assumed that zero values indicate missing data, and those values are omitted. Zero values are shown in line graphs, and bar charts.
* `RTT (Round Trip Time` Graph
    * The RTT (Round Trip Time) Graph tracks the time between data being transmitted and the associated TCP ACK.
* `Throughput Graphs` 
    * Throughput graphs are unidirectional and plot the total amount of bytes seen in the trace.
* `TCP Time-Sequence}`
    * TCP Time-Sequence Graphs are unidirectional and plot the individual TCP packets based on the TCP sequence number changes over time. In addition, this graph type depics the ACKs seen and the window size. In a smooth data transfer process, the "I bar line" goes from the lower left corner to the upper right corner along a smooth path.
> Likely causes of empty graphs is that you have selected a packet travelling in the wrong trafic direction before building a graph which is unidirectional-based.

* `Multiple Files - Ring Buffer]` [Capture Mode](https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFiles.html) can be used to limit the maximum disk usage by keeping the latest captured data
> Much like “Multiple files continuous”, reaching one of the multiple files switch conditions (one of the “Next file every …​” values) will switch to the next file. This will be a newly created file if value of “Ring buffer with n files” is not reached, otherwise it will replace the oldest of the formerly used files (thus forming a “ring”).
> This mode will limit the maximum disk usage, even for an unlimited amount of capture input data, only keeping the latest captured data.

* Wireshark IO Graphs support **"Copying to CSV Format"**
`Wireshark Advanced IO Graph {Calc} Functions`
| Function | Description
| ------ | ------ |
| `SUM(*)` | Adds up and plots the value of a field for all instances in the tick interval
| `MIN(*)` | Plots the minimum value seen for that field in the tick interval
| `AVG(*)` | Plots the average value seen for that field in the tick interval
| `MAX(*)` | Plots the maximum value seen for that field in the tick interval
| `COUNT(*)` | Counts the number of occurrences of the field seen during a tick interval **(Best for graphing the frequency of tcp.analysis.retransmission packets)**
| `LOAD(*)` | Used for response time graphs

### `{Wireshark Command Line Tools}`

* `Tshark`'s primary purpose is to offer command line packet capture and preferred over Wireshark GUI as it uses fewer resources. It can also be used with the **-z** parameter to gather information about protocol and application statistics.
* `tcpdump` uses fewer system resources than Tshark but does not offer as many capture configuration options
* `Capinfos.exe` Prints information about trace files (display capture duration, end/start times, average data rate in bytes, average packet size etc.) Capinfos.exe will not display information about protocol and application statistics
* `Editcap` Can be used to edit a trace filter such as split the filter, merge traces, alter trace file timestamp, remove duplicates etc... Useful for amending timestamp of two traces to a common timestamp, then merging for easier analysis and comparing contents in their IO graphs
* `Text2pcap` Generates a trace file from an ASCII hex dump of packets ... `{$ text2pcap plain.txt plain.pcapng}` .. Prepends dummy headers if not in the plain-text hex file
* `Dumpcap` Captures network packets and saves them into a libpcap format and is the capture engine for Tshark, uses fewer resources than Tshark.
* `Rawshark` expects raw libpcap packet headers, followed by packet data and makes no assumptions about the encapsulation or input format (like Tshark)

### `EOF`
