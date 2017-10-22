average.sh
==========
Average a value returned by tshark. See [average.sh.html](https://github.com/noahdavids/packet-analysis/blob/master/average.sh.html/).

bytes-in-flight.sh
==================
Calcuate the bytes in flight after each ACK. See [bytes-in-flight.sh.html](https://github.com/noahdavids/packet-analysis/blob/master/bytes-in-flight.sh.html/).

dns-time.sh
Create a table of DNS server query response times and list of unanswered queries. See [bytes-in-flight.sh.html](https://github.com/noahdavids/packet-analysis/blob/master/dns-time.sh.html/).

failed-connection-attempts.sh
=============================
find TCP connection attempts that have a failed. There ae 6 failure scenarios, see the comments for a description.

find-ips.sh
===========
uses egrep to list all strings in a file that match an IPv4 address format and the sort -u to get a unique list. Really just a one-liner by this way I do not have to remember (or type) the egrep string.

find-reset-connections.sh
=========================
find TCP connections that have been reset without being closed.

fix-pcap.sh
===========
removes a partial packet at the end of a packet trace file.

local-drops.sh
==============
For each retransmitted TCP segment determine if the segment is seen more than once

packet-matcher.sh
=================
Extracts byte strings from a TCP stream in a template trace and looks for the strings in a target trace. The goal is to find a match TCP stream in the target trace file

packet-matcher-faster.sh
========================
Compares IP ID and absolute TCP sequence and ACK numbers between two traces to match up TCP segments where the IP addresses and or TCP have been changed (i.e. NAT)

percent-retransmissions.sh
==========================
For every connection in the trace file calculate the percentage of retransmissions for every source IP address as retransmissions / not-retransmitted source segments. segmenst must contain data, i.e.will not identifiy retransmitted SYNs or FINs without data.

split-pcap.py
=============
Reads X.pcap and creates a set of X.pcap_IP1-Port1_IP2-Port2_split.pcap files, one for each TCP four-tuple. Reads only pcap files not pcapng. Requires Python and the scapy module.

start-packet-tracing.sh
=======================
runs tcpdump in the background with 10 files of 100 Meg each. 

stream-throughput.sh
====================
calculate the throughput of all TCP streams in a trace file

throughput-per-sec.sh
=====================
Calculate throughput per second of a specific stream at resolutions of 1, 1/10, 1/100, and 1/1000 of a second. results are suitable for graphing.

time-summary.sh
===============
finds all files in the current directory and any sub directories and displays then start and end times in sorted order.

unterminated-connections.sh
===========================
find TCP connections that have not been closed or reset

