analyze-arps.sh
===============
Analyze the ARP packets in a trace file. Calculates the ARP response time and idenifies ARP requests with no replies, gratuitous ARPs, duplicate IPs and duplicate MACs. See [analyze-arps.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/analyze-arps.sh.html).

average.sh
==========
Average a value returned by tshark. See [average.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/average.sh.html).

build-filter.sh
===============
Builds a tshark filter by ANDing or ORing the values in a list with a tshark variable. See [build-filter.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/build-filter.sh.html).

bytes-in-flight.sh
==================
Calcuate the bytes in flight after each ACK. See [bytes-in-flight.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/bytes-in-flight.sh.html).

dns-time.sh
===========
Create a table of DNS server query response times and list of unanswered queries. See [bytes-in-flight.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/dns-time.sh.html).

failed-connection-attempts.sh
=============================
Find TCP connection attempts that have a failed. There are 6 failure scenarios, See [failed-connection-attempts.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/failed-connection-attempts.sh.html).

find-ips.sh
===========
Uses egrep to list all strings in a file that match an IPv4 address format and the sort -u to get a unique list. Really just a one-liner by this way I do not have to remember (or type) the egrep string. Its useful with build-filter.sh to create a filter to display all the IPs listed in say a log file. See [find-ips.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/find-ips.sh.html).

find-mangled-sequence-numbers.sh
================================
Analyze a packet trace for packets where the sequence number in the ACK field does not match the sequence numbers in the selective acknowledgement blocks. See [find-mangled-sequence-numbers.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/find-mangled-sequence-numbers.sh.html).

find-reset-connections.sh
=========================
Find TCP connections that have been reset without being closed. See [find-reset-connections.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/find-reset-connections.sh.html).


find-retran-failures.sh
=======================
Find TCP connections that appear to have failed because of retransmission failures. See [find-retran-failures.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/find-retran-failures.sh.html).

fix-pcap.sh
===========
Removes a partial packet at the end of a packet trace file. See [fix-pcap.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/fix-pcap.sh.html).

local-drops.sh
==============
For each retransmitted TCP segment determine if the segment is seen more than once. See [local-drops.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/local-drops.sh.html).

packet-matcher-faster.sh
========================
Compares IP ID and absolute TCP sequence and ACK numbers between two traces to match up TCP segments where the IP addresses and or TCP have been changed (i.e. NAT). See [packet-matcher-faster.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/packet-matcher-faster.sh.html).

packet-matcher.sh
=================
Extracts byte strings from a TCP stream in a template trace and looks for the strings in a target trace. The goal is to find a match TCP stream in the target trace file. See [packet-matcher.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/packet-matcher.sh.html).

percent-retransmissions.sh
==========================
For every connection in the trace file calculate the percentage of retransmissions for every source IP address as retransmissions / not-retransmitted source segments. segments must contain data, i.e.will not identify retransmitted SYNs or FINs without data. See [percent-retransmissions.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/percent-retransmissions.sh.html).

ping-time.sh
===============
Send an ICMP echo request (ping) with a 16 character time stamp (HH:MM:SS.sssssssss) embedded in it instead of the standard sequence of ascii characaters. See [ping-time.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/ping-time.sh.html).


ping-message.sh
===============
Send an ICMP echo request (ping) with a 16 character message embedded in it instead of the standard sequence of ascii characaters. See [ping-message.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/ping-message.sh.html).

split-pcap.py
=============
Reads X.pcap and creates a set of X.pcap_IP1-Port1_IP2-Port2_split.pcap files, one for each TCP four-tuple. Reads only pcap files not pcapng. Requires Python and the scapy module. See [split-pcap.py.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/split-pcap.py.html).

start-packet-tracing.sh
=======================
Runs tcpdump in the background with 10 files of 100 Meg each. See [start-packet-tracing.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/start-packet-tracing.sh.html).

stream-throughput.sh
====================
Calculate the throughput of all TCP streams in a trace file. See [stream-throughput.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/stream_throughput.sh.html).

throughput-per-sec.sh
=====================
Calculate throughput per second of a specific stream at resolutions of 1, 1/10, 1/100, and 1/1000 of a second. results are suitable for graphing. See [throughput-per-sec.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/throughput-per-sec.sh.html).

time-summary.sh
===============
Finds all files in the current directory and any sub directories and displays then start and end times in sorted order. See [time-summary.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/time-summary.sh.html).

unterminated-connections.sh
===========================
Find TCP connections that have not been closed or reset. See [unterminated-connections.sh.html](http://htmlpreview.github.com/?https://github.com/noahdavids/packet-analysis/blob/master/unterminated-connections.sh.html).

