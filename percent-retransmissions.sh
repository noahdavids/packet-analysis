#!/bin/bash
# percent-retransmissions.sh begins on the previous line

# This macro uses tshark to calculate the percentage of retransmitted packets
# in a packet trace. Calculation is based on the soutrce IP address and
# tshark stream number. The calculation is the number of retransmitted segments
# containing data from a given IP address in a given TCP stream divided by the
# number of not retransmitted segments containing data from that host in that
# stream.

# Note that this will not count retransmitted SYN or FIN segments unless they
# contain data.

# Output has the format
# Stream Src-IP:Port Dst-IP:Port TTL retran / not-retran percentage

# One line for each source stream/4-tuple. The TTL is to given so you 
# some idea if the segments originated locally or remotely

# If the only thing printed is the command and file name it means that the 
# packet tracefile did not contain any retransmitted segments containing data.


# Version 1.0 May 29, 2017
# Version 1.1 June 1, 2017
#   changed so that there is only 1 pass through the file with tshark instead 
#   of 1+N passes where N is the number of Streams/4-tuples with 
#   retransmissions

PERCENTRETRANSMISSIONS="1.1_2017-06-01"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

if [ $# -ne 1 -a $# -ne 2 ]
   then echo "Usage:"
        echo "   percent-retransmissions.sh FILE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "Example:"
        echo "   percent-retransmissions.sh trace.pcap"
        exit
fi

FILE="$1"

CSV="$2" 

if [ ! -e $FILE ]
   then echo "Could not find input file $FILE"
   exit
fi

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# I always echo the command and arguments to STDOUT as a sanity check

echo percent-retransmissions.sh "$FILE"

# Find all data segments and display the TCP Stream, source IP, source port,
# TTL, destination IP and destination port and retransmission flag
# -- NOTE -- that this will not find SYN or FIN segments without data
# sort and then count them and write the results to a temporary file -1

tshark -r $FILE -Y "tcp.len > 0" -T fields -e tcp.stream \
          -e ip.src -e tcp.srcport -e ip.ttl -e ip.dst -e tcp.dstport \
          -e tcp.analysis.retransmission -e tcp.analysis.out_of_order | sort | uniq -c \
          > /tmp/percent-retransmissions-1

# scan temporary file for retransmissions (column 8 > 0) and write those lines
# to temporary file -2

awk '($8 > 0) {print $0}' /tmp/percent-retransmissions-1 > \
     /tmp/percent-retransmissions-2


# For each line in temporary file -2 find the lines in temporary file -1 that
# match all the fields except the count and retransmission flag. There will
# always be two lines since there has to be at least 1 un-retransmitted line.
# combine those two lines into 1 line and write temporary file -3

cat /tmp/percent-retransmissions-2 | \
   while read count stream sip sp ttl dip dp retran; do 
     egrep "$stream\s*$sip\s*$sp\s*$ttl\s*$dip\s*$dp" \
        /tmp/percent-retransmissions-1 | awk 1 ORS=' ' ; echo; done > \
        /tmp/percent-retransmissions-3

cat /tmp/percent-retransmissions-3 | uniq > /tmp/percent-retransmissions-4

# Finally, for each line in temporary file -3 extract out the not-retransmitted
# count, the TCP stream source IP/port and destination IP/port, the TTL and the
# retransmission count and write a formated line showing that and the calcuated
# retransmission percentage

if [ -z $CSV ]
then
awk '{print "Stream: " $2 " " $3 ":" $4 " -> " $6 ":" $7 " " \
         " retrans+out_of_order " $8+$16 "/" $1 " "  ($8+$16)/$1*100 \
         " retrans " $16 "/" $1 " " $16/$1*100  \
         " out_of_order " $8 "/" $1 " " $8/$1*100}' /tmp/percent-retransmissions-4
else
echo "Stream,Server,Client,TotalPackets,%retrans_out_of_order,count_retrans_out_of_order,%Retrans,count_retrans,%out_Of_order,count_out_of_order"
awk '{print  $2 "," $3 ":" $4 "," $6 ":" $7 "," $1 "," \
         ($8+$16)/$1*100 "," $8+$16 "," \
         $16/$1*100 "," $16 "," \
         $8/$1*100 "," $8 }' /tmp/percent-retransmissions-4
fi


#
# percent-retransmissions.sh ends here
