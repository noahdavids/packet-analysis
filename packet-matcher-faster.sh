#!/bin/bash
# local-drops.sh begins on the previous line
#

# Version 1.0 September 10, 2017

PACKETMATCHFASTVERSION="1.0_2017-09-10"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

if [ $# -ne 4 ]
   then echo "Usage:"
        echo "   packet-match-fast.sh FILE1 FILTER FILE2 COUNT"
        echo "      FILE1 is the name of one file"
        echo "      FILTER is a tshark filter used to select packets from"
        echo "        FILE1"
        echo "      FILE2 is the name of the other file"
        echo "      limit the results to COUNT values, 0 implies no limit"
        exit
fi

FILE1=$1
FILTER="$2"
FILE2=$3
COUNT=$4

if [ ! -e $FILE1 ]
   then echo "Could not find input file $FILE1"
   exit
fi

if [ ! -e $FILE2 ]
   then echo "Could not find input file $FILE2"
   exit
fi

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# Extract the IP ID, TCP sequence and ACK numbers from each TCP segment in
# FILE1 that matches the filer. Write the values to a temporya -1 file with
# dashs between the values instead of spaces

tshark -r $FILE1 $DASH "$FILTER" \
               -T fields -e ip.id -e tcp.seq -e tcp.ack \
               -o tcp.relative_sequence_numbers:FALSE | \
        while read id seq ack time; do echo $id-$seq-$ack; done > \
               /tmp/packet-matcher-fast-1; 

# If no segments are found report an error and exit

if [ $(cat /tmp/packet-matcher-fast-1 | wc -l) -eq 0 ]
   then echo "No segments in $FILE1 match $FILTER"
        echo "exiting now"
        exit
fi

# Extract the IP ID, TCP sequence and ACK numbers from each TCP segment in
# FILE2.

tshark -r $FILE2 $DASH "tcp" -T fields -e ip.id -e tcp.seq -e tcp.ack \
               -o tcp.relative_sequence_numbers:FALSE | \
        while read id seq ack time; do echo $id-$seq-$ack; done >> \
               /tmp/packet-matcher-fast-1

# Remove enries with an ID of 0x0. SYN-ACKs and RESETS may not have an IP ID
# and retransmissions might therefore trigger a false positive

cat /tmp/packet-matcher-fast-1 | grep -v "0x00000000" | \
                                  sort | uniq -c > /tmp/packet-matcher-fast-2

# If there are more than 2 matches we might have duplicate packets which will
# screw up things up so list the IP-SEQ-ACK values and exit

cat /tmp/packet-matcher-fast-2 | awk '($1 > 2) {print $0}' > \
                                            /tmp/packet-matcher-fast-3
if [ $(cat /tmp/packet-matcher-fast-3 | wc -l) -gt 0 ]
   then echo "Presence of more than 2 matches per id-seq-ack, possible"
        echo "duplicate packets in trace - remove duplicates before proceeding"
        echo
        cat /tmp/packet-matcher-fast-3 | awk '($1 > 2) {print $0}' | sort -nk1
        exit
fi

# Finally we can do real work. For each IP-SEQ-ACK that occurs twice
# (presumably once in each trace). Print the packet. This part is slow since
# the each packet trace file is scanned completely for each ID-SEQ-ACK.
# Therefore stop after COUNT segment pairs are displayed

SHOWN=0

cat /tmp/packet-matcher-fast-2 | awk '($1 == 2) {print $2}' | tr "-" " " | \
   while read id seq ack; do
      echo ===================================================================
      echo $id $seq $ack
      echo $FILE1
      echo "     " $(tshark -r $FILE1 $DASH "ip.id == $id && \
          tcp.seq == $seq && tcp.ack == $ack" \
          -o tcp.relative_sequence_numbers:FALSE -tad)
      echo 
      echo $FILE2
      echo "     " $(tshark -r $FILE2 $DASH "ip.id == $id && \
           tcp.seq == $seq && tcp.ack == $ack" \
           -o tcp.relative_sequence_numbers:FALSE -tad)
      echo

      SHOWN=$((SHOWN+1))
      if [ $SHOWN -eq $COUNT ]
         then exit
      fi
   done


