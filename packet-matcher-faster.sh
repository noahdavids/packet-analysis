#!/bin/bash
# packer-matcher-faster.sh begins on the previous line
#
# This macro searches for TCP packets in one file that match packets in
# another file. It is useful when NAT has changed the IP addresses and or
# port numbers. It uses the combination of IP ID and absolute sequence
# and ACK numbers as the key.
#
# Output is the matching pairs of tshark output, one from each file. This
# this is a slow process since each file must be searched for each
# id-sequence-number-ack-number key. Since the typical goal is just to
# identify the matching streams you can limit this to just a subset (like 1)
# of matching segments.
#
# Note that the packets are not printed in order. They are sorted by
# id-seq-ack number so typically all the packets from one IP address will 
# print out first. Which direction is printed first will be random and if the
# connection goes on for more than 64K packets or a host is very busy and the
# IP ID values cycle the order can change and later packets from one host may
# be printed before ealier packets from the same host.

# If the script finds more than 2 matches per key it assumes some packets
# are duplicated. This would generate false positives so the script prints
# the key values so you can investigate and aborts the matching phase. 

# This is packet-matcher-faster because it is faster than packet-matcher. But
# packet-matcher looks at actual data contents so it can match packets
# through proxies or other middleware boxes where the entire TCP header is
# changed.

# Version 1.0 September 10, 2017
# Version 1.1 September 17, 2017
#   Cleaned up some comments, added some comments and added a message if
#   no matches are found

PACKETMATCHERFASTVERSION="1.1_2017-09-15"

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
        echo "   packet-match-faster.sh FILE1 FILTER FILE2 COUNT"
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

if [ ! -f $FILE1 ]
   then echo "Could not find input file $FILE1"
   exit
fi

if [ ! -f $FILE2 ]
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
# FILE1 that matches the filter. Write the values to a temporary -1 file with
# dashs between the values instead of spaces

rm -f /tmp/packet-matcher-faster-1
tshark -r $FILE1 $DASH "$FILTER" \
               -T fields -e ip.id -e tcp.seq -e tcp.ack \
               -o tcp.relative_sequence_numbers:FALSE | \
        while read id seq ack; do echo $id-$seq-$ack; done > \
               /tmp/packet-matcher-faster-1; 

# Remove enries with an ID of 0x0. SYN-ACKs and RESETS may not have an IP ID
# and retransmissions of these might therefore trigger a false positive
# for duplicated packets

rm -f /tmp/packet-matcher-faster-2
cat /tmp/packet-matcher-faster-1 | grep -v "0x00000000" | \
                              sort | uniq -c > /tmp/packet-matcher-faster-2

# If no segments are found report an error and exit

if [ $(cat /tmp/packet-matcher-faster-2 | wc -l) -eq 0 ]
   then echo "No segments in $FILE1 match $FILTER"
        echo "exiting now"
        exit
fi

# If any ID-SEQ-ACK shows up more than once at this point we may have
# duplicated packets so report an error and print the duplicated keys
# for investigation. You can use "editcap -d" to remove the duplicates

rm -f /tmp/packet-matcher-faster-3
cat /tmp/packet-matcher-faster-2 | awk '($1 > 1) {print $0}' > \
                                            /tmp/packet-matcher-faster-3
if [ $(cat /tmp/packet-matcher-faster-3 | wc -l) -gt 0 ]
   then echo "Presence of more than 2 matches per id-seq-ack in"
        echo $FILE1
        echo "possible duplicate packets in trace - remove duplicates"
        echo "with \"editcap -d\" before proceeding"
        echo "list of duplicated id-seq-ack keys can be found in"
        echo "/tmp/packet-matcher-faster-3"
        exit
fi

# Extract the IP ID, TCP sequence and ACK numbers from each TCP segment in
# FILE2.

rm -f /tmp/packet-matcher-faster-4
tshark -r $FILE2 $DASH "tcp" -T fields -e ip.id -e tcp.seq -e tcp.ack \
               -o tcp.relative_sequence_numbers:FALSE | \
        while read id seq ack; do echo $id-$seq-$ack; done >> \
               /tmp/packet-matcher-faster-4


# Remove enries with an ID of 0x0 (again)

rm -f /tmp/packet-matcher-faster-5
cat /tmp/packet-matcher-faster-4 | grep -v "0x00000000" | \
                              sort | uniq -c > /tmp/packet-matcher-faster-5

# If no segments are found report an error and exit

if [ $(cat /tmp/packet-matcher-faster-5 | wc -l) -eq 0 ]
   then echo "Nothing to match on in $FILE2"
        echo "exiting now"
        exit
fi

# test for duplicates again

rm -f /tmp/packet-matcher-faster-6
cat /tmp/packet-matcher-faster-5 | awk '($1 > 1) {print $0}' > \
                                            /tmp/packet-matcher-faster-6
if [ $(cat /tmp/packet-matcher-faster-6 | wc -l) -gt 0 ]
   then echo "Presence of more than 2 matches per id-seq-ack in"
        echo $FILE2
        echo "possible duplicate packets in trace - remove duplicates"
        echo "with \"editcap -d\" before proceeding"
        echo "list of duplicated id-seq-ack keys can be found in"
        echo "/tmp/packet-matcher-faster-6"
        exit

fi

# Finally we can do real work. For each IP-SEQ-ACK that occurs twice
# (presumably once in each trace). Print the packet. This part is the slow
# part since each packet trace file is scanned completely for each ID-SEQ-ACK.
# Therefore stop after COUNT segment pairs are displayed. Write the packets
# to the temporary-7 file

SHOWN=0

rm -f /tmp/packet-matcher-faster-7
cat /tmp/packet-matcher-faster-2 /tmp/packet-matcher-faster-5 | sort | \
    uniq -c | awk '($1 == 2) {print $3}' | tr "-" " " | while read id seq ack
    do
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
   done > /tmp/packet-matcher-faster-7

# If the previous step produced no output indicate that no matches were
# found otherwise just dump the output file

if [ $(cat /tmp/packet-matcher-faster-7 | wc -l) -eq 0 ]
   then
       echo No matches found between $FILE1 and $FILE2
   else cat /tmp/packet-matcher-faster-7
fi

