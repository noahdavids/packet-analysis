#!/bin/bash
# bytes-in-flight.sh begins on the previous line
#
# This macro finds the bytes in flight after each segment. Basically how
# many bytes are unACKed. This is slightly different from what Wireshark
# does. Wireshark shows the bytes in flight from when a packet is sent.
# For example if there are no outstanding bytes and the sender sends
# 32,000 bytes (we can assume TCP offloading) Wireshark will show 32,000
# bytes in flight. If a series of ACKs acks all bytes and then the sender
# sends another 32,000 bytes Wireshark will again show 32,000 bytes in flight.
# At no point will it show 0 bytes in flight. I think this is misleading
# since you cannot see that the receiver is sending multiple ACKs and the
# bytes in flight is going down to zero and then the sender sends more data.
# It also calculates the avialble window by subtracting the bytes in flight 
# from the last window receivied.
#
# The data probably makes more sense when the trace is captured on the sender
#
# Version 1.0 February 4, 2017
# Version 1.1 February 16, 2017
#    swapped TSHARK-FILTER and OUTPUT-FILE is the usage message and  added
#    "not tcp.flags.syn == 1" to filter out the SYN segment because tshark
#    does not include tcp.len in the SYN segment so that segment is short a
#    field which screws everything up. Also changed display to show after
#    the sender sends data so if there are multiple sends without an ACK you
#    can see the bytes in flight go up. Added the available window calculation
#    which is the last window minus the bytes in flight
# Version 1.2 April 1, 2017
#    Added copyright and GNU GPL statement and disclaimer
#
BYTESINFLIGHTVERSION="1.2_2017-04-01"
#
# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

if [ $# -ne 7 ]
   then echo "Usage:"
        echo "   bytes-in-flight.sh FILE SND-IP SND-PORT DST-IP DST-PORT \
                   TSHARK-FILTER OUTPUT-FILE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "      SND-IP is the IP address of the host sending data"
        echo "      SND-PORT is the TCP Port number sending data"
        echo "      DST-IP is the IP address of the host receiving data"
        echo "      DST-PORT is the TCP Port number receiving data"
        echo "      TSHARK-FILTER is the filter clause including the \
-Y or -R "
        echo "      OUTPUT-FILE is the name of the output file"
        exit
fi

FILE=$1
SNDIP=$2
SNDPORT=$3
DSTIP=$4
DSTPORT=$5
FILTER=$6
OUTPUT=$7

if [ ! -e $FILE ]
   then echo "Could not find input file $FILE"
   exit
fi

# I'm not checking the individual octets, that is more complicated than I
# want and Tshark will report an error. This will just make sure that the
# format is correct, i.e. ddd.ddd.ddd.ddd

if [[ ! $SNDIP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
   then echo "$SNDIP is not a valid IP Address"
   exit
fi

if [[ ! $DSTIP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
   then echo "$DSTIP is not a valid IP Address"
   exit
fi

if [ $FILTER != "R" -a $FILTER != "Y" ]
   then echo "Filter string must be either R or Y, $FILTER is not allowed"
   exit
fi

# I always echo the command and arguments to STDOUT as a sanity check

echo bytes-in-flight.sh $FILE $SNDIP $SNDPORT $DSTIP $DSTPORT $FILTER $OUTPUT


# Filter the trace file for connections matching the SND-IP, SND-PORT,
# DST-IP, DST-PORT and output the source IP address, TCP sequence
# number, the TCP length, and ACK number, relative time window size and
# frame number. The frame number is to make it easy to go back in the
# trace and find frames that correspond to areas of interest
 
tshark -r $FILE -Y "(ip.addr eq $SNDIP and ip.addr eq $DSTIP) and \
       (tcp.port eq $SNDPORT and tcp.port eq $DSTPORT) \
       and not tcp.flags.syn == 1" -T fields \
       -e ip.src  -e tcp.seq -e tcp.len -e tcp.ack -e tcp.time_relative \
       -e tcp.window_size -e frame.number >/tmp/bytes-in-flight.out

# For each line output, if the source IP matches the SND-IP print the
# source IP and the sum of the TCP sequence number and the TCP length.
# You cannot just output tcp.nxtseq since if there is no data that 
# field is not printed and you send up with rows with different numbers
# of columns. You can parse this arrangement of data but it seemed
# easier to do it this way. If the IP does not match SND-IP print the
# source IP and the ACK number. In either case also print the relative
# time and frame number. Also if the IP matches the sender we do not care
# about the window size so just use an X. 

awk -v sndip=$SNDIP '{if ($1 == sndip) print $1 " " $2+$3 " " $5 " X " $7; \
                                  else print $1 " " $4 " " $5 " " $6 " " $7}' \
     /tmp/bytes-in-flight.out > /tmp/bytes-in-flight-2.out

# For each line, if the entry matches SNDIP read the fields in the entry
# and save the sequence number as sendersequence -- if the sequence value
# is greater than the previous sendersequence value. If the entry is not
# SNDIP then save the sequnce number as acksequence. ACK numbers do not
# go down so no need to test for that. There will be a discontinuity when
# seqence numbers wrap. Also if it is not the sender then save the window as
# lastwindow. Then output the relative time, sendersequence, acksequence,
# the difference between sendersequence and acksequence and the difference
# between the lastwindow and difference between the sendersequence and the
# acksequence. This is the bytes left in the window. Finally include the
# frame number.
#
echo "" > $OUTPUT
sendersequence=0
acksequence=0
lastwindow=0
cat /tmp/bytes-in-flight-2.out | while read senderip sequence reltime \
                                                      window framenumber; do
    if [ $senderip == "$SNDIP" ]
      then
        if [ $sequence -gt $sendersequence ]
           then
             sendersequence=$sequence
        fi
      else
        acksequence=$sequence
        lastwindow=$window
    fi
    echo $reltime " " $sendersequence " - " $acksequence " = BIF: " \
             $(($sendersequence - $acksequence)) "    " $lastwindow  \
             " Avail-Window: " \
             $(($lastwindow - ($sendersequence - $acksequence))) " " \
             $framenumber >> $OUTPUT
done

# clean up temporary files
rm /tmp/bytes-in-flight.out
rm /tmp/bytes-in-flight-2.out

# You can no manipulate the bytes in flight (column 6) however you want.
# You can graph bytes in flight over time, assuming you have installed
# gnuplot, with the plot commands below

# echo "set term x11 persist; plot \"$OUTPUT\" using 1:6" | gnuplot
#
# bytes-in-flilght.sh ends here

