#!/bin/bash
# bytes-in-flight.sh begins on the previous line
#
# This macro finds the bytes in flight after an ACK is sent. Basically how
# many bytes does the ACK leave outstanding. This is slightly different
# from what Wireshark does. Wireshark shows the bytes in flight from when
# a packet is sent. For example if there are no outstanding bytes and the
# sender sends 32,000 bytes (we can assume TCP offloading) Wireshark will
# shows 32,000 bytes in flight. If a series of ACKs acks all bytes and then
# then sender sends another 32,000 bytes Wireshark will again show 32,000
# bytes in flight. At no point will it show 0 bytes in flight. I think
# this is misleading since you cannot see that the receiver is sending
# multiple ACKs and the bytes in flight is going down to zero and then the
# sender sends more data. 
#
# The data probably makes more sense when the trace is captured on the sender
#
# Version 1.0 February 4, 2017
BYTESINFLIGHTVERSION="1.0_2017-02-04"
#
# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git

if [ $# -ne 7 ]
   then echo "Usage:"
        echo "   bytes-in-flight.sh FILE SND-IP SND-PORT DST-IP DST-PORT \
                   TSHARK-FILTER OUTPUT-FILE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "      SND-IP is the IP address of the host sending data"
        echo "      SND-PORT is the TCP Port number sending data"
        echo "      DST-IP is the IP address of the host receiving data"
        echo "      DST-PORT is the TCP Port number receiving data"
        echo "      OUTPUT-FILE is the name of the output file"
        echo "      TSHARK-FILTER is the filter clause including the \
-Y or -R "
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
# number, the TCP length, and ACK number, relative time and frame number.
# The frame number is to make it easy to go back in the trace and find
# frames that correspond to areas of interest
 
tshark -r $FILE -Y "(ip.addr eq $SNDIP and ip.addr eq $DSTIP) and \
       (tcp.port eq $SNDPORT and tcp.port eq $DSTPORT)" -T fields \
       -e ip.src  -e tcp.seq -e tcp.len -e tcp.ack -e tcp.time_relative \
       -e frame.number >/tmp/bytes-in-flight.out

# For each line output, if the source IP matches the SND-IP print the
# source IP and the sum of the TCP sequence number and the TCP length.
# You cannot just output tcp.nxtseq since if there is no data that 
# field is not printed and you send up with rows with different numbers
# of columns. You can parse this arrangement of data but it seemed
# easier to do it this way. If the IP does not match SND-IP print the
# source IP and the ACK number. In either case also print the relative
# time and frame number.

awk -v sndip=$SNDIP '{if ($1 == sndip) print $1 " " $2+$3 " " $5 " " $6; \
                                  else print $1 " " $4 " " $5 " " $6}' \
     /tmp/bytes-in-flight.out > /tmp/bytes-in-flight-2.out

# For each line, if the entry matches SNDIP read the fields in the entry
# and save the sequence number as sendersequence -- if the sequence value
# is greater than the previous sendersequence value. If the entry is not
# SNDIP then output the relative time, sendersequence, sequence, the
# difference between sendersequence and sequence and the frame number.

echo "" > $OUTPUT
sendersequence=0
cat /tmp/bytes-in-flight-2.out | while read senderip sequence reltime framenumber; do
    if [ $senderip == "$SNDIP" ]
      then
        if [ $sequence -gt $sendersequence ]
           then
             sendersequence=$sequence
        fi
      else
        echo $reltime " " $sendersequence " - " $sequence " = " \
             $(($sendersequence - $sequence)) "    " $framenumber >> $OUTPUT
    fi
done

# clean up temporary files
rm /tmp/bytes-in-flight.out
rm /tmp/bytes-in-flight-2.out

# You can no manipulate the bytes in flight (column 6) however you want.
# You can graph bytes in flight over time, assuming you have installed
# gnuplot, with the plot commands below

# echo "set term x11 persist; plot \"$OUTPUT\" using 1:6" | gnuplot

