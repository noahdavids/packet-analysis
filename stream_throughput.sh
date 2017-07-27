#!/bin/bash
# stream_throughput.sh begins on the previous line
#
# This macro uses tshark to make N+1 passes through a file. The first pass
# identifies all TCP streams. Then for each stream it calculates the throughput
# from the last frame's ACK number and dividing by the TCP relative time.
# Reset frames are excluded since they do not always carry an ACK number.
#
# The Output file has the format
#    TCP Stream: N IPSRC:PORTSRC -> IPDST:PORTDST   ACK / TIME = THROUGHPUT Bytes/Sec
#
# If the input file is large with many TCP streams it would make sense to first
# create a file containing just the segments of the TCP stream of interest,
# assuming you are not interested in all the streams.
#
# If there are enough segments that the sequence numbers wrap and are reused
# this macro cannot be used.
#
# This also does not consider any bytes ACKed via Selective Acknowledgment
# blocks. 
#
# Version 1.0 Jan  2 2017
# Version 1.1 Feb 28 2017
#    Correct message at start to display the IPSRC argument, it was just
#    missing from the echo command
# Version 1.2 Mar 04 3017
#    Corrected the version environment variable from LOCALDROPSVERSION 
#    to STREAMTHROUGHPUTVERSION
# Version 1.3 Apr 1 2017
#    Added copyright and GNU GPL statement and disclaimer
# Version 1.4 Jul 26, 2017
#    Removed the TSHARK-FILTER argument and now automagically figure out
#    if "-Y" or "-R" is needed
#    Added test to report if no packets from source where found.

STREAMTHROUGHPUTVERSION="1.4_2017-07-26"
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

if [ $# -ne 3 ]

   then echo "Usage:"
        echo "   stream-throughput.sh FILE IPSRC TSHARK-FILTER OUTFILE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "      IPSRC is the IP address of the host sending the bytes"
        echo "         you wish to calculate the throughput for."
        echo "      OUTFILE is the name of the output file"
        echo "Example:"
        echo "   stream-throughput.sh trace.pcap stream-throughput.out"
        exit
fi

FILE=$1
IPSRC=$2
OUTFILE=$3

if [ ! -e $FILE ]
   then echo "Could not find input file $FILE"
   exit
fi

# I'm not checking the individual octets, that is more complicated than I
# want and Tshark will report an error. This will just make sure that the
# format is correct, i.e. ddd.ddd.ddd.ddd

if [[ ! $IPSRC =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
   then echo "$IPSRC is not a valid IP Address"
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

echo stream-throughput.sh $FILE $IPSRC $OUTFILE

# Also echo the command, arguments, date and version to the output file

echo stream-throughput.sh $FILE $IPSRC $OUTFILE > $OUTFILE
echo stream-throughput.sh run on $(date) >> $OUTFILE
echo stream-throughput.sh version $STREAMTHROUGHPUTVERSION >> $OUTFILE
echo >> $OUTFILE

# Even though the argument is IP SOURCE we are filtering on ip.dst in the
# Tshark commands because we are interested in the ACK values going back to
# the source.

tshark -r $FILE $DASH "ip.dst == $IPSRC" -T fields -e tcp.stream | sort -nu > /tmp/tcp_streams

if [ $(cat /tmp/tcp_streams | wc -l) -eq 0 ]
then echo "There are no acknowledgment packets going to the IP source address " $IPSRC " - exiting"
     echo "There are no acknowledgment packets going to the IP source address " $IPSRC " - exiting" >> $OUTFILE
     exit
fi
   

cat /tmp/tcp_streams | while read x
do
   echo -n "TCP Stream $x  " >> /tmp/tcp_streams_throughput
   tshark -r $FILE -o tcp.relative_sequence_numbers:TRUE \
                   -o tcp.calculate_timestamps:TRUE \
       $DASH "tcp.stream == $x && not tcp.flags.reset == 1 && \
                ip.dst == $IPSRC" \
       -T fields -e tcp.time_relative -e ip.src -e tcp.srcport -e ip.dst \
                 -e tcp.dstport -e tcp.ack | tail -1  > /tmp/tcp_a_stream
   cat /tmp/tcp_a_stream | while read time ipsrc srcport ipdst dstport ack
   do

# If the time is 0 skip the calcuation, either the throughput is infinite or
# more likely there are only a few frames so the stream is probably not of
# interest

     if [[ "$time" =~ [123456789] ]]

# The destination IP address and port number are to the left of the "->"
# because while the packet is going to the destination the ACK number is
# how many bytes the destination received so the ACK / Time value is the
# throughput going in the other direction, i.e. destination to source

        then t=$(echo "scale=6; ($ack / $time)" | bc); \
                echo -e $ipdst:$dstport "\t-> " $ipsrc:$srcport \
                "\t" $ack "/" $time " = " $t " Bytes/sec" \
                >> /tmp/tcp_streams_throughput
     fi
   done
done

cat /tmp/tcp_streams_throughput | column -t >> $OUTFILE

rm /tmp/tcp_streams
rm /tmp/tcp_a_stream
rm /tmp/tcp_streams_throughput

# stream_throughput.sh ends here

