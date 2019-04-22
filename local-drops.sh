#!/bin/bash
# local-drops.sh begins on the previous line
#
# This macro uses tshark to make 2N+1 passes through a file. The first pass
# identifies all retransmitted TCP segments and extracts the starting sequence
# number from those segments. Then for each identified segment it finds all
# segments which include the starting sequence number. It then finds the first
# ACK for that sequence number.
#
# If this macro is run over a trace that was captured on the receiving host 
# we can see if the original segment was seen and if so if an ACK was sent. If
# this macro is run over a trace that was captured in the sending host
# we can see if an ACK was received before the retransmitted segment was sent
#
# The Output file has the format
#     TCP Seq NNNNNNN Pattern: PPPPPP
#     Titles
#     frame.number tcp.time_relative ip.src ip.ttl ip.dst tcp.seq tcp.ack tcp.nxtseq
#     frame.number tcp.time_relative ip.src ip.ttl ip.dst tcp.seq tcp.ack tcp.nxtseq
#     frame.number tcp.time_relative ip.src ip.ttl ip.dst tcp.seq tcp.ack tcp.nxtseq
#
# Multiple frames from the sending IP indicate that the frame was received (or
# sent) multiple times. The placement of the ACK from the receiving IP indicates
# when the ACK was sent.
#
# The pattern string PPPPPP represents the pattern of segments.
#    D-A-   would indicate the first segment is data followed by an ACK
#    D-D-A- would be data, data again and then an ACK
#    D-A-D- would be data and ack and then data again. We do not see the second ACK
#           because only the first ACK is recorded.
# Counting the unique patterns will give you an idea of the segment loss pattern
#
# If the input file is large with many TCP streams it would make sense to first
# create a file containing just the segments of the TCP stream of interest
#
# If there are enough segments that the sequence numbers wrap and are reused
# this will probably result in false positives (or negatives, it depends
# on your point of view). If this is the case the trace file should be broken
# up so that the sequence number spacve is mnot reused. Note that a sequence
# number wrap is OK, it is when it wraps and proceeds past where it originally
# started that things get messy.

# Version 1.0 Jan 1 2017
# Version 1.1 Jan 1 2017
#    Modified to include the ACK packets
# Version 1.2 Apr 1 2017
#    Added copyright and GNU GPL statement and disclaimer
# Version 1.3 May 15 2017
#    Have the script figure out to use -Y or -R in tshark command. Also sort
#    unique the retranmitted sequence numbers so we do get get duplicated
#    output if the sequence number is retransmitted multiple times.
# Version 1.4 June 28, 2017
#    Added the Pattern string 
# Version 1.5 July 23, 2017
#    Added IP TTL to the output
# Version 1.6 April 20, 2019
#    Added a title line listing the columns
#    Redirect broken pipe errors caused by piping tshark output to head to
#    /dev/null

LOCALDROPSVERSION="1.6_2019-04-20"

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
        echo "   local-drops.sh FILE SRC-ADDR TCP-PORT TSHARK-FILTER OUTFILE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "      SRC-ADDR is the IP address of the sender of the packets"
        echo "         Note: Trace should have been captured on the receiver"
        echo "               for this analysis to be useful"
        echo "      TCP-PORT is the client side TCP Port number, it may belong"
        echo "         to the sender or receiver, it is used to make sure that"
        echo "         only 1 connection is analyzed. (It assumes there is no"
        echo "         port reuse"
        echo "      OUTFILE is the name of the output file"
        echo "Example:"
        echo "   local-drops.sh trace.pcap 192.168.1.3 45673 local-drops.out"
        exit
fi

FILE=$1
IPSRC=$2
PORT=$3
OUTFILE=$4

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

# I'm checking to make sure the port argument is a number but
# not for the maximum port value, Tshark will do that.

if [[ ! $PORT =~ ^[0-9]+$ ]]
   then echo "$PORT should be a port number > 0 and <= 65535"
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

echo local-drops.sh $FILE $IPSRC $PORT $OUTFILE

# Also echo the command, arguments, date and version to the output file

echo local-drops.sh $FILE $IPSRC $PORT $OUTFILE > $OUTFILE
echo local-drops.sh run on $(date) >> $OUTFILE
echo local-drops.sh version $LOCALDROPSVERSION >> $OUTFILE
echo >> $OUTFILE


tshark -r $FILE $DASH "ip.src == $IPSRC && tcp.port == $PORT && \
   tcp.analysis.retransmission" -T fields -e tcp.seq \
   -o tcp.relative_sequence_numbers:FALSE | sort -u > /tmp/local_drops_retrans

NUMBERRETRANS=$(wc -l /tmp/local_drops_retrans | awk '{print $1}')
echo Numer of retransmission $NUMBERRETRANS >> $OUTFILE
echo >> $OUTFILE

cat /tmp/local_drops_retrans | while read x
do

   tshark -r $FILE -o tcp.relative_sequence_numbers:FALSE \
                   -o tcp.calculate_timestamps:TRUE \
       $DASH "ip.src == $IPSRC && tcp.port == $PORT && tcp.seq <= $x \
       && $x < tcp.nxtseq" -T fields -e frame.number -e tcp.time_relative \
       -e ip.src -e ip.ttl -e ip.dst -e tcp.seq -e tcp.ack -e tcp.nxtseq \
       > /tmp/local_drops_frames

   tshark -r $FILE -o tcp.relative_sequence_numbers:FALSE \
                   -o tcp.calculate_timestamps:TRUE \
       $DASH "ip.dst == $IPSRC && tcp.port == $PORT && tcp.ack > $x" \
       -T fields -e frame.number -e tcp.time_relative -e ip.src -e ip.ttl \
       -e ip.dst -e tcp.seq -e tcp.ack -e tcp.nxtseq 2>/dev/null | head -1 \
       >> /tmp/local_drops_frames


   cat /tmp/local_drops_frames | sort -nk1 > /tmp/local_drops_frames-2

   echo TCP Seq: $x Pattern: $(cat /tmp/local_drops_frames-2 | awk -v ipsrc=$IPSRC \
            '{ if ($3 == ipsrc) print "D"; else print "A"}' | tr "\n" "-") >> $OUTFILE
   (echo Frame.num tcp.time.rel ip.src ip.ttl ip.dst tcp.seq tcp.ack tcp.nxtseq
   cat /tmp/local_drops_frames-2) | column -t >> $OUTFILE
   echo >> $OUTFILE

done

rm /tmp/local_drops_retrans
rm /tmp/local_drops_frames
rm /tmp/local_drops_frames-2

# local-drops.sh ends here

