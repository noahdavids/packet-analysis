#!/bin/bash
# local-drops.sh begins on the previous line
#
# This macro uses tshark to make N+1 passes through a file. The first pass
# identifies all retransmitted TCP segments and extracts the starting sequence
# number from those segments. Then for each identified segment it finds all
# segments which include the starting sequence number. The idea is to 
# determine if the original of a retransmitted segment was seen or not. 
#
# This should be run over a trace that was captured on the receiving host
#
# Output is in /tmp/foo and has the format
#     TCP Seq NNNNNNNN DD
# where
#   NNNNNNNN     is the sequence number
#   DD           is a count of the number of times the Sequence number was seen
#                   A count greater than 1 indicates that the containing
#                   segment was probably dropped locally -- or that the ACK was #                   sent and dropped.
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
LOCALDROPSVERSION="1.0_2017-01-01"

# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git

if [ $# -ne 5 ]
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
        echo "      TSHARK-FILTER is either Y or R depening on the release \
of Tshark"
        echo "      OUTFILE is the name of the output file"
        echo "Example:"
        echo "   local-drops.sh trace.pcap 192.168.1.3 45673 Y local-drops.out"
        exit
fi

FILE=$1
IPSRC=$2
PORT=$3
FILTER=$4
OUTFILE=$5

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

if [ $FILTER != "R" -a $FILTER != "Y" ]
   then echo "Filter string must be either R or Y, $FILTER is not allowed"
   exit
fi
# I always echo the command and arguments to STDOUT as a sanity check

echo local-drops.sh $FILE $IPSRC $FILTER $OUTFILE

# Also echo the command, arguments, date and version to the output file

echo local-drops.sh $FILE $IPSRC $FILTER $OUTFILE run on $(date) > $OUTFILE
echo local-drops.sh version $LOCALDROPSVERSION >> $OUTFILE
echo >> $OUTFILE


tshark -r $FILE -$FILTER "ip.src == $IPSRC && tcp.port == $PORT && tcp.analysis.retransmission" -T fields -e tcp.seq > /tmp/local_drops_retrans

NUMBERRETRANS=$(wc -l /tmp/local_drops_retrans | awk '{print $1}')
echo Numer of retransmission $NUMBERRETRANS >> $OUTFILE
echo >> /tmp/foo

cat /tmp/local_drops_retrans | while read x
do
   echo TCP Seq: $x $(tshark -r $FILE -$FILTER "ip.src == $IPSRC && tcp.port == $PORT && tcp.seq <= $x && $x < tcp.nxtseq" | wc -l); done >> $OUTFILE

rm /tmp/local_drops_retrans

