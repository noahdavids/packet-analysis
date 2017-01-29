#!/bin/bash
# find-reset-connections.sh begins on the previous line
#
# This macro uses tshark to find TCP connections that have been reset without
# being closed. That is one host has sent a RESET without either host sending
# a FIN. Typically this means that some error condition happened and that is
# a stream that needs investigation. Unfortunately many applications send a
# FIN and then immediately shutdown the socket so that any response from the
# remote host (like a FIN-ACK) triggers a reset. This is probably not an
# issue and we do not want to waste time investigating these connections.
# This script will filter those connections out. Note that this is an
# assumption; the host receiving the reset may report an error and this
# is the error we have been called to investigate. So keep that in mind.
# 
# The Output has the format
#     <Stream Number> <Src IP> <Src Port> <TCP Seq> <Dest IP< <Dst Port>
#     <Stream Number> <Src IP> <Src Port> <TCP Seq> <Dest IP< <Dst Port>
#     <Stream Number> <Src IP> <Src Port> <TCP Seq> <Dest IP< <Dst Port>

# If the sequence number is 0 it is probably an indictaion that the reset
# was sent in response to a SYN packet.

# Version 1.0 Jan 29 2017

FINDRESETCONNECTIONSVERSION="1.0_2017-01-29"

# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git

if [ $# -ne 2 ]
   then echo "Usage:"
        echo "   find-reset-connections.sh FILE TSHARK-FILTER"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "Example:"
        echo "   find-reset-connections.sh trace.pcap Y"
        exit
fi

FILE=$1
FILTER=$2


if [ ! -e $FILE ]
   then echo "Could not find input file $FILE"
   exit
fi

if [ $FILTER != "R" -a $FILTER != "Y" ]
   then echo "Filter string must be either R or Y, $FILTER is not allowed"
   exit
fi

# I always echo the command and arguments to STDOUT as a sanity check

echo find-reset-connections.sh $FILE $FILTER


# Search the trace file and for every FIN or reset segment print the
# stream number, the IP address and port number sending the FIN or reset
# the TCP Sequence number of the reset, the IP address and port receving
# the FIN or reset, and the fin and reset flags. Sort removing duplicates
# because we do not care if more than 1 FIN or reset is sent and send
# it all to a temporary file.
 
tshark -r $FILE  -$FILTER "tcp.flags.fin == 1 || tcp.flags.reset == 1" \
   -T fields -e tcp.stream -e ip.src -e tcp.srcport -e tcp.seq -e ip.dst \
   -e tcp.dstport -e tcp.flags.fin -e tcp.flags.reset \
   -o tcp.relative_sequence_numbers:TRUE | sort -u > /tmp/fins-and-resets.out


# Search through the tempoary file for lines corresponding to resets. that
# is lines where the FIN flag is a 0 and the reset flag is a 1. These are
# the last 2 fields in the line so it is 0 following by white space followed
# by 1 and the end of the line. Extract out only column 1 - the TCP stream number.
# We will iterate over this list or stream numbers.

for x in $(egrep "0\s*1$" /tmp/fins-and-resets.out | awk '{print $1}')

# For each of the stream numbers found above search for an entry in the temporary
# file which begins with that stream number and ends with the FIN flag of 1 and
# the reset flag of 0. Count the number of lines found and then write out the stream
# number and the line count into an other temporary file

   do echo $x $(cat /tmp/fins-and-resets.out | egrep "^$x\s+.*1\s*0$" | wc -l)
done > /tmp/fins-and-resets-2.out

# Search the second temporary file for lines ending with 0, i.e. the line count
# was 0, i.e. no FINs where found. For each line found read the stream number
# and the count then search the first temporary file for the stream number and
# print the stream number, Src IP, Src Port, TCP Seq, Dest IP, and Dst Port.

grep "0$" /tmp/fins-and-resets-2.out | while read stream count
     do egrep "^$stream\s+" /tmp/fins-and-resets.out \
     | awk '{print $1 " " $2 " " $3 " " $4 " " $5 " " $6}'
done | column -t

# clean-up temorary files

rm /tmp/fins-and-resets.out
rm /tmp/fins-and-resets-2.out

# find-reset-connections.sh ends here


