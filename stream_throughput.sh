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
# Version 1.0 Jan 2 2017
LOCALDROPSVERSION="1.0_2017-01-02"
#
# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git

if [ $# -ne 4 ]
   then echo "Usage:"
        echo "   stream-throughput.sh FILE IPSRC TSHARK-FILTER OUTFILE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "      IPSRC is the IP address of the host sending the bytes"
        echo "         you wish to calculate the throughput for."
        echo "      TSHARK-FILTER is either Y or R depening on the release \
of Tshark"
        echo "      OUTFILE is the name of the output file"
        echo "Example:"
        echo "   stream-throughput.sh trace.pcap Y stream-throughput.out"
        exit
fi

FILE=$1
IPSRC=$2
FILTER=$3
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

if [ $FILTER != "R" -a $FILTER != "Y" ]
   then echo "Filter string must be either R or Y, $FILTER is not allowed"
   exit
fi

# I always echo the command and arguments to STDOUT as a sanity check

echo stream-throughput.sh $FILE $FILTER $OUTFILE

# Also echo the command, arguments, date and version to the output file

echo stream-throughput.sh $FILE $FILTER $OUTFILE > $OUTFILE
echo stream-throughput.sh run on $(date) >> $OUTFILE
echo stream-throughput.sh version $LOCALDROPSVERSION >> $OUTFILE
echo >> $OUTFILE

# Even though the argument is IP SOURCE we are filtering on ip.dst in the
# Tshark commands because we are interested in the ACK values going back to
# the source.

tshark -r $FILE -$FILTER "ip.dst == $IPSRC" -T fields -e tcp.stream | sort -nu > /tmp/tcp_streams

cat /tmp/tcp_streams | while read x
do
   echo -n "TCP Stream $x  " >> /tmp/tcp_streams_throughput
   tshark -r $FILE -o tcp.relative_sequence_numbers:TRUE \
                   -o tcp.calculate_timestamps:TRUE \
       -$FILTER "tcp.stream == $x && not tcp.flags.reset == 1 && \
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
