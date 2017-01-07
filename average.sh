#!/bin/bash
# average.sh begins on the previous line
#
# Rhis macro averages a value returned from tshark.
#
# Version 1.0 Jan 2 2017
LOCALDROPSVERSION="1.0_2017-01-07"
#
# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git

if [ $# -ne 3 ]
   then echo "Usage:"
        echo "   average.sh FILE TSHARK-FILTER TSHARK-VARIABLE"
        echo "      FILE is the name of the trace file to be analyzed"
        echo "      TSHARK-FILTER is the filter clause including the \
-Y or -R "
        echo "      TSHARK-VARIABLE is the variable to be averaged"
        echo "Examples:"
        echo "   To get the average time between transmission of data packets"
        echo "     average.sh trace.pcap \"-Y ip.src == 172.16.1.11 && \
tcp.srcport == 80 && tcp.len > 0\" tcp.frame_time_displayed"
        echo "   To get the average advertised window size"
        echo "     average.sh trace.pcap \"-Y ip.src == 192.168.1.1 && \
tcp.srcport == 42345\" tcp.window_size"
        echo "   To get the average round trip time"
        echo "     average.sh trace.pcap \"-Y ip.src == 172.16.1.11 && \
tcp.srcport == 42345\" tcp.analysis.ack_rtt"
        exit
fi

FILE=$1
FILTER=$2
VARIABLE=$3

if [ ! -e $FILE ]
   then echo "Could not find input file $FILE"
   exit
fi

# I'm leting tshark sanitity check the filter and variable strings

# Echo the command line so there is a record of what was done

echo
echo tshark -r $FILE \"$FILTER\" -T fields -e $VARIABLE \| awk \'{sum += \$1\; n++} END { print sum, \"/\", n, \"=\", sum / n}\';

tshark -r $FILE "$FILTER" -T fields -e $VARIABLE | awk '{sum += $1; n++} END { print sum, "/", n, "=", sum / n;}';

# average.sh ends here

