#!/bin/bash
# average.sh begins on the previous line
#
# This macro averages a value returned from tshark.
#
# Version 1.0 Jan 2 2017
# Version 1.1 Mar 4 2017
#    Corrected the version environment variable from
#    LOCALDROPSVERSION to AVERAGEVERSION
# Version 1.2 Apr 1 2017
#    Added copyright and GNU GPL statement and disclaimer

AVERAGEVERSION="1.2_2017-04-01"

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

