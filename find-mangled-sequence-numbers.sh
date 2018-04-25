#!/bin/bash
# find_mangled_sequence_numbers.sh begins on the previous line
#
# This script uses tshark to evidence of sequence number mangling. That is the
# sequence numbers recorded in SACK blocks does not match the sequence numbers
# in the TCP ACK header field. This is subjective so the second argument
# provides the threshold value.
#
# This happens when some middle-ware device is altering the sequence number in
# the TCP header but does not alter the sequence numbers in the SACK blocks.
#
# The output is the list of streams with mangled sequence numbers.
#
# Version 1.0 February, 6, 2018
# Version 1.1 Aprl 24, 2018
#   minor edititing of some comments
#
FINDMANGLEDSEQUENCENUMBERSVERSION="1.1_2018-04-24"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

if [ $# -gt 2 ] || [ $# -lt 1 ]
   then echo "Usage:"
        echo "   find-mangled-sequence-numbers FILE [THRESHOLD]"
        echo "       FILE is the name of the trace file to be analyzed"
        echo "       THRESHOLD is the value above which triggers a report,"
        echo "                 default is 1,000,000"
   exit
fi

FILE=$1

if [ ! -e "$FILE" ]
   then echo "Could not find input file $FILE"
   exit
fi

if [ $# -eq 2 ]
   then THRESHOLD=$2
   else THRESHOLD=1000000
fi

echo "find-mangled-sequence-numbers $FILE $THRESHOLD"

# For every TCP segment that has a SACK block, print out the TCP stream number
# the ack number and the first left edge value of the SACK block. Subtract the
# left edge from the ack number and if the value is greater than the threshold
# or less than the negative threshold print out the TCP stream number. Then
# sor the stream numbers and remove the dupliactes.
#
# Note that is some chance of a false positive when the ACK number wraps at
# same time that here is a SACK block. 


tshark -r $FILE -Y "tcp.options.sack_le" -E occurrence=f \
       -o tcp.relative_sequence_numbers:FALSE \
       -T fields -e tcp.stream -e tcp.ack -e tcp.options.sack_le | \
       awk -v thresh=$THRESHOLD \
          '(($3-$2 > thresh) || ($3-$2 < -thresh)) {print $1}' | sort -nu

exit

