#!/bin/bash
# throughput-per-sec.sh begins on the previous line
#

# This script generates a throughput per time-unit for a stream. It is
# something suitable for graphing.  It is different from the
# stream_throughput.sh script with generates the average throughput for all
# streams in a trace file. A low average will not tell you if the throughput
# is uniformly low or high with periods of low.

# OUTPUT is a file with 1 line for unit of time resolution (0.001,
# 0.01, 0.1, or 1 sec) of the trace with the format
#   (Ending-ACK - Begining-ACK) / (Ending-time - Beginning-time) = Throughput
# Where
#   the Ending-ACK and Ending-time on line X-1 are the Begining-ACK -time
#      on line X.
#   Throughput is always per second, not per time resolution unit.
#
# Note that the times are not exactly at the indicated time resolution. They
# will be the "next" segment after the time resolution tick. 
#
# The gnuplot command
#   plot "OUTPUT-FILE" using 8:13 
# Will graph the throughput (column 13) versus the Ending-time.

# Version 1.0 September 6, 2017
# Version 1.1 September 8, 2017
#    Corrected calculations for resolutions greater than 1
#    Reject resolutions that are not 1, 10 (tenth of a second), 100 (hundreth
#      of a second), or 1000 (milli-seconds)
# Version 1.2 October 1, 2017
#    Added more comments and argument processing, redirect the output to a 
#    file
# Version 1.3 October 6, 2017
#    Added a filter to make sure that only segments with the ACK flag set are
#    used. Some resets at the send of a connection may not have the ACK flag
#    set and tshark will provide a 0 ACK number for those segments. This can
#    result in a very large negative number for throughput at the end of the
#    connection.
# Version 1.4 October 16, 2017
#    Changed from frame time to stream time so the first calculation is not
#    skewed if the stream doesn't start at 0 frame time.

THROUGHPERSECVERSION="1.4_2017-10-16"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


if [ $# -ne 5 ]
   then echo "Usage:"
        echo "   throughput-per-sec.sh FILE TCP-STREAM DEST-IP RESOLUTION OUTPUT-FILE"
        echo "      FILE is the name of one file"
        echo "      TCP-STREAM is the TCP Stream number"
        echo "      DEST-IP is the IP address of the receiving host"
        echo "      Resolution is 1 (sec) 10 (tenth of a second)"
        echo "         100 one hundredth of a second) or 1000 (millisecond)"
        echo "      OUTPUT-FILE is the file that will hold the results"
        exit
fi

FILE=$1
TCPSTREAM=$2
DESTIP=$3
RESOLUTION=$4
OFILE=$5

if [ $RESOLUTION -ne 1 ] && [ $RESOLUTION -ne 10 ] && \
   [ $RESOLUTION -ne 100 ] && [ $RESOLUTION -ne 1000 ]
   then
     echo "resolution argument can only be 1, 10, 100, or 1000"
     exit
fi

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# Throughput is measured based on the receiver's ACKs so for each segment
# from the receiving host extract the relative timestamp and the ACK value
# filter out any frames withour an ACK.

tshark -r $FILE -Y "tcp.stream == $TCPSTREAM && ip.src == $DESTIP && \
     tcp.flags.ack == 1" -T fields -e tcp.time_relative -e tcp.ack \
     > /tmp/throughput-per-sec-1

# If resolution is greater than 1 second we need to multiple the relative time
# by the resolution and create a new temp file, /tmp/throughput-per-sec-2. If
# resolution is 1 second just copy /tmp/throughput-per-sec-1 to
# /tmp/throughput-per-sec-2

if [ $RESOLUTION -gt 1 ] 
   then cat /tmp/throughput-per-sec-1 | awk -v r=$RESOLUTION \
            '{printf("%0.6f %d\n", ($1 * r), $2)}' > /tmp/throughput-per-sec-2
   else mv  /tmp/throughput-per-sec-1 /tmp/throughput-per-sec-2
fi

# replace the decimal point with a space and sort -u the file on the first
# column -- this is the seconds, or tenths of seconds, or hundreds, etc. The
# magic is that sort will filter out everything except the first unique value.
# so its an easy way to get the just the first entry per resolution unit of
# time. This gets written to a third temp file /tmp/throughput-per-sec-3

cat /tmp/throughput-per-sec-2 | tr "." " " | sort -unk1 | \
                    awk '{print $1 "." $2 " " $3}'> /tmp/throughput-per-sec-3

# Now do the calculations. Start with the second row (tail -n+2) because there
# may not be an ACK in the first row (if its a SYN). Then subtrack the 
# previous row's time and ACK numbers from the current row and divide by the
# time difference. For resolutions greater than 1 we divide the time values by
# the resolution when they are displayed and multiple the bytes/resolution
# by the resolution to get bytes/second regardless of the resolution.

tail -n+2 /tmp/throughput-per-sec-3 | awk -v r=$RESOLUTION -v p=0 -v q=0  \
           '{printf ("%s%d%s%d%s%0.6f%s%0.6f%s%0.6f\n", \
           "( ", $2, " - ", p, " ) / ( ", $1/r, " - ", q/r, " ) = ", \
            ($2-p)/($1-q)*r); p=$2; q=$1}' | column -t > $OFILE

# you can graph the bytes/sec with gnuplot with
#      plot "FILE-NAME" using 8:13
# column 8 is the time stamp to the right of the minus sign and column 13 is
# the bytes per second calculation

# throughput-per-sec.sh ends here
