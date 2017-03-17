#!/bin/bash
# start-packet-tracing.sh begins on the previous line
#
# This macro starts tcpdump to record packets using a ring buffer of 10
# files of 100 megabytes each. The process is placed in the background.
#
# Version 1.0 February 4, 2017
STARTPACKETTRACINGVERSION="1.0_2017-02-05"
#
# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git


if [ $# -lt 2 -o $# -gt 4 ]
   then echo "Usage:"
        echo "   start-packet-tracing.sh DEVICE OUTPUT-FILE LENGTH FILTER"
        echo "      DEVICE is the name of the device to trace on"
        echo "      OUTPUT-FILE is file that packets will be written to"
        echo "      LENGTH is the number of bytes to capture"
        echo "         0 indicates that the entire frame should be captured"
        echo "       114 is the default and will capture the entire"
        echo "       Ethernet/IP/TCP header assuming there are no IP options. "
        echo "       If the header does not use all 40 bytes of options you"
        echo "       will also capture some of the TCP data. UDP headers are"
        echo "       smaller so some UDP data will also be captured"
        echo "      FILTER is a tcpdump filter string to limit what is"
        echo "       captured. The default is the null string which will"
        echo "       capture everything. If you want to include a filter you"
        echo "       must include the length argument."
        echo ""
        echo "   Examples:"
        echo "       ./start-packet-tracing wlp5s0 /tmp/wlp5s0.pcap" 
        exit
fi

LENGTH=114
FILTER=\"\"

if [ $# -ge 2 ]
   then
     DEVICE=$1
     OUTPUT=$2
fi

if [ $(ls -l $OUTPUT 2>/dev/null | wc -l) -gt 0 ]
   then
     echo Deleting $OUTPUT* 
     rm -f $OUTPUT*
fi

if [ $# -ge 3 ]
   then
     LENGTH=$3
fi

if [ $# -eq 4 ]
   then
     FILTER=$4
fi

# I always echo the command and arguments to STDOUT as a sanity check
# I am also including the default values for any arguments not provided.

echo start-packet-trace.sh $DEVICE $OUTPUT $LENGTH $FILTER

if [ $# -eq 4 ]
   then
     tcpdump -i $DEVICE -C 100 -W 10 -s $LENGTH -w $OUTPUT $FILTER &
   else
     tcpdump -i $DEVICE -C 100 -W 10 -s $LENGTH -w $OUTPUT &
fi

echo $! > /tmp/start-packet-trace.pid

echo use kill \$\(cat /tmp/start-packet-trace.pid\) to terminate the packet trace.

# start-packet-tracing.sh stops here

