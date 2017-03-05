#!/bin/bash
# unterminated-connections.sh begins on the previous line
#
# This macro uses tshark to find TCP connections aka streams in a packet
# trace that have not been terminated by the end of the packet trace.
#
# The output is a list of stream indexes and a count of the total number of
# streams.
#
# Version 1.0 March 5, 2017
UNTERMINATEDCONNECTSIONVERSION="1.0_2017-03-05"

# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git


if [ $# -ne 1 ] && [ $# -ne 2 ]
   then echo "Usage:"
        echo "   unterminated-connections.sh FILE TSHARK-FILTER"
        echo "       FILE is the name of the trace file to be analyzed"
        echo "       TSHARK-FILTER is an optional filter to limit the packets
        echo "            and connections to be considered
        echo "Example:"
        echo "   unterminated-connections.sh trace.pcap"
        echo "   unterminated-connections.sh trace.pcap \"tcp.port == 1234\" "
        exit
fi

FILE=$1

if [ ! -e $FILE ]
   then echo "Could not find input file $FILE"
   exit
fi

# I always echo the command and arguments to STDOUT as a sanity check

echo unterminated-connections.sh $FILE $2


# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# Scan the packet capture file and for any TCP packets output the TCP stream
# index and the value if the TCP FIN and TCP RESET flags. Then sort removing
# the duplicates. Writethe list to a temporary file in /tmp.

if [ $# -eq 1 ]
then
tshark -r $FILE $DASH "tcp.stream" -T fields -e tcp.stream \
      -e tcp.flags.fin -e tcp.flags.reset | sort -u \
      > /tmp/unterminated-connections-1
fi

# If a filter argument was provided add it to the display filter.

if [ $# -eq 2 ]
then 
FILTER=$2
tshark -r $FILE $DASH "tcp.stream && $FILTER" -T fields -e tcp.stream \
      -e tcp.flags.fin -e tcp.flags.reset | sort -u \
      > /tmp/unterminated-connections-1
fi

# Scan the first temporay file and create a new file. Add a dash (-) at the
# end of the TCP stream index and an "F:" and "R:" in front of the FIN and 
# reset flags. The dash is needed so that when we search for the index we
# do not get lines where the index is a prefix, i.e. search for 100 and get
# 1000 thru 1009 as well.

cat /tmp/unterminated-connections-1 | awk '{print $1 "- F:" $2 " R:" $3}' \
      > /tmp/unterminated-connections-2

# Extract out just the unique TCP stream indexes and then for each index
# search the file for lines with that stream index. Combine all the lines
# by changing new lines to spaces and then filter out anything with "F:1" or
# "R:1". Then print the TCP stream index to a third temporary file.

for x in $(cat /tmp/unterminated-connections-2 | awk '{print $1}' \
      | tr "-"  " " | sort -nu)
    do grep ^$x- /tmp/unterminated-connections-2 | tr "\n-" "  " \
      | grep -v "R:1" | grep -v "F:1" | awk '{print $1}'
    done > /tmp/unterminated-connections-3

# Display the temorary file to the terminal window, then count the lines in the
# file and display that as well

cat /tmp/unterminated-connections-3
echo Total number of unterminated connectionsis $(cat /tmp/unterminated-connections-3 | wc -l)

# clean up the temporary files

rm /tmp/unterminated-connections-1
rm /tmp/unterminated-connections-2
rm /tmp/unterminated-connections-3

# unterminated-connections.sh stops here


