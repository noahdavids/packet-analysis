#!/bin/bash
# find failed connection attempts.sh begins on the previous line
#
# This macro searchs a packet trace looking for connection attempts that
# failed. There are several scenarios
#   1. SYN failed to get any response and is retransmitted until timeout
#   2  SYN failed to get any response but is not retransmitted
#   3. response is an ICMP destination unreachable - may be the cause of no
#      retransmissions. This response is typically due to a firewall either
#      on the target host or in the network between client and the target host
#   4. response is a reset, probably because nothing is listening although it
#      could be a firewall.
#   5. Server responds with a SYN-ACK but doesn't actually complete the
#      3-way handshake, it ignores the client's ACK and continues to send
#      back a SYN-ACK. This is due to listen backlog overflow.
#   6. response is an ACK instead of a SYN-ACK beacuse of port reuse and the
#      the previous connection is in TIME-WAIT state.
#   7. If the connection fails because the SYN-ACK is not reaching the client we
#      can have the scenario where the client gives up retransmitting SYNs while the
#      server is still retransmitting SYN-ACKs. If the client then starts a new
#      connection using the same client port number we have the server responding to
#      the SYN with an ACK and then retransmitting the SYN-ACK.

# Note just because a TCP stream does not include a SYN-ACK doesn't mean the
# connection attempt failed. It is possible that the SYN-ACK is not captured
# for some reason.

# The first thing the macro does is find all streams with a SYN, if there is
# no SYN there is no connection attempt to fail. Then for each of those streams
# it looks for TCP segments from the server. If there are no packets from the
# server we are into scenarios 1, 2 or maybe 3. It then looks for segments
# from the server with the ACK bit and multiple different other flags, i.e. 
# ACK-PSH, ACK-RST, ACK-SYN or ACK-FIN. If there are segments with at least 2
# combinationsthe connection had to have been successful. If not the
# connection has failed -- maybe. If the only segment is a reset with or
# without the ACK flag set I am going to assume we are into scenario 4. If the
# only ACK segment is a ACK-SYN I am going to assume scenario 5. If the only
# thing is an ACK with no other flags set we are in scenario 6 maybe. It is
# possible that the ACK-SYN was dropped and the server is just ACKing data
# sent to it from the client and the trace was stopped before the client
# disconnected. These connections are marked as suspect.
#
# Output is 3 columns, the keyword scenario, the scenario index and then the TCP Stream # numbers of the failed connections. If there are suspect streams they following in a
# second table.
#
# One final note. This script will count as a valid connection a TCP stream
# with a ACK-SYN from the server followed by a ACK-FIN or an ACK-RST from 
# the server. This is a connection that is accepted at the TCP layer and
# immediately closed at the application layer. Clients may disagree with this
# conclusion.


# Version 1.0 April 2, 2017
# Version 1.1 April 3, 2017
#  Added scenario 7
# Version 1.2 April 9, 2017
#  Added labels to each TCP stream number indicating the scenario.
# Version 1.3 April 11, 2017
#  fixed bug that incorrectly identified valid connections as scenario 7
#  if there were more than 999 bytes ACKed by server.

FAILEDCONNECTIONATTEMPTSVERSION="1.3_2017-04-11"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


if [ $# -lt 1 -o $# -gt 2 ]
   then echo "Usage:"
        echo "   failed-connection-attempts.sh FILE [ FILTER ]"
        echo "      FILE is the name of the trace file"
        echo "      FILTER is an optional tshark filter, it will be ANDed"
        echo "         tcp && not icmp"
fi

# just making sure that the file exists.

if [ ! -e "$1" ]
   then echo "Could not find input file $1"
   exit
fi

FILE=$1

# echo the command line to confirm the arguments

if [ $# -eq 2 ]
   then
     echo "failed-connection-attempts.sh $FILE \"$2\" "
else
          echo "failed-connection-attempts.sh $FILE"
fi

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# Call tshark wiriting the TCP stream number, source and destination IP
# addresses and the TCP flags. Enclose the stream value in "_" characters
# so that so when we match on stream 10 we do not also select streams 110,
# 210, 310, etc. Write everything out to temporary file
# /tmp/fail-connection-attempts-1.

if [ $# -eq 2 ]
   then
     tshark -r "$FILE" $DASH "tcp && not icmp && ($2)" -T fields \
       -e tcp.stream -e ip.src -e ip.dst -e tcp.flags -e tcp.ack \
       -o tcp.relative_sequence_numbers:TRUE 2>/dev/null | \
       awk '{print "_" $1 "_ " $2 " " $3 " " $4 " " $5}' \
       > /tmp/failed-connection-attempts-1
else
     tshark -r "$FILE" $DASH "tcp && not icmp" -T fields -e tcp.stream -e ip.src \
       -e ip.dst -e tcp.flags -e tcp.ack \
       -o tcp.relative_sequence_numbers:TRUE 2>/dev/null | \
       awk '{print "_" $1 "_ " $2 " " $3 " " $4 " " $5}' \
       > /tmp/failed-connection-attempts-1
fi


if [ ! -e /tmp/failed-connection-attempts-1 ]
   then echo "tshark did not find any packets - exiting"
        exit
fi

# Flags are written with the format 0xxxxxxxAB. The A hexit holds the TCP
# flags nonce, congestion window reduced (CWR), ECN-Echo, Urgent and ACK, the
# B hexit holds the TCP flags, Push, Reset, SYN and FIN. All we really care
# about is if the ACK flag is set so if the A hext is greater than 1. Print
# out the TCP stream value, IP source and destinations, either a 1 or a 0
# depending on the value of the A hexit and the value of the B hexit. Sort the
# result and removing the duplicates and write to the -2 temp file.

awk '{if (substr ($4, 9, 1) >= 1) print $1 " " $2 " " $3 " 1 " substr ($4, 10, 1); \
   else print $1 " " $2 " " $3 " 0 " substr ($4, 10, 1)}' \
   /tmp/failed-connection-attempts-1 | sort -u > /tmp/failed-connection-attempts-2

# We are going to be accummulatinglines into the -4 and -5 temp files. They
# should not exist but just to be echo echo "" with out the line feed into
# each of them

echo -n "" > /tmp/failed-connection-attempts-4
echo -n "" > /tmp/failed-connection-attempts-5

# For each line where the A flag hexit was a 1 and the B flag was a 2 --
# basically the SYN segment. List the TCP stream, client address (source of
# the SYN) and server address (destination of the SYN)

awk '($4 == "0" && $5 == "2") {print $1 " " $2 " " $3}' /tmp/failed-connection-attempts-2  | \
   while read stream client server
      do

# Write all lines from the target stream which are sourced from the server
# going to the client. The client match is overkill but its there we might as
# well use it. Write the results in the -3 temp file.

      grep "$stream $server $client" /tmp/failed-connection-attempts-2 \
        > /tmp/failed-connection-attempts-3

# file doesn't exist so nothing from server was seen. Strip the "_" from the
# stream value and write the value into temp file -4.

      if [ ! -e /tmp/failed-connection-attempts-3 ]
         then echo Scenario 1/2/3 $stream | tr "_" " " >> /tmp/failed-connection-attempts-4

# file is empty so again nothing from server was seen. I suspect that for any
# given system running this script we will have either this case or the
# previous case buit I am not sure that all systems everywere will behave the
# same way so I am covering both cases. 

      elif [ $(cat /tmp/failed-connection-attempts-3 | wc -l) -eq 0 ]
         then echo Scenario 1/2/3 $stream | tr "_" " " >> /tmp/failed-connection-attempts-4

# there is more than 1 type of packet with the ACK flag set, will be ACK-PSH, ACK-RST,
# ACK-SYN or ACK-FIN If it were just ACK-RST or just ACK-SYN this would be a failed
# connection attempt without question but because there are at least 2 different ACKs
# it could scenario 7. If the first relative ACK is greater than 65535 it it most likely 
# likely scenario 7 so I add the stream index to the suspect list. If the first
# relative ack is < 65535 I am considering it as a valid connection. There is some
# small probability 0.000015259 (65535÷4294967295) that this is incorrect.

      elif [ $(awk '($4 == "1") {print $0}' /tmp/failed-connection-attempts-3 \
         | wc -l) -gt 1 ]
         then grep "$stream" /tmp/failed-connection-attempts-1 \
                   > /tmp/failed-connection-attempts-6 
              head -1 /tmp/failed-connection-attempts-6 | \
                   awk '($5 > 65535) {print "Scenario 7 " $1}' | tr "_" " " \
                   >> /tmp/failed-connection-attempts-5

# We have a reset, with or without an ACK, either way that is all we have so a
# failed connection attempt. Write the stream to temp file -4.

      elif [ $(awk '($5 == "4") {print $0}' /tmp/failed-connection-attempts-3 \
         | wc -l) -gt 0 ]
         then echo Scenario 4 $stream | tr "_" " " >> /tmp/failed-connection-attempts-4

# We have a ACK-SYN but no other ACKs, so this is a failed connection.
# Probably a listen backlog overflow. The client thinks its an established
# connecton but its not.

      elif [ $(awk '($4 == "1" && $5 == "2") {print $0}' \
         /tmp/failed-connection-attempts-3 | wc -l) -gt 0 ]
         then echo Scenario 5 $stream | tr "_" " " >> /tmp/failed-connection-attempts-4

# we have an ACK and nothing else this could be valid, it is possible that
# the ACK-SYN was dropped from the trace. It is also possible it is scenario 6.
# Labeling it as suspect.

      else [ $(awk '($4 == "1" && ($5 == "8" || $5 == "0")) {print $0}' \
         /tmp/failed-connection-attempts-3 | wc -l) -gt 0 ]
         echo Scenario 6 $stream | tr "_" " " >> /tmp/failed-connection-attempts-5
      fi
   done


# clean up the temporary files and echo results

# rm /tmp/failed-connection-attempts-1
# rm /tmp/failed-connection-attempts-2

if [ -e /tmp/failed-connection-attempts-3 ]
   then rm /tmp/failed-connection-attempts-3
fi

FOUND=0
if [ $(cat /tmp/failed-connection-attempts-4 | wc -l) -gt 0 ]
   then echo "TCP Streams with failed connection attempts"
        sort -n /tmp/failed-connection-attempts-4
        FOUND=1
fi
rm /tmp/failed-connection-attempts-4

if [ $(cat /tmp/failed-connection-attempts-5 | wc -l) -gt 0 ]
   then echo "TCP Streams with suspect connection attempts"
        sort -n /tmp/failed-connection-attempts-5
        FOUND=1
fi
rm /tmp/failed-connection-attempts-5

if [ $FOUND == 0 ]
   then echo "NO TCP connection failures found"
fi

# failed connection attempts.sh ends here

