#!/bin/bash
# find failed connection attempts.sh begins on the previous line
#
# This macro searchs a packet trace looking for connection attempts that
# failed. 

# Output is a table of failed connection attempts. The first column is the
# TCP stream number followed by the server-ip:server-port and
# client-ip:client-port. The 4th coloumn is an indicator of why the stream
# made it into the table.
#	RST - first response from the server is a ReSeT without ACKing any
#	      data
#	CHA - first response from the server is a CHAllenge ACK
#	IMC - server just accepts and then IMmediately Closes the connection
#             with a FIN. Note there are two versions of this IMC if the
#             determination is made by looking at the Server's segments and
#             imc (lower case) if the determination is made by looking at the
#             client's segments.
#	SYN - the only response from the server is an ACK-SYN
#	NOS - there are NO tcp Segments from the server
#       CLR - The server responds with an ACK-SYN but then the CLient sends
#             a Reset or an ACK and then a reset
#       CIC - Client Immediatelty Closes the connection with a FIN after
#             the Server's ACK-SYN
#       MAR - short for martian, if we get to this point there is a hole
#             in the algorithm since its not determined to be a good
#             connection and its not one of the above failures

# The presence or absense of an ACK-SYN is not enough to determine if a 
# connect attempt succeeded or not. It is possible that the ACK-SYN is not
# captured for some reason. Also if the listen backlog is filled it is
# possible that server will send a ACK-SYNs but then still not complete the
# 3-way-handshake and continue to retransmit ACK-SYNs. You also cannot just
# look for retransmitted SYNs. First a SYN may be retransmitted multiple
# times before being accepted. Second, if the server responds with an ICMP
# destination unreachable or a reset the SYN may not be retransmitted. 
# Also if the server responds with a challenge ACK instead of a ACK-SYN the
# client can send its own reset.

# You can monitor the progress of the script by looking at
# /tmp/failed-connection-attempts-4. As each stream number with a SYN is
# processed the number is written to the -4 file.
#         tail -f /tmp/failed-connection-attempts-4 2>/dev/null
# is your friend. Note that if its a large file with just a few connection
# attempts -4 may not update very fast.


# Version 1.0 April 2, 2017
# Version 1.1 April 3, 2017
#  Added scenario 7
# Version 1.2 April 9, 2017
#  Added labels to each TCP stream number indicating the scenario.
# Version 1.3 April 11, 2017
#  fixed bug that incorrectly identified valid connections as scenario 7
#  if there were more than 999 bytes ACKed by server.
# Version 1.4 April 13, 2017
#  Redid the internal logic, added scenario 8 and removed the "suspected"
#  list
# Version 1.5 April 14, 2017
#  Added scenario 9 and 10 added the suspected list back
# Version 2.0 April 16, 2017
#  Completelty rewritten, removed the scenarios in favor of a simpler approach
#  and removed the suspected list (again).
# Version 2.1 August 22, 2017
#  Added the server:port client:port columns to the output
# Version 2.2 September 10, 2017
#  Added CLR test
# Version 2.3 October 1, 2017
#  Added a check for the case where the server's 1 data packet is missing but
#  but the client ACKs it so we know its a good. This was previsouly
#  incorrectly flagged as SYN. Also the case where no server packets are
#  captured but the client is ACKing data. This was previsouly incorrectly
#  flagged as NOS.
# Version 2.4 Decemeber 12, 2017
#  Added the CIC and MAR flags, also reworked algorthim to hopefully make
#  it faster.
# Version 2.5 January 4, 2018
#  Added a check right at the start for a client segment with seq and ack 
#  numbers > 2 and  the reset flag == 0. This indicates a good connection.
#  Should speed up processing and also correctly identify the case where
#  where the only captured server side segment is the SYN-ACK but the client
#  is ACKing segments that the trace does not see. It also catches the case
#  where the first server response is a challenge ACK but the client tries
#  again instead of sending a reset and the connection completes.
# Version 2.6 January 10, 2016
#  Changed that first client segment check to check is ACK and SEQ > 2 and
#  the ACK flag is set, I droped the reset flag must not be set.

FAILEDCONNECTIONATTEMPTSVERSION="2.6_2018-01-10"

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

# Call tshark writing the TCP stream number, source and destination IP
# addresses and ports, all the flags the ACK number and the TCP length.
# and sequence number. Enclose the stream value in "_" characters so that
# so when we match on stream 10 we do not also select streams 110, 210,
# 310, etc. Write everything out to the temporary file
# /tmp/fail-connection-attempts-1.
#
# The not icmp is to make sure we aren't confused by an ICMP response
# from the server. 

if [ $# -eq 2 ]
   then
     tshark -r "$FILE" $DASH "tcp && not icmp && ($2)" -T fields \
       -e tcp.stream -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
       -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.reset \
       -e tcp.flags.syn -e tcp.flags.fin -e tcp.ack -e tcp.len -e tcp.seq \
       -o tcp.relative_sequence_numbers:TRUE 2>/dev/null | \
       awk '{print "_" $1 "_ " $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8 \
             " " $9 " " $10 " " $11 " " $12 " " $13}' \
                        > /tmp/failed-connection-attempts-1
else
     tshark -r "$FILE" $DASH "tcp && not icmp" -T fields \
       -e tcp.stream -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
       -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.reset \
       -e tcp.flags.syn -e tcp.flags.fin -e tcp.ack -e tcp.len -e tcp.seq \
       -o tcp.relative_sequence_numbers:TRUE 2>/dev/null | \
       awk '{print "_" $1 "_ " $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8 \
             " " $9 " " $10 " " $11 " " $12 " " $13}' \
                        > /tmp/failed-connection-attempts-1

fi


# If the output file doesn't exist or is empty report that an exit

if [ ! -e /tmp/failed-connection-attempts-1 ]
   then echo "tshark did not find any packets - exiting"
        exit
fi

if [ $(head -1 /tmp/failed-connection-attempts-1 | wc -l) -eq 0 ]
   then echo "tshark did not find any packets - exiting"
        exit
fi

# initialize the LASTSTREAM variable and clear out the temporary file used to 
# accumulate the failed connection attempts

LASTSTREAM=-1
echo -n "" > /tmp/failed-connection-attempts-3
echo -n "" > /tmp/failed-connection-attempts-4

# Find segments where the SYN flag is set and the ACK flag is not.

cat /tmp/failed-connection-attempts-1 | \
  while read stream client server cport sport ack push reset \
             syn fin ackno tcplen seqno
  do
    if  [ "$ack" == 0 -a "$syn" == 1 ]
        then echo $stream >> /dev/null
        else continue
    fi

# record the stream number so we do not process the same stream again. Also
# send it to -4 so we can know what the script is doing.

    CURRENTSTREAM=$(echo $stream | tr "_" " ")
    if [ $CURRENTSTREAM -le $LASTSTREAM ]
       then continue
    fi

    echo $CURRENTSTREAM > /tmp/failed-connection-attempts-4
    LASTSTREAM=$CURRENTSTREAM

# Find the first 200 segments for that stream and then separate into server
# sourced and client sourced segments. Yes, 200 is an arbitrary number but if
# we cannot figure out it out after 200 segments we have a bigger problem and
# yes 200 is probably over kill but I wanted to be sure.

    grep -E "$stream" -m 200 /tmp/failed-connection-attempts-1 > \
       /tmp/failed-connection-attempts-1a

    grep -E "$stream $server $client $sport $cport" \
       /tmp/failed-connection-attempts-1a > /tmp/failed-connection-attempts-2s

    grep -E "$stream $client $server $cport $sport" \
       /tmp/failed-connection-attempts-1a > /tmp/failed-connection-attempts-2c

# If a client side segment has sequence and ACK numbers > 2 and the ACK
# flag is set we know this is a good connection so just continue

    if [ $(awk '($11 > 2 && $13 > 2 && $6 == 1) {print $0}' \
       /tmp/failed-connection-attempts-2c | wc -l) -gt 0 ]
       then continue
    fi

# If there are server sourced segments

    if [ $(cat /tmp/failed-connection-attempts-2s | wc -l) -gt 0 ]
       then 

# If the only Server segments are ACK-SYNs or just ACKs with an ACK of 1
# and no data is sent it is either a SYN or CLR scenario. Check the
# client side, if there is a reset with a sequence number of 1 its a CLR
# else its a SYN

         if [ $(awk '(!(($6 == 1 && $9 == 1) || ($6 == 1 && $11 == 1) || \
            ($12 > 0))) {print $0}' /tmp/failed-connection-attempts-2s | \
            wc -l) -eq 0 ]
            then if [ $(awk '(($8 == 1) && ($13 == 1)) {print $0}' \
                    /tmp/failed-connection-attempts-2c| wc -l) -gt 0 ]
                    then echo $stream $server:$sport $client:$cport "CLR" | \
                       tr "_" " " >> /tmp/failed-connection-attempts-3
                    else  echo $stream $server:$sport $client:$cport "SYN" | \
                       tr "_" " " >> /tmp/failed-connection-attempts-3
                 fi
                 continue
         fi

# If the first segment has the ACK flag is set and the RST, SYN and FIN
# flags are not set and the ACK number > 65535, it is probably
# (99.9984741% (1-65535÷4294967295)) a challenge ACK so mark it as failed
  
         if [ $(head -1 /tmp/failed-connection-attempts-2s | \
            awk '($6 == 1 && $8 == 0 && $9 == 0 && $10 == 0 && \
                                              $11 > 65535) {print $0}' \
            | wc -l) -gt 0 ]
            then echo $stream $server:$sport $client:$cport "CHA" | \
                     tr "_" " " >> /tmp/failed-connection-attempts-3
                 continue
         fi

# If we have a server segment with either the PUSH flag set or data,
# or it is ACKing data from client (something more than a FIN) treat it
# as a good connection

         if [ $(awk '(($7 == 1) || ($11 > 2) || ($12 > 0)) {print $0}' \
            /tmp/failed-connection-attempts-2s | wc -l) -gt 0 ]
            then continue
         fi


# At this point we only care about the first non-SYN packet from the server

         grep -E "$stream $server $client $sport $cport . . . 0" -m 1 \
             /tmp/failed-connection-attempts-1a > \
             /tmp/failed-connection-attempts-2s


# FIN flag is set and the ACK number == 1 so server closed the connection
# without accepting any data so make this as failed

         if [ $(awk '($10 == 1 && $11 == 1 && $12 == 0) {print $0}' \
                     /tmp/failed-connection-attempts-2s | wc -l) -gt 0 ]
            then echo $stream $server:$sport $client:$cport "IMC" | \
                     tr "_" " " >> /tmp/failed-connection-attempts-3
            continue
         fi

# RESET flag is set, mark it as failed, rember this is the first segment from
# from the server that does not have the SYN flag set.

         if [ $(awk '($8 == 1) {print $0}' /tmp/failed-connection-attempts-2s | \
               wc -l) -gt 0 ]
            then echo $stream $server:$sport $client:$cport "RST" | tr "_" " " \
                                   >> /tmp/failed-connection-attempts-3
                 continue
         fi
    fi

# If we are here then either the server sent no segments or all the above 
# tests failed. Lets look at the client's packets

# Client did send something besides a SYN, could be a FIN, reset, or data or
# ACK of data

   if [ $(cat /tmp/failed-connection-attempts-2c | wc -l) -gt 0 ]
      then

# If there are any segments (from client) with an ACK > 2 or with TCP data
# we have a good connection

         if [ $(awk '($11 > 2 || $12 > 0) {print $0}' \
             /tmp/failed-connection-attempts-2c  | wc -l) -gt 0 ]
            then continue
         fi

# Did the client send a FIN with an ACK of 1 indicating that it closed
# the connection immediately

          if [ $(awk '($10 == 1 && $11 == 1) {print $0}' \
             /tmp/failed-connection-attempts-2c | wc -l) -gt 0 ]
             then echo $stream $server:$sport $client:$cport \
                  "CIC" | tr "_" " " >> /tmp/failed-connection-attempts-3
             continue
          fi

# Did the client send a FIN with an ACK of 2 indicating that it closed
# the connection in response to an immediate FIN from the server. Keep
# in mind that we are only here if the client never sent and data so
# the only reason for a FIN with an ACK of 2 is that neither side sent
# any data and the server sent an immediate FIN. We should have spotted
# this already but only if the server didn't send an ACK before the FIN.
# I flaf this with a lower case IMC so I can tell the difference.

          if [ $(awk '($10 == 1 && $11 == 2) {print $0}' \
             /tmp/failed-connection-attempts-2c | wc -l) -gt 0 ]
             then echo $stream $server:$sport $client:$cport \
                  "imc" | tr "_" " " >> /tmp/failed-connection-attempts-3
             continue
          fi

# Did the client send a reset and did not send data or ACK data (covered
# in a previous test)

          if [ $(awk '($8 == 1) {print $0}' \
             /tmp/failed-connection-attempts-2c  | wc -l) -gt 0 ]
             then echo $stream $server:$sport $client:$cport \
                  "CLR" | tr "_" " " >> /tmp/failed-connection-attempts-3
             continue
          fi
   fi

# If we are here either the trace file has no segments (of any type from
# the server or all of the above tests failed. Double check there are
# no segments from the server. Assuming there are none flag the connection
# as NOS. If there are flag it as MAR since we should be there.

   if [ $(grep -E "$stream $server $client $sport $cport" \
       /tmp/failed-connection-attempts-1a | wc -l) -eq 0 ]
      then echo $stream $server:$sport $client:$cport \
                  "NOS" | tr "_" " " >> /tmp/failed-connection-attempts-3
      else echo $stream $server:$sport $client:$cport \
                  "MAR" | tr "_" " " >> /tmp/failed-connection-attempts-3
   fi

  done


# output the results

if [ $(head -1 /tmp/failed-connection-attempts-3 | wc -l) -eq 0 ]
   then echo No failed connection attempts found
   else cat /tmp/failed-connection-attempts-3 | column -t
fi

