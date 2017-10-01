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
#             with a FIN
#	SYN - the only response from the server is an ACK-SYN
#	NOS - there are NO tcp Segments from the server
#       CLR - The server responds with an ACK-SYN but then the CLient sends
#             a Reset or an ACK and then a reset

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

# A connection attempt is considered as succeded if the client sends a SYN and
# the server sends a segment with the PSH flag set since that means that the
# server has sent data. Also if the ACK number of the first ACK segment sent
# by the server with no other TCP flags set is < 65535. That is an arbitrary
# cut off but large enough that several segments could be dropped without
# changing the conclusion and small enough that the probability that it is a
# challenge ACK is small (0.000015259 (65535 / 4294967295)). Also if the
# server sends a FIN with an ACK number > 1 it means that it has ACKed
# something besides the SYN, note that this might be the FIN from the client
# but either way it is considered a succeeded connection. On the other hand if
# the server accepts the connection and then immediatelty sends a FIN the
# conection attempt is considered as failed. Technically this is not a failed
# TCP connection attempt but since the client application most likely reported
# an error it gets added to the list of failed connection attempts. There is 
# also the case of the server sending a ACK-SYN and the client sending an ACK
# followed by a RESET. technically this is also a completed connection but
# most likely the server will report an error so it is flagged as CLR. the case
# of the client responding to the ACK-SYN with a reset is clearly a failed
# connection (no ACK from the client) and is also flagged as CLR.

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

FAILEDCONNECTIONATTEMPTSVERSION="2.3_2017-10-01"

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
# Enclose the stream value in "_" characters so that so when we match
# on stream 10 we do not also select streams 110, 210, 310, etc. Write
# everything out to the temporary file /tmp/fail-connection-attempts-1.
#
# The not icmp is to make sure we aren't confused by an ICMP response
# from the server. 

if [ $# -eq 2 ]
   then
     tshark -r "$FILE" $DASH "tcp && not icmp && ($2)" -T fields \
       -e tcp.stream -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
       -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.reset \
       -e tcp.flags.syn -e tcp.flags.fin -e tcp.ack -e tcp.len \
       -o tcp.relative_sequence_numbers:TRUE 2>/dev/null | \
       awk '{print "_" $1 "_ " $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8 \
             " " $9 " " $10 " " $11 " " $12}' \
                        > /tmp/failed-connection-attempts-1
else
     tshark -r "$FILE" $DASH "tcp && not icmp" -T fields \
       -e tcp.stream -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
       -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.reset \
       -e tcp.flags.syn -e tcp.flags.fin -e tcp.ack -e tcp.len \
       -o tcp.relative_sequence_numbers:TRUE 2>/dev/null | \
       awk '{print "_" $1 "_ " $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8 \
             " " $9 " " $10 " " $11 " " $12}' \
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
             syn fin ackno tcplen
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

# find the first segment from the server to the client for this stream that
# does not have the SYN flag set

    grep -E "$stream $server $client $sport $cport . . . 0" -m 1 \
       /tmp/failed-connection-attempts-1 > /tmp/failed-connection-attempts-2

# PUSH flag is set, good connection
    if [ $(awk '($7 == 1) {print $0}' /tmp/failed-connection-attempts-2 | \
         wc -l) -gt 0 ]
       then continue
    fi

# ACK flag is set and the RST, SYN and FIN flags are not set and the ACK 
# number > 65535, it is probably (99.9984741% (1-65535÷4294967295)) a
# challenge ACK so mark it as failed
  
    if [ $(awk '($6 == 1 && $8 == 0 && $9 == 0 && $10 == 0 && \
                                              $11 > 65535) {print $0}' \
                     /tmp/failed-connection-attempts-2 | wc -l) -gt 0 ]
       then echo $stream $server:$sport $client:$cport "CHA" | tr "_" " " \
                                   >> /tmp/failed-connection-attempts-3
            continue
    fi

# ACK flag is set and the RST, SYN and FIN flags are not set and the ACK 
# number < 65535, it is probably not a challenge ACK so assume its good and
# skip the to the next stream. Note that is NOT the else from the previous
# "if" since it still requires that the ACK flag be set.

    if [ $(awk '($6 == 1 && $8 == 0 && $9 == 0 && $10 == 0 && \
                                              $11 < 65535) {print $0}' \
                     /tmp/failed-connection-attempts-2 | wc -l) -gt 0 ]
       then continue
    fi

# FIN flag is set and the ACK number == 1 so server closed the connection
# without accepting any data. It is possible that the client opened a
# connection then the server sent 1 segment of data and closed the connection
# but the TCP length is also 0 so make this as failed

    if [ $(awk '($10 == 1 && $11 == 1 && $12 == 0) {print $0}' \
                     /tmp/failed-connection-attempts-2 | wc -l) -gt 0 ]
       then echo $stream $server:$sport $client:$cport "IMC" | tr "_" " " \
                                   >> /tmp/failed-connection-attempts-3
            continue
    fi

# If the FIN flag is set and we are here it means that the ACK number is
# greater than 1 or there is TCP data either way we are good

    if [ $(awk '($10 == 1) {print $0}' \
                     /tmp/failed-connection-attempts-2 | wc -l) -gt 0 ]
       then continue
    fi

# RESET flag is set, mark it as failed

    if [ $(awk '($8 == 1) {print $0}' /tmp/failed-connection-attempts-2 | \
         wc -l) -gt 0 ]
       then echo $stream $server:$sport $client:$cport "RST" | tr "_" " " \
                                   >> /tmp/failed-connection-attempts-3
            continue
    fi

# If we are here then either the server sent no segments or sent just an
# ACK-SYN. It is possible that none of the server's segments were captured.
# so look at the last segment sent by the client that doesn't have the SYN
# flag set. If the last segment with the ACK flag set has an ACK value greater
# than 1 then we know that the server sent something more than just a SYN, so
# treat it as a good connection. I am limiting the search to the first 100
# non-SYN segments from the client. Yes 100 is arbitrary but if the client has
# sent 100 non-SYN segments without ACking anything from the server and the
# server hasn't sent an ACK the stream probably need to be investigated
# anyway.

    grep -E "$stream $client $server $cport $sport" -m 100 \
       /tmp/failed-connection-attempts-1 | awk '($9 == 0) {print  $0}'> \
       /tmp/failed-connection-attempts-5

# Last line with the ACK flags set

    grep -E "$stream $client $server $cport $sport 1" \
       /tmp/failed-connection-attempts-5 | tail -1 > \
       /tmp/failed-connection-attempts-6

# If the file has lines check that the ACK value is greater than 1, if so we 
# have a good connection, just continue to the next stream. If not fall
# through to the final tests.

   if [ $(cat /tmp/failed-connection-attempts-6 | wc -l) -gt 0  ]
      then if [ $(awk '{print $(NF-1)}' \
              /tmp/failed-connection-attempts-6) -gt 1 ]
              then continue
           fi
   fi

# If we are here the connection attempt has failed, the only question is are
# there any SYNs from the server or not and what did the client do.

    grep -E "$stream $server $client $sport $cport . . . 1" -m 1 \
       /tmp/failed-connection-attempts-1 > /tmp/failed-connection-attempts-2

# The server did not sent a SYN so flag the connection as NOS

    if [ $(awk '($9 == 1) {print $0}' /tmp/failed-connection-attempts-2 | \
         wc -l) -eq 0 ]
       then echo $stream $server:$sport $client:$cport "NOS" | tr "_" " " \
                                   >> /tmp/failed-connection-attempts-3
            continue
    fi

# A SYN from the server was found so now the question is did the client send
# just SYNs and then a RESET (or an ACK and a RESET). We already have a file
# with the first 100 not-SYNs from the client. So we check the first 2 lines,
# if either contain a reset we flag this as client reset, else because the 
# server did send a SYN we flag it as SYN.

    head -2 /tmp/failed-connection-attempts-5 > \
           /tmp/failed-connection-attempts-6

    if [ $(awk '($8 == 1) {print $0}' /tmp/failed-connection-attempts-6 | \
         wc -l) -eq 1 ]
      then echo $stream $server:$sport $client:$cport \
                   "CLR" | tr "_" " " >> /tmp/failed-connection-attempts-3
      else echo $stream $server:$sport $client:$cport \
                   "SYN" | tr "_" " " >> /tmp/failed-connection-attempts-3
    fi
  done


# output the results

if [ $(head -1 /tmp/failed-connection-attempts-3 | wc -l) -eq 0 ]
   then echo No failed connection attempts found
   else cat /tmp/failed-connection-attempts-3 | column -t
fi

