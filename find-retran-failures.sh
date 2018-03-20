#!/bin/bash
# find-retran-failures.sh begins on the previous line
#

# This script uses tshark to look through a packet trace file and find TCP
# connections that appear to have failed because of retransmission issues.
# Ideally the packet trace file should be collected on the host sending the
# packets. If the trace file is collected on the receiver or at some point
# between sender and receiver it is possible failures will be missed.
#
# For each failure identified output will consist of a line containing 
# 1. the TCP stream number
# 2. the number of seconds before the last TCP segment in the file and the
#    last segment in the stream. A stream that ends with 3 retransmissions
#    0.5 seconds before the last TCP segment in the trace is less likely to
#    have failed then one that ends 200 seconds before the last TCP segment
#    since there is less time to receive the ACK. Anything less than 0.1
#    seconds is ignored    
# 3. The first IP address and the number of its unACKed bytes
# 4. The second IP address and number of its unACKed bytes

# This is followed by the last 20 lines of the TCP stream with the columns
# 1. TCP stream number
# 2. time since start of trace file (relative time)
# 3. source IP address
# 4. source port
# 5. destination IP address
# 6. destination port
# 7. IP ID (this makes it easy to spot duplicated packets)
# 8. IP TTL (makes it easy to see which IP address is local)
# 9. TCP sequence number
# 10. TCP ACK number
# 11. TCP length
# 12. FIN flag (1 == FIN)
# 13. TCP reset flag (1 == RST)
# 14. tshark expert info

# And this is followed by a list of TCP streams where the only segments in 
# the stream where SYN segments. technically these are not TCP connections
# that have failed because of retransmissions since the connection was never
# completed. 

# In addition as the script is running it prints out the stream number that
# it is currently processing. You can look at the partial results by
# monitoring the file /tmp/find-retran-failures-3.


# Version 1.0 March 20, 2018

FINDRETRANFAILURESVERSION="1.0_2018-03-20"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


if [ $# -ne 1 ] && [ $# -ne 2 ]
   then echo "Usage:"
        echo "   find-retran-failures.sh FILE [FILTER]"
        echo "      FILE is the name of one file"
        echo "      FILTER is a tshark display filter string"
        exit
fi

FILE=$1

if [ $# -eq 2 ]
   then FILTER=$2
fi

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
   then DASH="-R"
fi

# make sure that we are starting with a clean slate

rm -f /tmp/find-retran-failures-1
rm -f /tmp/find-retran-failures-2
rm -f /tmp/find-retran-failures-3
rm -f /tmp/find-retran-failures-4
rm -f /tmp/find-retran-failures-5

# read all the TCP segments, don't be confused by ICMP

if [ $# -eq 1 ]
   then tshark -r $FILE -Y "tcp && not icmp" -T fields -e tcp.stream \
        -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst \
        -e tcp.dstport -e ip.id -e ip.ttl -e tcp.seq -e tcp.ack -e tcp.len \
        -e tcp.flags.fin -e tcp.flags.reset -e _ws.expert \
         > /tmp/find-retran-failures-1
   else tshark -r $FILE -Y "tcp && not icmp && ($FILTER)" -T fields \
        -e tcp.stream -e frame.time_relative -e ip.src -e tcp.srcport \
        -e ip.dst -e tcp.dstport -e ip.id -e ip.ttl -e tcp.seq -e tcp.ack \
        -e tcp.len -e tcp.flags.fin -e tcp.flags.reset -e _ws.expert \
         > /tmp/find-retran-failures-1
fi

# If no streams where found report that and quit

if [ $(cat /tmp/find-retran-failures-1 | wc -l) -eq 0 ]
   then echo "tshark did not find any TCP streams - exiting"
        exit
fi

# record the timestamp of the last TCP segment. not exactly the last frame in
# the trace but close enough unless I want to read the trace file twice --
# which I don't want to do.

LASTTIME=$(tail -1 /tmp/find-retran-failures-1 | awk '{print $2}')

# Also find the last TCP stream number

LASTSTREAM=$(sort -nk1 /tmp/find-retran-failures-1 | tail -1 | \
           awk '{print $1}')

# Loop through the text file -- once for each stream and write out the last
# 20 segments of that stream. 20 is arbitrary but I figure it is enough

echo -n current stream: 
for x in $(seq 0 $LASTSTREAM)
   do echo -n "$x, "
      grep "^$x\s" /tmp/find-retran-failures-1 | \
      while read stream time sip sport dip dport ipid ittl tseq tack \
            tlen fin reset expert
      do
         echo $stream $time $sip $sport $dip $dport $ipid $ittl $tseq $tack \
             $tlen $fin $reset $expert
      done | tail -20 > /tmp/find-retran-failures-2

# If there are at least 2 retransmissions or duplicate ACKs or out of order
# packets (which could be a mis-dentified retransmission) in the last 20 lines
# then we need to look more closely.

      if [ $(grep -m 1 -E "retrans|out|Dup" /tmp/find-retran-failures-2 | wc -l) \
         -gt 2 ]

# Calculate the time difference between the last segment in the stream and the
# last TCP segment in the trace. If the time is < 0.100 seconds there is not
# enough time to conclude that no ACK will be received so skip the stream.

         then DELTAEND=$(awk -v lasttime=$LASTTIME '{print lasttime-$2}' \
                   /tmp/find-retran-failures-2 | tail -1)
              if [ $(echo $DELTAEND "<" 0.100 | bc) -eq 1 ]
                  then continue
              fi

# For each IP address, ip1 and ip2, calculate the largest expected ACK by
# adding the sequence number to the tcp length plus 1 for a FIN and sorting.
# This is the "ns" value. Then find the largest ACK from the other IP address.
# If the difference is 0 we know that all data has been ACKed no
# retransmission failure. Note that there is 1 failure scenario this will not
# identify. If the sender is the remote host and its not getting the local
# hosts ACKs we will see all data being ACKed so will not recognize any
# problem.

              cat /tmp/find-retran-failures-2 | awk '{print $3}' | sort -u \
                  > find-retran-failures-4
              ip1=$(head -1 find-retran-failures-4)
              ip2=$(tail -1 find-retran-failures-4)
              ip1ns=$(awk -v ip1=$ip1 '($3 == ip1) {print $9 + $11 + $12}' \
                        /tmp/find-retran-failures-2 | sort -n | tail -1)
              ip2a=$(awk -v ip2=$ip2 '($3 == ip2) {print $10}' \
                        /tmp/find-retran-failures-2 | sort -n | tail -1)
              ip2ns=$(awk -v ip2=$ip2 '($3 == ip2) {print $9 + $11 + $12}' \
                        /tmp/find-retran-failures-2| sort -n | tail -1)
              ip1a=$(awk -v ip1=$ip1 '($3 == ip1) {print $10}' \
                        /tmp/find-retran-failures-2 |sort -n | tail -1)
              D1=$((ip1ns - ip2a))
              D2=$((ip2ns - ip1a))
              if [ $D1 -eq 0 ] && [ $D2 -eq 0 ]
                 then continue
              fi

# if one of the ACK numbers is 1 greater than the ns number and the other
#  number is 0 what we probably have is keep alive sequence so again no
# retransmission failure.

  	      if [ $D1 -eq 0 ] && [ $D2 -eq -1 ]
                 then continue
              fi
              if [ $D1 -eq -1 ] && [ $D2 -eq 0 ]
                 then continue
              fi

# at least 1 IP has sent a FIN and a RESET probably just shutting down the
# connection and not waiting for the other IP to send its FIN

              if [ $(grep "$ip1.*$ip2.*FIN" /tmp/find-retran-failures-2 | \
                   wc -l) -gt 0 ] && \
                 [ $(grep "$ip1.*$ip2.*RST" /tmp/find-retran-failures-2 | \
                   wc -l) -gt 0 ]
                 then continue
              fi
 
              if [ $(grep "$ip2.*$ip1.*FIN" /tmp/find-retran-failures-2 | \
                   wc -l) -gt 0 ] && \
                 [ $(grep "$ip2.*$ip1.*RST" /tmp/find-retran-failures-2 | \
                   wc -l) -gt 0 ]
                 then continue
              fi

# the only segments are SYN segments. We probably have a failure to establish
# a connection not the same as a failure in the middle of a connection. Sill
# keep a record of the streams and list them at the end

              if [ $(grep -v SYN  /tmp/find-retran-failures-2 | wc -l) -eq 0 ]
                 then echo $x >> /tmp/find-retran-failures-5
                      continue
              fi

# At this point we have what looks like a retransmission failure

              (echo =======================================================
               echo TCP Stream: $x "    " Ends $DELTAEND seconds before trace ends "    " \
                    $ip1 "bytes unACKed: " $D1 "    " $ip2 "bytes UnACKed" $D2
               echo =======================================================
               cat /tmp/find-retran-failures-2
               echo =======================================================) \
                   >> /tmp/find-retran-failures-3
         fi         
   done

# OK we are done, echo a line to get a new line after the list of streams
# processed

echo

# and dump out the -3 file or indicate that nothing was found

if [ -f /tmp/find-retran-failures-3 ]
   then cat /tmp/find-retran-failures-3
   else echo No TCP connections appear to have failed due of retransmissions
fi

# now list the Streams with only SYN segments

if [ -f /tmp/find-retran-failures-5 ]
   then echo
        echo
        echo =======================================================
        echo The following streams contain nothing but SYN segments
        echo =======================================================
	cat /tmp/find-retran-failures-5 | tr "\n" ", " | sed "s/,$//g"
        echo
fi

# find-retran-failures.sh ends here
