#!/bin/bash
# dns-times.sh begins on the previous line
#
# This macro uses tshark to find DNS (port 53) queries and calculate the
# time between query and response. It differs from the dns.time value
# caculated by wireshark in that it calculates the time between the first
# response for transaction ID X and the first query for transaction X not
# the first response and last query for transaction X.
#
# The output is a a table with the following columns.
#     Server ID Type Name Response-time - Query-time = Delta-time
#
# It also lists unanswered queries in the table
#     Server ID Type Name Query-time

# Version 1.0 March 15, 2017
DNSTMEVERSION="1.0_2017-03-15"

# This software is provided on an "AS IS" basis, WITHOUT ANY WARRANTY OR ANY
# SUPPORT OF ANY KIND. The AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES
# OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE.  This disclaimer
# applies, despite any verbal representations of any kind provided by the
# author or anyone else.

# from https://github.com/noahdavids/packet-analysis.git


if [ $# -ne 1 ]
   then echo "Usage:"
        echo "   dns-time.sh FILE"
        echo "       FILE is the name of the trace file to be analyzed"
   exit
fi

FILE=$1

if [ ! -e "$FILE" ]
   then echo "Could not find input file $FILE"
   exit
fi

# I always echo the command and arguments to STDOUT as a sanity check

echo dns-time.sh "$FILE"


# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# Scan the packet capture file for DNS traffic and write the frame number
# the epoch time and human readable time, the IP source and destination, the
# transaction  ID, a flag for query (0) or response (1), the name being
# queried, and the query type to /tmp/dns-time-1. Also filter out ICMP records
# This removes ICMP destination unreachable and any other errors.

tshark -r "$FILE" $DASH "not icmp && (udp.port == 53 || tcp.port == 53)" \
      -T fields -e frame.number -e frame.time_epoch -e frame.time \
      -e ip.src -e ip.dst -e dns.id -e dns.flags.response -e dns.qry.name \
      -e dns.qry.type > /tmp/dns-time-1

# For every line in the dns-time-1 which is a response (column 11 (flags)
# is 1 extract out the Server IP (column 8), client IP (column 9), transaction
# ID (column 10), the name being queried (column 12) and the query type
# (column 13).

awk '($11 == 1) {print $8 " " $9 " " $10 " " $12 " " $13}' /tmp/dns-time-1 | \
    sort -u | \
   while read server client id name type
   do

# Echo the server, id, type and name values and then (inside the parens)
# extract from dns-time-1 the queries by matching on the lines
# matching the Client, Server, ID, Query Flag (0), name and type and 
# writing the epoch time (column 2) and the human readable time (column 6)
# (but not the month, day or year) lines to dns-time-2, keep only the first
# line then do the same for the response keeping only the first line -- on
# the theory that the fist answer will move things forward and subsequent
# answers will be ignored. Note that for the response the order of the IP
# addresses are reversed, i.e. server then client.

       echo $server $id $type $name  $( \
       grep $client.*$server.*$id.*0.*$name.*$type /tmp/dns-time-1 | \
       awk '{print $2 " " $6}' | head -1 > /tmp/dns-time-2
       grep $server.*$client.*$id.*1.*$name.*$type /tmp/dns-time-1 | \
       awk '{print $2 " " $6}' | head -1 >> /tmp/dns-time-2

# dns-time-2 should have 2 lines, remove the new line so there
# is only 1 line then print out the human readable time of the response
# column 4 "-" the human readable time of the query (column 2) " = "
# the difference in the epoch times of response (column 3) and query
# (column 1)
 
       cat /tmp/dns-time-2 | tr "\n" " " | \
         awk '{print $4 " - " $2 " = " $3-$1}')

# end of the while loop and everything goes into a third temporary file

       done > /tmp/dns-time-3

# put a nice header on it and write out dns-time-3 and run it through
# column to make a nice table

(echo Server ID Type Name Response-time - Query-time = Delta-time
 cat /tmp/dns-time-3) | column -t


# now list the queries without an answer

echo
echo
echo Unanswered queries

# First echo a table header line

(echo Server ID Type Name Query-time

# For each query (column 11 == 0) extract the query time, client and
# server IP the transaction ID, name and type.  Count the number of response
# by looking for lines that are server client ID response flag (1) name and
# type. If there are no matching lines print out server, id, type name and
# time. Again run everything through column to make a nice table

awk '($11 == 0) {print $6 " " $8 " " $9 " " $10 " " $12 " " $13}' /tmp/dns-time-1 | \
   while read time client server id name type
   do
      if [ "0" == $(grep $server.*$client.*$id.*1.*$name.*$type /tmp/dns-time-1 | wc -l) ]
      then echo $server $id $type $name $time
      fi
   done) | column -t

# clean up the temporary files

rm /tmp/dns-time-1
rm /tmp/dns-time-2
rm /tmp/dns-time-3

# dns-time.sh stops here


