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
#     Server ID Type Name Rcode Response-time - Query-time = Delta-time
#
# It also lists unanswered queries in the table
#     Server ID Type Name Query-time
#
# Type ==  1 Type A host address
# Type == 12 domain name PRT query
# Type == 28 Type AAAA IPv6 host address
#
# Rcode == 0 normal, no error response
# Rcode == 2 Server failure
# Rcode == 3 No such name
#
# Version 1.0 March 15, 2017
# Version 1.1 April 01, 2017
#    Added copyright and GNU GPL statement and disclaimer
# Version 1.3 October 7, 2017
#    Added a check to make sure that the found response has 1 query. If not
#    just skip it. Had a trace with multiple responses and no queries. Also
#    removed non-printing characters from the output. Queries had control
#    characters and bytyes > 127 in the names and the causes column to barf.
#    Finally check that the output line in /tmp/dns-time-1 has all 13 fields.
#    Had some malformed queries that did not have all the fields and that
#    screwed things up as well.
# Version 1.4 October 12, 2017
#    Added support for IPv6 client and server addresses
# Version 1.5 February 13, 2018
#    Added the dns.flags.rcode to the output to distinguish between a 
#    response that actually provided an answer and one which did not. Also
#    added some comments for various DNS types and rcodes.

DNSTMEVERSION="1.5_2018-02-11"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

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
# queried, the query type and the query response code to /tmp/dns-time-1.
# Also filter out ICMP records. This removes ICMP destination unreachable and
# any other errors. Finally filter the output to make sure it has only
# printable and white space characters. This is needed because some
# dns.qry.name strings have non-printing characters that that causes errors in
# some of the subsequent commands. Also  make sure that there are 14 fields
# (frame.time will have 5 fields, month day, year, time, time-zone). If the
# DNS record is malformed we can get a line without complete data which will
# also screw things up later on. Note that I am selecting both IPv4 and IPv6
# addresses only 1 type per frame will print so it doesn't hurt anything to
# "print" both.

tshark -r "$FILE" $DASH "not icmp && (udp.port == 53 || tcp.port == 53)" \
      -T fields -e frame.number -e frame.time_epoch -e frame.time \
      -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst \
      -e dns.id -e dns.flags.response -e dns.qry.name \
      -e dns.qry.type -e dns.flags.rcode | tr -dc [:graph:][:space:] | \
       awk '{ if (NF == 14) print $0; else if (NF == 13) print $0 " -"}' \
       > /tmp/dns-time-1

# For every line in the dns-time-1 which is a response (column 11 (flags)
# is 1 extract out the Server IP (column 8), client IP (column 9), transaction
# ID (column 10), the name being queried (column 12), the query type (column
# 13) and the response code (column 14).

awk '($11 == 1) {print $8 " " $9 " " $10 " " $12 " " $13 " " $14}' \
    /tmp/dns-time-1 | sort -u | while read server client id name type rcode
   do

# Search for the client, server, id, name, type and response == 0 values to get
# the request time and then server, client, id, name, type response == 1 values
# to get the matching response time and write the epoch time (column 2) and
# the human readable time (column 6) (but not the month, day or year) lines to
# dns-time-2, keep only the first line then do the same for the response
# keeping only the first line -- on the theory that the fist answer will move
# things forward and subsequent answers will be ignored. Note that for the
# response the order of the IP addresses are reversed, i.e. server then client.

       grep $client.*$server.*$id.*0.*$name.*$type /tmp/dns-time-1 | \
       awk '{print $2 " " $6}' | head -1 > /tmp/dns-time-2
       grep $server.*$client.*$id.*1.*$name.*$type /tmp/dns-time-1 | \
       awk '{print $2 " " $6}' | head -1 >> /tmp/dns-time-2

# dns-time-2 should have 2 lines, remove the new line so there
# is only 1 line then print out the human readable time of the response
# column 4 "-" the human readable time of the query (column 2) " = "
# the difference in the epoch times of response (column 3) and query
# (column 1). If there aren't two lines just skip it.

       if [ $(cat /tmp/dns-time-2 | wc -l) -eq 2 ] 
          then echo $server $id $type $name $rcode \
            $(cat /tmp/dns-time-2 | tr "\n" " " | \
                    awk '{print $4 " - " $2 " = " $3-$1}')
       fi

# end of the while loop and everything goes into a third temporary file

       done > /tmp/dns-time-3

# put a nice header on it and write out dns-time-3 and run it through
# column to make a nice table

(echo Server ID Type Name Rode Respose-time - Query-time = Delta-time
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


