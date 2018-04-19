#!/bin/bash
# analyze-arps.sh begins on the previous line
#
# This macro uses tshark filter on all ARP packets in a packet trace file,
# printing the relative time of each ARP frame as well as the ARP header's
# source hardware MAC, source IPv4 address, opcode, destination hardware MAC
# destination hardware IPv4 addresses and the frames Ethernet source address
# or the SLL src Ethernet address if the frame has an SSL header instead of
# an Ethernet header. It then processes the frames calculating the time
# between an ARP request (opcode == 1) and reply (opcode == 2) asd well as
# counting the number of requests without a response. It will also count
# gratuitous ARPs and ARP replies without a corresponding request. In addition
# it tries to identify duplicate IP addresses, i.e. The same IP address with 2
# (or more) different MAC addresses and also duplicate MACs, a mac address
# with multiple IP addresses. While duplicate IPs is almost always a problem
# duplicate MACs may not indictae a problem, for example two IPs on the same
# physical interface, or a device doing proxy ARPs. 

# output will look like

# $ ./analyze-arps.sh trace-1.pcapng
# analyze-arps.sh trace-1.pcapng
# Normal responses:
# Request-time     Source-IP      Target-IP      Reply-from-MAC     Reply-time       Delta-time
# 1.043783252      192.168.1.207  192.168.1.1    a0:04:60:89:47:78  1.043985651      .000202399
# 22.285249058     192.168.1.200  192.168.1.48   00:10:75:4f:b3:6e  22.285428326     .000179268
# 22.376849133     192.168.1.200  192.168.1.1    a0:04:60:89:47:78  22.377140059     .000290926
# 34.750269513     192.168.1.48   192.168.1.207  6c:0b:84:67:fe:62  34.750283475     .000013962
# 53.167904018     192.168.1.19   192.168.1.200  52:54:00:8a:8b:6d  53.168060303     .000156285
# 53.173934457     192.168.1.21   192.168.1.200  52:54:00:8a:8b:6d  53.174181599     .000247142
# 54.002637415     192.168.1.21   192.168.1.200  52:54:00:8a:8b:6d  54.002836446     .000199031
# 56.819787204     192.168.1.207  192.168.1.1    a0:04:60:89:47:78  56.819975909     .000188705
# 92.867790453     192.168.1.207  192.168.1.1    a0:04:60:89:47:78  92.867989455     .000199002
# . . . . .
#
# No response:
# Number_of_Requests  Source-IP     Target-IP
# . . . . 
# 1                   192.168.1.5   192.168.1.3
# 1                   192.168.1.5   192.168.1.4
# 2                   0.0.0.0       192.168.1.18
# 2                   192.168.1.1   192.168.1.18
# 2                   192.168.1.19  192.168.1.48
# 2                   192.168.1.21  192.168.1.48
# 3                   0.0.0.0       192.168.1.20
# 3                   192.168.1.48  192.168.1.200
# 4                   192.168.1.11  192.168.1.1
# 4                   192.168.1.1   192.168.1.21
# 4                   192.168.1.21  192.168.1.12
# 6                   192.168.1.8   192.168.1.13
# 290                 192.168.1.5   192.168.1.1
# 796                 192.168.1.6   192.168.1.1
# 1024                192.168.1.3   192.168.1.1
# 1054                192.168.1.20  192.168.1.1
# 
# 
# Gratuitous ARPs
# Number-of-ARPs  Source-IP
# 1               192.168.1.20
# 4               192.168.1.200
# 
# Duplicate IPs
# Frame-Source       ARP.src_hw_mac     Source-IP
# 00:09:5b:bc:cb:c9  00:09:5b:bc:cb:c9  192.168.1.200
# 52:54:00:8a:8b:6d  52:54:00:8a:8b:6d  192.168.1.200
#
# The sections for No, responses, Gratuitous ARPs, Duplicate IPs and
# Duplicate MACs are only printed if they have sonething in them. If
# no ARPs are found in the trace file it will report that
#
# $ ./analyze-arps.sh trace-2.pcap
# analyze-arps.sh trace-2.pcap
# Normal responses:
# No ARP Request/Replies found
#
#
# Version 1.0 Arpril 18, 2018

ANAYZEARPSVERSION="1.0_2018-04-18"

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
        echo "   analyze-arps.sh FILE"
        echo "      FILE is the name of the trace file"
        exit
fi

# just making sure that the file exists.

if [ ! -e "$1" ]
   then echo "Could not find input file $1"
   exit
fi

FILE=$1

# echo the command line to confirm the arguments

echo "analyze-arps.sh $FILE"

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# clean up old files

rm -f /tmp/analyze_arps-*

EXPECTREPLY=0

# print out the header information into a temporay file. Note that the last
# field outrput is either the Ethernet source address of the SLL source
# address. You will get an SLL header if the "any" device is used for the
# trace capture device.

tshark -r $FILE $DASH "arp" -T fields -e frame.time_relative  \
       -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.opcode \
       -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e eth.src \
       -e sll.src.eth > /tmp/analyze_arps-1

# insert a line to flag the end of the data set
echo "0.0 00 999.999.999.999 1 00 999.999.999.999 00" >>  /tmp/analyze_arps-1

awk '{if ($4 == 1) print $3 " " $6; else print $6 " " $3}' \
      /tmp/analyze_arps-1 | sort -u | while read src dst
      do awk -v s=$src -v d=$dst '(($3 == s && $4 == 1 && $6 == d) || \
                                   ($3 == d && $4 == 2 && $6 == s))' \
         /tmp/analyze_arps-1
        done |

while read time smac sip op dmac dip ethsllsrc
      do

# echo $time $smac $sip $op $dmac $dip $ethsllsrc

# If the source is 999.999.999.999  we are done. If we are still expecting a
# reply write it out. Either way exit 
         if [ $sip == "999.999.999.999" ]
         then if [ $EXPECTREPLY -eq 1 ]
              then echo $oldsip $olddip >> /tmp/analyze_arps-3
              fi
              exit

# Source equals destination implies a Gratuitous ARP
         elif [ "$sip" == "$dip" ]
         then
            echo $sip >> /tmp/analyze_arps-2
            continue

# see a request, save everything
         elif [ $op  -eq 1 ] && [ $EXPECTREPLY -eq  0 ] 
         then
            oldtime=$time
            oldsmac=$smac
            oldsip=$sip
            olddmac=$dmac
            olddip=$dip
            EXPECTREPLY=1

# Expecting a reply and see another request, write the previous request to the
# unanswered file
         elif [ $op  -eq 1 ] && [ $EXPECTREPLY -eq  1 ] 
         then
            echo $oldsip $olddip >> /tmp/analyze_arps-3
            oldtime=$time
            oldsmac=$smac
            oldsip=$sip
            olddmac=$dmac
            olddip=$dip
            EXPECTREPLY=1

# See a reply but not execting it, write it to the unexpected reply file
         elif [ $op  -eq 2 ] && [ $EXPECTREPLY -eq  0 ]  
         then
            echo "at $time unexpected reply for $sip from $smac/$sip" >> /tmp/analyze_arps-4
            EXPECTREPLY=0

# Expecting a reply and see a reply
         elif [ $op  -eq 2 ] && [ $EXPECTREPLY -eq  1 ]  
         then
            echo $oldtime $oldsip $olddip $smac $time \
               $(echo $time - $oldtime | bc) >> /tmp/analyze_arps-5
            EXPECTREPLY=0
         fi
      done

echo "Normal responses:"
if [ -e "/tmp/analyze_arps-5" ]
   then (echo Request-time Source-IP Target-IP Reply-from-MAC \
              Reply-time Delta-time
         sort -nk1 /tmp/analyze_arps-5) | column -t
   else echo "No ARP Request/Replies found"
fi

if [ -e "/tmp/analyze_arps-3" ]
   then echo; echo "No response:"
        (echo Number_of_Requests Source-IP Target-IP
         cat /tmp/analyze_arps-3 | sort | uniq -c | sort -nk1) | column -t
fi

if [ -e "/tmp/analyze_arps-4" ]
   then echo; echo "Unexpected Reply"
        cat /tmp/analyze_arps-4
fi

if [ -e "/tmp/analyze_arps-2" ]
   then echo; echo "Gratuitous ARPs"
        (echo Number-of-ARPs Source-IP
         cat /tmp/analyze_arps-2 | sort | uniq -c) | column -t
fi

if [ -e "/tmp/analyze_arps-7" ]
   then echo; echo "Duplicate IPs"
        (echo Frame-Source ARP.src_hw_mac Source-IP
         cat /tmp/analyze_arps-7) | column -t
fi

# Look for duplicate IP addresses, that is 1 source IP with 2 different
# frame source addresses and or arp.src.hw_mac addresses

awk '!($3 == "0.0.0.0")' /tmp/analyze_arps-1 | awk '{print $7 " " $2 " " $3}' \
    | sort -u > /tmp/analyze_arps-6;
awk '{print $3}' /tmp/analyze_arps-6 | sort | uniq -c | awk '($1 > 1)' \
  | awk '{print $2}' | while read ip
  do
    awk -v ip=$ip '($3 == ip)' /tmp/analyze_arps-6
  done > /tmp/analyze_arps-7

if [ $(cat /tmp/analyze_arps-7 | wc -l) -gt 0 ]
   then echo; echo "Duplicate IPs"
        (echo Frame-Source ARP.src_hw_mac Source-IP
         cat /tmp/analyze_arps-7) | column -t
fi

# Look for replies from 1 arp.src.hw_mac with 2 or more  different 
# IP addresses

awk '($4 == 2)' /tmp/analyze_arps-1 | awk '{print $2 " " $3}' \
    | sort -u > /tmp/analyze_arps-8;
awk '{print $1}' /tmp/analyze_arps-8 | sort | uniq -c | awk '($1 > 1)' \
  | awk '{print $2}' | while read mac
  do
    awk -v mac=$mac '($1 == mac)' /tmp/analyze_arps-8
  done > /tmp/analyze_arps-9

if [ $(cat /tmp/analyze_arps-9 | wc -l) -gt 0 ]
   then echo; echo "Duplicate MACs"
        (echo ARP.src_hw_mac Source-IP
         cat /tmp/analyze_arps-9) | column -t
fi



