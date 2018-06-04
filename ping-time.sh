#!/bin/bash
# ping-time.sh begins on the previous line
#
# This macro makes use of the "-p (pad) option of ping to embed 16 characters
# into an ICMP echo (ping) message. The 16 characters are the current time
# to the nearest tenth of a micro second and have the format HH:MM:SS.sssssss
#
# This lets you correlate the time recorded by the system which captured a
# packet trace with the time time on the system that sent the packet. This
# can prevent confusion when the sender records an event at time T and the
# packet trace or the logs on the capturing system show nothing significant
# at that time.
#
# Note that no output is sent to either STDOUT or STDERR everything is
# redirected to /dev/null. 

PINGDTVERSION="1.0_2018-06-03"
#
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
        echo "   ping-time.sh TARGET-IP"
        echo "      TARGET-IP is the IP address or name of the target host"
        echo "Example:"
        echo "   ping-time.sh 192.168.1.207"
        exit
fi

TARGET=$1

# date +%H:%M:%S.%N generates a date string of the format
#    HH:MM:SS.sssssssss or 20:35:44.148741603
# cut -c 1-16 extracts out the HH:MM:SS.sssssss string. Note that the
# last 2 digits are missing. The pad string can only be 16 characters.
#    20:35:44.1487416
# od -x converts it to hex and head -1 takes only the first line
#    0000000 3032 333a 3a35 3434 312e 3834 3437 3631
# the awk command takes the hex characters flips the nibbles around and
# removes the spaces
#    32303a33353a34342e31343837343136
# the above string of hex chacaters is the "-p" argument to ping. The other
# arguments are
# -b allow pinging a broadcast address
# -q for quite
# -c 1 send only 1 ping
# -s 32 packet size is 32 bytes, 8 bytes representing the epoch time to the
#    second, 8 bytes of something else and the 16 bytes of pad characters

ping -b -q -c 1 -s 32 -p $(date +%H:%M:%S.%N | cut -c 1-16 | \
     od -x | head -1 | awk '{for (i=2; i <=NF; i++) printf ("%s%s", \
                     substr ($i, 3, 2), substr ($i, 1, 2))}') $TARGET \
                     2>/dev/null >/dev/null
#
# ping-time.sh ends here

