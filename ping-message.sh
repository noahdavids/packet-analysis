#!/bin/bash
# ping-message.sh begins on the previous line
#
# This macro makes use of the "-p (pad) option of ping to embed 16 characters
# into an ICMP echo (ping) message. The 16 characters are supplied as an
# argument to the script
#
# When tracing a multipart activity you can use the messages to indicate in
# the packet stream where 1 activity stops and another starts.
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

if [ $# -ne 2 ]
   then echo "Usage:"
        echo "   ping-message.sh TARGET-IP" "MESSAGE"
        echo "      TARGET-IP is the IP address or name of the target host"
        echo "      MESSAGE any 16 characaters, if there are spaces the string"
        echo "         should be enclosed in quotes. Messages longer than 16 "
        echo "         characters are truncated at 16 characters. Messages"
        echo "         shorter than 16 characters are padded with spaces."
        echo "Example:"
        echo "   ping-message.sh 192.168.1.13 \"message 1\""
        exit
fi

TARGET=$1
MESSAGE="$2"
# First add 16 spaces to the end of the message and then cut the message at
# 16 characters - basically pad the message with spaces if it is less than 16
# character without bothering to figure out the actual length. Next use od -x
# to convert it to hex. Then the awk command takes the hex characters flips
# the nibbles around and remove the spaces in the string that od produces,
# not the spaces in the message. The string of hex chacaters is the "-p"
# argument to ping. The other arguments are
# -b allow pinging a broadcast address
# -q for quite
# -c 1 send only 1 ping
# -s 32 packet size is 32 bytes, 8 bytes representing the epoch time to the
#    second, 8 bytes of something else and the 16 bytes of pad characters
#    which is the message.

ping -b -q -c 1 -s 32 -p $(echo $MESSAGE "                " | cut -c 1-16 | \
     od -x | head -1 | awk '{for (i=2; i <=NF; i++) printf ("%s%s", \
                     substr ($i, 3, 2), substr ($i, 1, 2))}') $TARGET \
                     2>/dev/null >/dev/null
# ping-message.sh ends here


