#!/bin/bash
# check_subnet.sh begins on the previous line
#
# This macro compares a target IPv4 address with a subnet of the form X.X.X.X/NN
# and prints out TRUE if the target in in the subnet and FALSE if it is not.
# sinple to do for 1 or 2 addresses and 1 or 2 subnets but if you have many
# addresses or subnets you do not want to do it by eyeball.
#
# Note this script relies on ipcalc to calculate the minimum and maximum IP
# addresses
#
# Version 1.0 November 27, 2019
# Version 1.1 Novemebr 29, 2019
#   modified to handle ipcalc versions that don't have the
#   --network && --braodcast arguments

CHECKSUBNETVERSION="1.1_2019_11_29"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

TARGET=$1
SUBNET=$2

if [ $(man ipcalc | grep "\-\-network" | wc -l) -gt 0 ]
   then
        echo $TARGET $(ipcalc --network $SUBNET | tr "=" " ") \
                     $(ipcalc --broadcast $SUBNET | tr "=" " ") | \
             while read ip x network y broadcast
             do echo -n $ip $SUBNET Netowork=$network Broadcast=$broadcast " "
                echo $ip $network $broadcast | tr "." " " | \
                awk '{print ((($1*256 + $2)*256 +$3)*256) + $4 " " \
                            ((($5*256 + $6)*256 +$7)*256) + $8 " " \
                            ((($9*256 + $10)*256 +$11)*256) + $12}' | \
                     awk '{if (($1 > $2) && ($1 < $3)) print "TRUE"; else print "FALSE"}'
             done
    else
        echo $TARGET $(ipcalc $SUBNET | grep HostM | awk '{print $2}') | \
             while read ip HostMin HostMax
             do echo -n $ip $SUBNET HostMin=$HostMin HostMax=$HostMax " "
                echo $ip $HostMin $HostMax | tr "." " " | \
                awk '{print ((($1*256 + $2)*256 +$3)*256) + $4 " " \
                            ((($5*256 + $6)*256 +$7)*256) + $8 " " \
                            ((($9*256 + $10)*256 +$11)*256) + $12}' | \
                     awk '{if (($1 >= $2) && ($1 <= $3)) print "TRUE"; else print "FALSE"}'
             done
fi

#
# check_subnet ends here

