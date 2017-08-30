#!/bin/bash
# time-summary.sh begins on the previous line
#
# This macro finds all pcap files in the current directory tree and uses
# capinfos to sort them by start time.
#
# Note that version 1 of capinfos will not sort correctly if the set of files
# spans multiple months. See example 1
#
# Version 1.0 August 24 2017
# Version 1.1 August 29 2017
#   Changed to handle the different format between capinfos versions 1.x
#   and 2.x
#
#TIMESUMMARYVERSION="1.1_2017-08-29"
#
# from https://github.com/noahdavids/packet-analysis.git
#
# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

if [ $# -eq 0 -o $# -gt 2 ]
   then echo "Usage:"
        echo "   time-summary.sh FILE-FILTER"
        echo "      FILE-FILTER is a string that idenifies the files"
        echo "      NEGATIVE-FILTER strings to filter out of the file list"
        exit
fi
FILTER=$1

if [ $# -eq 2 ]
   then 
      for x in $(find . -type f | grep -E $FILTER | grep -E -v $2); do capinfos -ae $x | grep -v "Packet size limit:"; echo; done | tr "\n" " " | sed "s/File name:/\n/g" > /tmp/time-summary-1
   else
       for x in $(find . -type f | grep -E $FILTER); do capinfos -ae $x | grep -v "Packet size limit:"; echo; done | tr "\n" " " | sed "s/File name:/\n/g" > /tmp/time-summary-1
fi

if [ $(grep "First packet time" /tmp/time-summary-1 | wc -l) -gt 0 ]
   then
     cat /tmp/time-summary-1 | awk '{print $5 " " $6 " - " $10 " " $11 " " $1}' | sort    
   else
     cat /tmp/time-summary-1 | awk '{print $5 " " $6 " " $7 " - " $12 " " $13 " " $14 " " $1}' | sort
fi

