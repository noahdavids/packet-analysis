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
# Version 1.2 August 30 2017
#   The 1x version of capinfos will not correctly if you just sort on the date
#   because the date format is Month day time. April and August will sort 
#   first. Rewrtten to first output the start time in epoch time, sort the
#   first on tha list and then just process each file in order. This isn't
#   needed for capinfso 2x where the date is YYYY-MM-DD time. But the script
#   does it anyway. 
#
#TIMESUMMARYVERSION="1.2_2017-08-30"
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

# list all the files
if [ $# -eq 2 ]
   then 
      find . -type f | grep -E $FILTER | grep -E -v $2 > /tmp/time-summary-1
   else
      find . -type f | grep -E $FILTER > /tmp/time-summary-1
fi

# Get the start time in epoch time for each file and sort the file list. The
# time is the last column but the label will vary ("Start time" or "First
# packet time") depending on capinfos version. So I copy the time from the
# last column to the first column and sort on the first column. Then extract
# the file name in the second column.
cat /tmp/time-summary-1 | while read file; do capinfos -aS $file \
    |  tr "\n" " " | sed "s/File name:/\n/g" | awk '{print $NF " " $0}'; \
    done | sort -nk1 | awk '{print $2}' > /tmp/time-summary-2

# for each file get the start and stop time in human readable time. Note
# that /tmp/time-summary-2 will have blank lines the $(#file) returns
# the number of characters in the $file so I test for 0 to skip the
# blank lines. Also if the packets have been size limited there is a message
# the "grep -v" filters out the line with that message.
cat /tmp/time-summary-2 | while read file; do if [ "${#file}" -gt 0 ]; then \
    capinfos -ae $file | grep -v "Packet size limit" | tr "\n" " " \
    | sed "s/File name:/\n/g"; fi; done > /tmp/time-summary-3

# create a table "start-time" - ""end-time" File-path. The first line in
# /tmp/time-summary-3 is blank, the "(NF > 1)" awk test skips that line.
if [ $(grep "First packet time" /tmp/time-summary-3 | wc -l) -gt 0 ]
   then
     cat /tmp/time-summary-3 | awk '(NF > 1) {print $5 " " $6 " - " $10 " " \
         $11 " " $1}' | column -t
   else
     cat /tmp/time-summary-3 | awk '(NF > 1) {print $5 " " $6 " " $7 " - " \
         $12 " " $13 " " $14 " " $1}' | column -t
fi

