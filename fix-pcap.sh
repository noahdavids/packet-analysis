#!/bin/bash
# fix-pcap.sh begins on the previous line
#
# This macro fixes pcap that end in a middle of a packet. It does this by
# reading the file and writing a new file. The damaged packet will not
# be written. It then renames the newly output file back to the original
# name.
#
# Version 1.0 August 24 2017
# Version 1.1 September 6, 2017
#   Added a test to see if the file exists before trying to read it
#
#FIXPCAPVERSION="1.1_2017-09-06"
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

if [ $# -ne 1 ]
   then echo "Usage:"
        echo "   fix-pcap.sh FILE"
        echo "      FILE is a string that idenifies the file"
        exit
fi
FILE=$1

if [ -f $FILE ]
  then
     tcpdump -r $FILE -w /tmp/fix-pcap.pcap
     mv /tmp/fix-pcap.pcap $FILE
  else
     echo Could not find $FILE 
fi

