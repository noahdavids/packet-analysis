#!/bin/bash
# build-filter.sh begins on the previous line
#
# This macro reads a list from a file and builds a tshark filter
# comparing each item in the list to a tshark variable which is input
# as an argument. THe items are then either ANDed or ORed as specified
# by a second argument. 

# Version 1.0 August 30 2017
# Version 1.1 September 7, 2017
#    typos in the comments corrected.

BUILDFILTERVERSION="1.1_2017-09-07"

# from https://github.com/noahdavids/packet-analysis.git

# Copyright (C) 2017 Noah Davids

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

if [ $# -ne 3 ]
   then echo "Usage:"
        echo "   build-filter.sh FILE TSHARK-VARIABLE OPERATOR"
        echo "      FILE is the file to scan through looking for IP addresses"
        echo "      TSHARK-VARIABLE is a shark variable, for example ip_addr"
        echo "      OPERATOR is either and or or depending on what you want"
        echo "         anything other than and will result in or"
        exit
fi

if [ $3 == "and" ]
   then
      cat $1 | awk -v variable=$2 \
           '{printf ("%s %s == %s", sep, variable, $1); sep = " &&"}'; echo
   else
      cat $1 | awk -v variable=$2 \
           '{printf ("%s %s == %s", sep, variable, $1); sep = " ||"}'; echo
fi

