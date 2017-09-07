#!/bin/bash
# find-ips.sh begins on the previous line
#
# This macro looks through a file and extracts all the strings with the format
#      [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
# basically an IP address
#
# Version 1.0 August 30 2017

FINDIPSVERSION="1.0_2017-08-30"

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
        echo "   find-ips.sh FILE"
        echo "      FILE is the name of the file to look through"
        exit
fi

# Search through the file and extract only the strings (-o). Then create a
# sorted list of each unique address

egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $1 | sort -u


