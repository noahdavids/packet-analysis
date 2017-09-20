#!/bin/bash
# packet-matcher.sh begins on the previous line
#
# This macro uses tshark to match segments from 1 TCP stream in a "template"
# trace with segments in another, target, trace. It matches by extracting a 
# string of TCP data from a segment in the template stream and looking for a
# frame that contains the same string in the target trace. So for every
# segment in the template stream the target trace is searched once. This is
# not a speedy process. The strings do no have to be in the same relative
# position in the template and target segments.
#
# The output is first a count of the number of segments found in the template
# file followed by two tables. The first table is of uniquely matched segments
# each row is the frame number from the template trace, the frame number from
# the target trace and the stream number that the target frame belongs to.
# There is also a count of matches. The second table is of non-unique matches,
# that is the template occurred more than once in the target. Each row is the
# template frame number followed by the list of matching target frames.
# Either of these tables may be skipped if they are empty. Non matching
# template frames are not displayed so if there are no matches the only thing
# displayed is the count of template segments found.
#
# Version 1.0 March 18, 2017
# Version 1.1 April 1 2017
#    Added copyright and GNU GPL statement and disclaimer
# Version 1.2 September 19, 2017
#    Corrected some comments

# PACKETMATCHERVERSION="1.2_2017-09_19"
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

if [ $# -ne 6 ]
   then echo "Usage:"
        echo "   packet-matcher.sh TEMPLATE-FILE TARGET-FILE PORT-1 PORT-2 START END"
        echo "       TEMPLATE-FILE "
        echo "       TARGET-FILE is the name of the target trace file"
        echo "       PORT-1 and PORT-2 are the ports identify the template stream"
        echo "       START and END are the start and end of the TCP data that is"
        echo "          extracted from the template data and looked for in the target"
        echo "          START must be >= 1."
   exit
fi

TEMPLATE=$1
TARGET=$2

if [ ! -e "$TEMPLATE" ]
   then echo "Could not find template file $TEMPLATE"
   exit
fi

if [ ! -e "$TARGET" ]
   then echo "Could not find target file $TARGET"
   exit
fi

PORT1=$3
PORT2=$4

if [ $5 -ge $6 ]
  then echo "START ($5) must be < END ($6)"
       exit;
fi
START=$(( ( ( $5 - 1 ) * 3 ) + 1 ))
END=$(( ( $6 * 3 ) - 1 ))

COUNT=0

# I always echo the command and arguments to STDOUT as a sanity check

echo packet-matcher.sh $TEMPLATE $TARGET $PORT1 $PORT2 $5 $6

# Just in case there are old temporary files clean them up

rm -f /tmp/packet-matcher-2 2>/dev/null
rm -r /tmp/packet-matcher-3 2>/dev/null

# Figure out if we can use "-Y" as the display filter argument or we need 
# "-R". Basically look at the help output and if we do not find the "-Y"
# we use "-R"

DASH="-Y"
if [ $(tshark -help | egrep "\-Y <display filter>" | wc -l) -eq 0 ]
then DASH="-R"
fi

# For each segment matching both PORT1 and PORT2 and having TCP data in the
# TEMPLATE file. Note that if there are two streams using the same set of
# port numbers things may get a bit confused. We interpret the port as echo
# data so that all data is extracted as a string of XX:XX:XX:.... where the
# XX's are 0-9a-f.

tshark -r $TEMPLATE $DASH "tcp.port == $PORT1 && tcp.port == $PORT2 && \
    tcp.len > 0" -d tcp.port==$PORT1,echo -d tcp.port==$PORT2,echo -T fields \
    -e frame.number -e echo.data | \

# for each frame cut out the characters indicated by START and END and search
# for segments in the TARGET file that contain that string. Write the results
# packet-matcher-1

  while read number data
    do sub=$(echo $data | cut -c $START-$END)
       tshark -r $TARGET $DASH "tcp contains $sub" -T fields -e frame.number \
           -e tcp.stream > /tmp/packet-matcher-1

# If the number of lines in packet-matcher-1 is 1 we have a unique match. Write
# the frame number from the TEMPLATE file and frame number and stream number
# from the TARGET file to packet-matcher-2

       if [ $(cat /tmp/packet-matcher-1 | wc -l) -eq 1 ]
         then echo $number $(cat /tmp/packet-matcher-1) >> /tmp/packet-matcher-2
       fi

# If the is more than 1 line in packet-matcher-1 we have a non-unique match.
# Write the frame number from the TEMPLATE file and all the frame numbers
# (column 1) from the TARGET file to packet-matcher-3

       if [ $(cat /tmp/packet-matcher-1 | wc -l) -gt 1 ]
       then echo $number $(cat /tmp/packet-matcher-1 | \
           awk '{print $1}') >> /tmp/packet-matcher-3
       fi

# Count the number of TEMPLATE frames 
       COUNT=$(($COUNT+1))
       echo $COUNT > /tmp/packet-matcher-4
    done

# Once all of the frames from the TEMPLATE file have been processed.

echo
echo $(cat /tmp/packet-matcher-4) template frames found
echo

# Keep track if we have actually output any  matches.

OUTYES=0

# Count the lines in packet-matcher-2 and if there is at least 1 write
# out some column headers and then the contents of packet-matcher-2. Then
# write out a count of the number of lines in packet-matcher-2

if [ -e /tmp/packet-matcher-2 ]
  then (echo Matching Frames; echo Template Target Stream
        cat /tmp/packet-matcher-2) | column -t
        echo; echo $(cat /tmp/packet-matcher-2 | wc -l) matching frames
        OUTYES=1
  fi

# Count the lines in packet-match-3 and if there is at least 1 write
# out some column headers and the content sof packet-matcher-3
if [ -e /tmp/packet-matcher-3 ]
  then echo; (echo non-unique matches; echo Template Target
     cat /tmp/packet-matcher-3) | column -t
     OUTYES=1
fi

# If we haven't output anything yet out a message indicating that no matches were found.

if [ $OUTYES -eq 0 ]
  then echo "No matches were found"
fi

# clean up the files

rm -f /tmp/packet-matcher-1 2>/dev/null
rm -f /tmp/packet-matcher-2 2>/dev/null
rm -r /tmp/packet-matcher-3 2>/dev/null
rm -f /tmp/packet-matcher-4 2>/dev/null

# packet-matcher.sh ends here



