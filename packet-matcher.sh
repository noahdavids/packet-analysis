#!/bin/bash
# packet-matcher.sh begins on the previous line
#
# This macro uses tshark to match segments from 1 TCP stream in a "template"
# trace with segments in another, target, trace. It matches by extracting a 
# string of TCP data from a segment in the template stream and looking for a
# frame that contains the same string in the target trace. So for every
# segment in the template stream the target trace is searched once. This is
# not a speedy process. The strings do no have to be in the same relative
# position in the template and target segments. In an effort to speed things
# up and remove strings that are probably not unique the target string is
# skipped if there are too many repeating characters. Repeating characters
# are removed and the resulting string length must be at least 33% of the
# original string length. 

# TO RUN THIS SCRIPT YOU MUST CREATE A pm-decodes PROFILE will all protocols
# EXCEPT Ethernet, IPv4, IPv6, TCP and ECHO disabled

# The output is first a count of the number of segments matching the port
# filters in the template file and the number of segments where the template
# string met the 33% rule. This is followed by two tables. The first table
# is of uniquely matched segments each row is the frame number from the
# template trace, the string and then the frame number dash TCP stream number
# that the target frame belongs to. The second table is of non-unique matches,
# that is the template occurred more than once in the target. Each row is the
# template frame number, the string, and the the first 20 matching target
# frame number dash TCP stream numbers. I figured 20 matches was enough.
# Either of these tables may be skipped if they are empty. Template frames
# with no match in any target frame not displayed so if there are no matches
# at all the only thing displayed is the in initial number of segments matching
# the port filter and a count of the template strings meeting the 33% rule and
# then a message saying no matches were found.
#
# Version 1.0 March 18, 2017
# Version 1.1 April 1 2017
#    Added copyright and GNU GPL statement and disclaimer
# Version 1.2 September 19, 2017
#    Corrected some comments
# Version 1.3 March 7, 2018
#    Discovered that the decode to echo was not working in all cases unless
#    the highest layer protocol was first disabled. Created a profile to
#    disable all protocols except Ethernet, SLL, IPv4, IPv6, TCP and echo.
#    This profile will have to be created. The behavior appears to be tshark
#    version dependent so you can try removing the -C argument and see if it
#    works if you do not want to create the profile. Also added a check to be
#    sure that frame was long enough to include all the data bytes. A short
#    frame will result in a short string and possible false positives. Also
#    added a filter to not bother searching for strings that had too many
#    repeating characters on the theory that they would result in non-unique
#    matches. Added the string from each matching frame and the stream number
#    to the target in the target frame number to the final output. If there
#    are non-unique matches but the targets are all from different streams you
#    haven't found a match. f the matches are not unique but they are all from
#    the same stream you may have a match. Finally added a count of the number
#    of segments that matched the port filter and that met the 33%
#    non-repeating character criteria.

# PACKETMATCHERVERSION="1.3_2018-03_05"
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
FOUND=0

# I always echo the command and arguments to STDOUT as a sanity check

echo packet-matcher.sh $TEMPLATE $TARGET $PORT1 $PORT2 $5 $6

# Just in case there are old temporary files clean them up

rm -f /tmp/packet-matcher-1 2>/dev/null
rm -r /tmp/packet-matcher-2 2>/dev/null
rm -f /tmp/packet-matcher-3 2>/dev/null
echo $FOUND $COUNT > /tmp/packet-matcher-4

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
# XX's are 0-9a-f. Note the use of pm-decodes profiles. You need to create
# it or you version works without it feel free to remove it.

tshark -r $TEMPLATE $DASH "tcp.port == $PORT1 && tcp.port == $PORT2 && \
    tcp.len > 0" -d tcp.port==$PORT1,echo -d tcp.port==$PORT2,echo \
    -C pm-decodes -T fields -e frame.number -e echo.data | \

# First increment the number of segments matching the port filter and write
# this out along with the number of template strings matching the 33% rule.
# to the /tmp/packet-matcher-4 file. You can monitor the progress of the
# script by looking at this file. Then for each frame, cut out the characters
# indicated by START and END and make sure it is long enough. If the frame was
# short you can end up matching against a short string which could lead to
# false positivies. Then calculate the length of that string after removing
# repeating characters, if the length is at least 33% of the original length
# search for segments in the TARGET file that contain that string. Write the
# results to packet-matcher-1 The idea is that if the search string contains
# too many repeating character sequences (like nulls or spaces) it is most
# likely not very unique and isn't worth the effort to search the target. Of
# course strings of 12121212 is also not very unique and would not be filtered
# by this technique and 33 is an arbitrary cut off.

  while read number data
    do 
       FOUND=$(($FOUND+1))
       echo $FOUND $COUNT > /tmp/packet-matcher-4
       sub=$(echo $data | cut -c $START-$END)
       if [ ${#sub} -lt $(($END-$START+1)) ]
          then continue
       fi
       P=$(echo $5 $6 $(echo $sub | tr ":" "\n" | uniq | wc -l) | \
            awk '{print int($3/($2-$1+1)*100)}')
       if [ $P -lt 33 ]
          then continue
       fi
       tshark -r $TARGET $DASH "tcp contains $sub" -T fields -e frame.number \
           -e tcp.stream > /tmp/packet-matcher-1

# If the number of lines in packet-matcher-1 is 1 we have a unique match. Write
# the frame number from the TEMPLATE file, the template string, and frame number
# and stream number from the TARGET file to packet-matcher-2

       if [ $(cat /tmp/packet-matcher-1 | wc -l) -eq 1 ]
         then echo -e "$number \t $sub \t" \
              $(awk '{print $1 "-" $2}' /tmp/packet-matcher-1) \
              >> /tmp/packet-matcher-2
       fi

# If there is more than 1 line in packet-matcher-1 we have a non-unique match.
# Write the frame number from the TEMPLATE file, the template string, and the
# first 20 frame and stream numbers from the TARGET file to packet-matcher-3

       if [ $(cat /tmp/packet-matcher-1 | wc -l) -gt 1 ]
       then echo -e "$number \t $sub \t" \
            $(head -20 /tmp/packet-matcher-1 | awk '{print $1 "-" $2}') \
            >> /tmp/packet-matcher-3
       fi

# increment the number of TEMPLATE strings that have met the 33% rule and write
# out the new count and the current number that have match the port filter
       COUNT=$(($COUNT+1))
       echo $FOUND $COUNT > /tmp/packet-matcher-4
    done

# Once all of the frames from the TEMPLATE file have been processed.

# extract out the FOUND and COUNT numbers

FOUND=$(awk '{print $1}' /tmp/packet-matcher-4)
COUNT=$(awk '{print $2}' /tmp/packet-matcher-4)

# If no tempate frames were found something is wrong

if [ $FOUND  -eq 0 ]
   then echo
        echo No template frames were found, either the port numbers were in
        echo error or the decode failed. Have you created the pm-decodes
        echo profile correctly?
        exit
   fi

# No template frames met the 33% rule probably just a bad place to search

if [ $COUNT -eq 0 ]
   then echo
        echo $FOUND segments matched the tcp.port filter but
        echo No tempate frames met the 33% rule try a different substring
        exit
   fi

# display the number of frames matching the tcp port filter and the number of 
# frames meeting the 33% rule.

echo -n $FOUND segments match the tcp.port filter and
echo " $COUNT segments met the 33% rule"

# Keep track if we have actually output any  matches.

OUTYES=0

# If packet-matcher-2 exists and has at least 1 line indicate that there are
# uniquely matching frames, calculate the percentage of matches from the
# strings that met the 33% rule and then show them.

if [ -e /tmp/packet-matcher-2 ]
  then UNIQUE=$(cat /tmp/packet-matcher-2 | wc -l)
       if [ $UNIQUE -gt 0 ]
          then echo
               echo $UNIQUE $COUNT | \
               awk '{print $1 " Uniquely Matching Frames (" $1/$2*100 "%)"}'
               cat /tmp/packet-matcher-2
               OUTYES=1
       fi
   fi

# If packet-matcher-3 exists and has at least 1 line indicate that there are
# non-uniquely matching frames, calculate the percentage of matches from the
# strings that met the 33% rule and then show them.

if [ -e /tmp/packet-matcher-3 ]
  then UNIQUE=$(cat /tmp/packet-matcher-3 | wc -l)
       if [ $UNIQUE -gt 0 ]
          then echo
               echo $UNIQUE $COUNT | \
               awk '{print $1 " non-Uniquely Matching Frames (" $1/$2*100 "%)"}'
               cat /tmp/packet-matcher-3
               OUTYES=1
       fi
   fi


# If we haven't output anything yet out a message indicating that no matches
# were found.

if [ $OUTYES -eq 0 ]
  then echo "No matches were found"
fi

# clean up the files

rm -f /tmp/packet-matcher-1 2>/dev/null
rm -f /tmp/packet-matcher-2 2>/dev/null
rm -f /tmp/packet-matcher-3 2>/dev/null
rm -f /tmp/packet-matcher-4 2>/dev/null

# packet-matcher.sh ends here



