#!/usr/bin/python
# split-pcap.py begins on the previous line
#
# This script will take a pcap file and split into multiple files, one per
# TCP 4-tuple. If the 4-tuple is reused for multiple connections all
# connections will be in the 1 file. The output file name will be the original
# file name stripped of any directories followed by
#     _IP1-Port1_IP2-Port2_split.pcap
# The files are written into the current directory.
#
# The script will exit with a warning if it detects files with the same
# file name as the original file and the suffix _split.pcap. This is because
# the output files are written in append mode so if the script is run over
# the same file twice it will just add the packets to the existing files
# and you end up with duplicates.

# This script only supports pcap formated files. See the usage message for
# suggestions on converting pcapng files -- 
#                                   or try googling "convert pcapng to pcap"
#
# This script requires the modules sys, re (regular expression), logging, glob 
# and scapy. I expect that sys, re, logging, and glob  are installed by default.
# You will probably have to install scapy. How will vary depending on your
# OS nd what is already installed. You can try:
#     pip install scapy
# or  apt-get install python-scapy
# or  rpm install scapy (from the epel repro)
#
# Usage:
#     split-pcap.py file-name [packet-count]
# Where:
#     file-name is the name or path of the file to be processed. This script
#        only supports pcap files, not pcapng. The following commands can be
#        used to convert a pcapng file to pcap format
#            tcpdump -r file.pcapng -w new-file.pcap
#        or
#            tshark -r file.pcapng -w new-file.pcap -F libpcap
#        You can also use editcap with the -F libcap argument 
#
#     packet-count is optional and is the total number of packets (any protocol)
#        in the file. If packet-count is provided the script will write a line
#        "Percentage done: " for every integer increase in the percentage of
#        the packets processed. If you get the number wrong the percentages
#        will be off but you can multiple the count by 10 to get a line every
#        10 percent instead of every 1 percent. If packet-count is not provided
#        the script will write a line with the packet count of the packet
#        being processed. 

# Version 1.0 July 9, 2017
# Version 1.1 July 9, 2017
#     Correctetd handling of the file name prefix to strip off any directory
#     path character  to leave just thefile name. Also the detection of
#     already existing files to check the current directory and not the input
#     file source directory.
# Version 1.2 July 13, 2017
#     Correcly write the link type for pcap contained Cooked Linux frames
#     abort for anything other than Ethernet and CookedLinux
#
# from https://github.com/noahdavids/packet-analysis.git
#
# Copyright (C) 2017 Noah Davids
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3, https://www.gnu.org/licenses/gpl-3.0.html
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


import sys
import re
import glob

# This is needed to suppress a really irrating warning message when scapy
# is imported
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import*
except ImportError:
    print "scapy is not installed. See comments for installation suggestions"
    exit ()

# argument processing, require just the file name. If a second argument
# is provided make sure its an integer
if len (sys.argv) < 2 or len (sys.argv) > 3:
   print "Usage is: split-pcap.py file-name [packet-count]"
   print "Try\n     grep -A 20 Usage: " + sys.argv[0] +  \
                                            " | head -20\nfor details"
   exit ()

if len (sys.argv) == 3:
   inputFileString = sys.argv [1]
   try:
      inputTotalPackets = int (sys.argv [2])
   except ValueError:
      print "The second argument must be an integer <" + \
                       sys.argv [2] + "> does appear to be an integer"
      exit ()
else:
   inputFileString = sys.argv [1]
   inputTotalPackets = 0

# try opening the file. 
try:
   pcapIn = PcapReader (inputFileString)
except IOError:
   print "It doesn't look like " + inputFileString + " exists"
   exit()
except NameError:
   print "It doesn't look like " + inputFileString + \
                                      " is a file that can be processed."
   print "Note that this script cannot process pcapng files. Review the "
   print "usage details for ideas on how to convert from pcapng to pcap" 
   exit ()

# Extract out just the the file name. Note that I assume the the ".*/" match
# is greedy and will match until the last "/" character in the string. If
# the match fails there are no "/" characters so the whole string must be the
# name.
x = re.search ("^.*/(.*$)", inputFileString)
try:
   prefix = x.group(1) + "_"
except:
   prefix = inputFileString + "_"

# Look for prefix*_split.pcap files. If you find them print a
# warning and exit.

t = len (glob (prefix + "*_split.pcap"))
if t > 0:
   print "There are already " + str (t) + " files with the name " + \
       prefix + "*_split.pcap."
   print "Delete or rename them or change to a different directory to"
   print "avoid adding duplicate packets into the " + prefix + \
                                               "*_split.pcap trace files."
   exit ()

pcapOutName = ""
oldPcapOutName = ""
packetCount = 0
donePercentage = 0;
oldDonePercentage = -1

# Loop for each packet in the file

for aPkt in pcapIn:

# count the packets read
   packetCount = packetCount + 1

# If the packet contains a TCP header extract out the IP addresses and
# port numbers
   if TCP in aPkt:
      ipSrc = aPkt[IP].src
      tcpSport = aPkt[TCP].sport
      ipDst = aPkt[IP].dst
      tcpDport = aPkt[TCP].dport

# put things in some sort of cannonical order. It doesn't really matter
# what the order is as long as packets going in either direction get the
# same order.
      if ipSrc > ipDst:
         pcapOutName = prefix + ipSrc + "-" + str(tcpSport) + "_" + ipDst + "-" + str(tcpDport) + "_split.pcap"
      elif ipSrc < ipDst:
         pcapOutName = prefix + ipDst + "-" + str(tcpDport) + "_" + ipSrc + "-" + str(tcpSport) + "_split.pcap"
      elif tcpSport > tcpDport:
         pcapOutName = prefix + ipSrc + "-" + str(tcpSport) + "_" + ipDst + "-" + str(tcpDport) + "_split.pcap"
      else:
         pcapOutName = prefix + ipDst + "-" + str(tcpDport) + "_" + ipSrc + "-" + str(tcpSport) + "_split.pcap"

# If the current packet should be written to a different file from the last
# packet, close the current output file and open the new file for append
# save the name of the newly opened file so we can compare it for the next
# packet. 
      if pcapOutName != oldPcapOutName:
         if oldPcapOutName != "":
            pcapOut.close()

         if type(aPkt) == scapy.layers.l2.Ether:
            lkType = 1
         elif type (aPkt) == scapy.layers.l2.CookedLinux:
            lkType = 113
         else:
            print "Unknown link type: "
            type (aPkt)
            print "    -- exiting"
            exit

         pcapOut = PcapWriter (pcapOutName, linktype=lkType, append=True)
         oldPcapOutName = pcapOutName

# write the packet
      pcapOut.write (aPkt)

# Write the progress information, either percentages if we had a packet-count
# argument or just the packet count.

      if inputTotalPackets > 0:
         donePercentage = packetCount * 100 / inputTotalPackets
         if donePercentage > oldDonePercentage:
            print "Percenage done: ", donePercentage
            oldDonePercentage = donePercentage
      else:
         print packetCount 
#
# split-pcap.py ends here

