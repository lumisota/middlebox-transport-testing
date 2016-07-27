import socket 
import struct 
import signal
import select
import errno
import os 
import sys 
import tcplib

import threading
import commands
import time
import pcaplib

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

while True:
    try:
        inputready,outputready,exceptready = select.select([s], [], [])
    except select.error, e:
        if e[0] == errno.EINTR: continue
        else: break

    if len(inputready) == 0: continue

    (rcvddata, recvaddr) = s.recvfrom(65565)

  	# receive a packet
    (rcvddata, recvaddr) = s.recvfrom(65565)

    # parse ip header
    ipdata = rcvddata[0:20]
    iph = tcplib.iphdr()
    iph.parsehdr(ipdata)

    # parse tcp header
    tcpheader = rcvddata[iph.hdrlen:iph.hdrlen+20]
    tcph = tcplib.tcphdr()
    tcph.parsehdr(tcpheader)
    datalen = len(rcvddata) - iph.hdrlen - tcph.hdrlen

    print 'boom!\n'