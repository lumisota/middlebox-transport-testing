# Copyright (C) 2010 WIDE Project.  All rights reserved.
# Copyright (C) 2016 University of Glasgow. All rights reserved.
#
# Michio Honda  <micchie@sfc.wide.ad.jp>
# Stephen McQuistin <sm@smcquistin.uk>
#	[August 2016] Add HTTP-wrapped tests to support HTTP proxies
#  
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import code
import logging
import sys
import os
import time
import datetime
import random
import socket
import struct
import threading
import commands
import tcplib
import tcpsrlib
import pcaplib
import re
import copy
import __main__

#
#
# Execute by "python tcpexposure.py tcp_mbox_test dest_hostname dport"
# or "python mboxcheck.py tcp_mbox_large filename(1 hostname per 1 line) dport"
# By default, this uses RAW socket to output our TCP segments.
# If you want to use pcap, add "1" to the argument
#
#
# This program causes force reset from the host OS, so you need to drop it.
# For Mac OSX or FreeBSD, a following example is possible
# e.g., sudo ipfw add 100 deny tcp from LOCAL_IPADDR to any dst-port 80,34343 tcpflags rst
# To disable above rule, simply type:
# sudo ipfw flush
# For FreeBSD, PF configuration is also possible
# e.g., block out quick on msk0 proto tcp to port 34343 flags R/R
# For Linux, please also configure iptables (e.g., 
# /sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 34343 -j DROP)
# 
#


#
# Test entries
#
TestEntries = {'Syn':-1, 'SynOpt':-1, 'SynOpt2':-1, \
	'Data':-1, 'DataKnownOpt':-1, 'DataOpt':-1, \
	'Split':-1, 'SplitKnownOpt':-1, 'SplitOpt':-1, \
	'Coalesce':-1, 'CoalesceKnownOpt':-1, 'CoalesceOpt':-1, \
	'CoalesceFq':-1, 'CoalesceFqKnownOpt':-1, 'CoalesceFqOpt':-1, \
	'PseudoRtx':-1, 'PseudoRtxL':-1, 'PseudoRtxS':-1, \
	'SeqHole':-1, 'AckHole':-1, \
	'UnexpAwnd':-1, 'UnexpAwnd4Opt':-1, \
	'ChangeIncomingSeq':-1, 'ChangeIncomingSeq4Opt':-1, \
	'ChangeAwnd':-1, 'ChangeAwnd4KnownOpt':-1, 'ChangeAwnd4Opt':-1, \
	'ChangeSeq':-1, 'ChangeSeq4KnownOpt':-1, 'ChangeSeq4Opt':-1, \
	'IndAck':-1, 'IndAck4KnownOpt':-1, 'IndAck4Opt':-1, \
	'DataHttp':-1, 'IndAckHttp':-1, 'ChangeSeqHttp':-1, \
    'ChangeAwndHttp':-1, 'ChangeIncomingSeqHttp':-1, 'IndAck4KnownOptHttp':-1, \
    'ChangeSeq4KnownOptHttp':-1, 'ChangeAwnd4KnownOptHttp':-1, 'IndAck4OptHttp':-1, \
    'ChangeSeq4OptHttp':-1, 'ChangeAwnd4OptHttp':-1, 'ChangeIncomingSeq4OptHttp':-1, \
    'SplitHttp':-1, 'SplitKnownOptHttp':-1, 'SplitOptHttp':-1, \
    'CoalesceFqHttp':-1, 'CoalesceHttp':-1, 'CoalesceFqKnownOptHttp':-1, \
    'CoalesceKnownOptHttp':-1, 'CoalesceFqOptHttp':-1, 'CoalesceOptHttp':-1, \
    'PseudoRtxHttp':-1, 'PseudoRtxLHttp':-1, 'PseudoRtxSHttp':-1, \
    'AckHoleHttp':-1, 'SeqHoleHttp':-1, 'HttpResponseHeaderChange':-1, \
    'HttpRequestChange':-1}

#
# Payload marking to request special behavior of the responder
# MUST be synchronized with server program
#
Request_hdrdata = 0xa1
Request_dupack = 0xb2

UDP_FLOOD_CTL_PORT = 35000
FLOOD_UDP_START = 0x00000001
FLOOD_UDP_STOP = 0x00000002
FLOOD_UDP_CONFIRMED = 0x00000003

#
# Default sending parameters
#
Isn = 252001
AckSeq = 0
Awnd = 8064
Mss = 512

Ts_vals = (13572468, 0)
Winscale = 2
Mptcp_idsn = 0x12345678abcdef00
Mptcp_token = 0x0D0C0B09

#
# Known receiving parameters (SHOULD be synced with the server tool)
#
PeerAwnd = 32768
PeerMss = 512
PeerTs_vals = (12345678, 0)
PeerWinscale = 6
PeerMpcap = (0x0D0C0B0A, 0x0102030405060000)

#
# logging and debug functions
#
def make_result_string(dictres):
    s = ""
    s += 'Syn %(Syn)d SynOpt %(SynOpt)d SynOpt2 %(SynOpt2)d '%dictres
    s += 'Data %(Data)d DataKnownOpt %(DataKnownOpt)d DataOpt %(DataOpt)d '%dictres
    s += 'Split %(Split)d SplitKnownOpt %(SplitKnownOpt)d SplitOpt %(SplitOpt)d '%dictres
    s += 'Coalesce %(Coalesce)d CoalesceKnownOpt %(CoalesceKnownOpt)d CoalesceOpt %(CoalesceOpt)d '%dictres
    s += 'CoalesceFq %(CoalesceFq)d CoalesceFqKnownOpt %(CoalesceFqKnownOpt)d CoalesceFqOpt %(CoalesceFqOpt)d '%dictres
    s += 'PseudoRtx %(PseudoRtx)d PseudoRtxL %(PseudoRtxL)d PseudoRtxS %(PseudoRtxS)d '%dictres
    s += 'SeqHole %(SeqHole)d AckHole %(AckHole)d '%dictres
    s += 'UnexpAwnd %(UnexpAwnd)d UnexpAwnd4Opt %(UnexpAwnd4Opt)d '%dictres
    s += 'ChangeIncomingSeq %(ChangeIncomingSeq)d ChangeIncomingSeq4Opt %(ChangeIncomingSeq4Opt)d '%dictres
    s += 'ChangeAwnd %(ChangeAwnd)d ChangeAwnd4KnownOpt %(ChangeAwnd4KnownOpt)d ChangeAwnd4Opt %(ChangeAwnd4Opt)d '%dictres
    s += 'ChangeSeq %(ChangeSeq)d ChangeSeq4KnownOpt %(ChangeSeq4KnownOpt)d ChangeSeq4Opt %(ChangeSeq4Opt)d '%dictres
    s += 'IndAck %(IndAck)d IndAck4KnownOpt %(IndAck4KnownOpt)d IndAck4Opt %(IndAck4Opt)d '%dictres
    s += 'DataHttp %(DataHttp)d IndAckHttp %(IndAckHttp)d ChangeSeqHttp %(ChangeSeqHttp)d ' % dictres
    s += 'ChangeAwndHttp %(ChangeAwndHttp)d ChangeIncomingSeqHttp %(ChangeIncomingSeqHttp)d IndAck4KnownOptHttp %(IndAck4KnownOptHttp)d ' % dictres
    s += 'ChangeSeq4KnownOptHttp %(ChangeSeq4KnownOptHttp)d ChangeAwnd4KnownOptHttp %(ChangeAwnd4KnownOptHttp)d IndAck4OptHttp %(IndAck4OptHttp)d ' % dictres
    s += 'ChangeSeq4OptHttp %(ChangeSeq4OptHttp)d ChangeAwnd4OptHttp %(ChangeAwnd4OptHttp)d ChangeIncomingSeq4OptHttp %(ChangeIncomingSeq4OptHttp)d ' % dictres
    s += 'SplitHttp %(SplitHttp)d SplitKnownOptHttp %(SplitKnownOptHttp)d SplitOptHttp %(SplitOptHttp)d ' % dictres
    s += 'CoalesceFqHttp %(CoalesceFqHttp)d CoalesceHttp %(CoalesceHttp)d CoalesceFqKnownOptHttp %(CoalesceFqKnownOptHttp)d ' % dictres
    s += 'CoalesceKnownOptHttp %(CoalesceKnownOptHttp)d CoalesceFqOptHttp %(CoalesceFqOptHttp)d CoalesceOptHttp %(CoalesceOptHttp)d ' % dictres
    s += 'PseudoRtxHttp %(PseudoRtxHttp)d PseudoRtxLHttp %(PseudoRtxLHttp)d PseudoRtxSHttp %(PseudoRtxSHttp)d ' % dictres
    s += 'AckHoleHttp %(AckHoleHttp)d SeqHoleHttp %(SeqHoleHttp)d HttpResponseHeaderChange %(HttpResponseHeaderChange)d ' % dictres
    s += 'HttpRequestChange %(HttpRequestChange)d' % dictres
    return s

logfile = ""

def log2file(msg):
    global logfile
    print msg.strip()
    logfile.write(msg)

def printans(ans):
    log2file("Info: Received " + '%d'%len(ans) + " Acks\n")
    s = ""
    for rcv in ans:
	s += "Info: "
        s += tcpsrlib.summarize_ans1(rcv)
    log2file(s)

def printpkts(pkts):
    log2file("Info: Transmitting " + '%d'%len(pkts) + " Pkts\n")
    s = ""
    for pkt in pkts:
	s += "Info: "
	s += tcpsrlib.summarize_pkt(pkt)
    log2file(s)

def get_snd_nxt(ans, sent_seq):
    if len(ans) == 0: 
	return sent_seq
    highest_ack = tcpsrlib.get_highest_ack(ans)
    if highest_ack == 0: 
	return sent_seq
    else: 
	return highest_ack

def get_rcv_nxt(ans, ackseq):
    if len(ans) == 0: 
	return ackseq
    highest_endseq = 0
    for rcv in ans:
	endseq = rcv[1].seqno + rcv[0].length - rcv[0].hdrlen - rcv[1].hdrlen
	if endseq > highest_endseq: 
	    highest_endseq = endseq
    if highest_endseq == 0: 
	return ackseq
    return highest_endseq
	
def get_mpdata_nxt(ans, sent_dsn):
    if len(ans) == 0: 
	return sent_dsn
    highest_dsn_ack = 0
    nxt_dsn = [0, 0]
    for rcv in ans:
	if len(rcv[2]) == 0: continue
	for opt in rcv[2]:
	    if opt[0] != 'MP_ACK': continue
	    if opt[1] > highest_dsn_ack: 
	        highest_dsn_ack = opt[1]
    if highest_dsn_ack == 0: 
	return sent_dsn
    nxt_dsn[0] = highest_dsn_ack
    nxt_dsn[1] = sent_dsn[1] + (highest_dsn_ack - sent_dsn[0])
    return nxt_dsn

def get_mprcv_nxt(ans, mpackseq):
    if len(ans) == 0: 
	return mpackseq
    highest_dsn = 0
    tmp_dlen = 0
    for rcv in ans:
	for opt in rcv[2]:
	   if opt[0] != 'MP_DSS': continue
	   if opt[1] > highest_dsn:
	       highest_dsn = opt[1]
	       tmp_dlen = opt[2]
    if highest_dsn == 0: 
	return mpackseq
    return highest_dsn + tmp_dlen

#
# Functions to obtain result
#

#
# Check availability header request.  This should be done if we intend to 
# obtain something from peer-received TCP header 
# Returns tuple of my received header, peer received header, peer sent header,
# rest of peer sent payload as padding
def hdr_request_reply(ans, http=0, result=None):
    for rcv in ans:
	payload = rcv[3]
	# This request MUST contain receiving IP/TCP and sending IP/TCP headers
	if len(payload) < 80: 
	    continue
	if http == 1:
		if struct.unpack(str(len(payload)) + 's', payload)[0][0:4] == "HTTP":
			log2file("Info: HTTP response received as expected")
			http_header = struct.unpack(str(len(payload)) + 's', payload)[0][:payload.find("\r\n\r\n")+4]
			http_header_expected = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % (len(payload)-payload.find("\r\n\r\n")-4)
			if http_header != http_header_expected:
				log2file("Info: HTTP response received:", http_header)
				if result != None: result['HttpResponseHeaderChange'] = 1
			elif result != None and result['HttpResponseHeaderChange'] == -1 and http_header == http_header_expected:
				result['HttpResponseHeaderChange'] = 0
			payload = payload[payload.find("\r\n\r\n")+4:]
		else:
			log2file("Info: HTTP response expected, not received")
			http = 0
	# Obtain IP/TCP headers the peer received
	riph, rtcph, rtcpopts, shdrs = tcpsrlib.parse_headers(payload)
	# Validation of payload contents
	if riph.proto != socket.IPPROTO_TCP: 
	    log2file("Info: header request doesn't work, funny proto number\n")
	    continue
	elif len(shdrs) < 40:
	    log2file("Info: header request doesn't work, no sending header data\n")
	    continue

	siph, stcph, stcpopts, padding = tcpsrlib.parse_headers(shdrs)
	if http == 1:
		http_request_sent_abbrv = "GET /%s HTTP/1.1\r\nHost: tcptest.smcquistin.uk\r\nConnection: close\r\n\r\n" % struct.pack('!B', Request_hdrdata)
		if padding[:padding.find("\r\n\r\n")+4] != http_request_sent_abbrv:
			log2file("Info: HTTP request sent:", http_request_sent_abbrv)
			if result != None: result['HttpRequestChange'] = 1
		elif result != None and result['HttpRequestChange'] == -1 and padding[:padding.find("\r\n\r\n")+4] == http_request_sent_abbrv:
			result['HttpRequestChange'] = 0
		padding = padding[padding.find("\r\n\r\n")+4:]
	if siph.proto != socket.IPPROTO_TCP:
	    log2file("Info: header request doesn't work, funny proto number\n")
	    continue
	elif struct.unpack('!B', padding[6:7])[0] != Request_hdrdata:
	    log2file("Info: header request doesn't work, funny content\n")
	    continue
	log2file('Info: Peer received %sInfo: Peer sent %s'%\
			(tcpsrlib.summarize_ans1((riph, rtcph, rtcpopts)), \
			 tcpsrlib.summarize_ans1((siph, stcph, stcpopts))))
	return ((rcv[0], rcv[1], rcv[2]), (riph, rtcph, rtcpopts), (siph, stcph, stcpopts), padding)
    log2file("Info: header request doesn't work, no hdr data\n")

    return (None, None, None, None)

# returns 0 if SYNACK is received
# returns 1 if any reply is not received
# returns 2 if RST is received
def get_syn_result(ans):
    synack = tcpsrlib.get_synack(ans)
    if synack:
	return 0
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_RST:
            log2file("Info: Got RST without SYNACK\n")
	    return 2
    log2file("Info: get neither SYNACK nor RST\n")
    return 1

# returns 0 if SYNACK is received
# returns 1 if any reply is not received
# returns 2 if RST is received
# returns 3 if option is removed
# returns 4 if option is zeroed
# returns 5 if option is invalid
def get_syn_opt_result(ans):
    res = get_syn_result(ans)
    if res > 0: return res

    synack = tcpsrlib.get_synack(ans)
    if synack == None: return res
    optfound = 0
    for opt in synack[2]:
        if opt[0] != 'MP_CAPABLE': continue
        log2file("Info: MP_CAP" + ' token:0x%x'%opt[1] + ' idsn:0x%x\n'%opt[2])
	optfound = 1
	if opt[1] == 0x00000000 or opt[2] == 0x0000000000000000: 
	    log2file("Info: Got zeroed MP_CAP\n")
	    return 4
	if opt[1] != PeerMpcap[0]:
	    log2file("Info: Got modified (not zeroed) token in MP_CAP\n")
	    return 5
	if opt[2] != PeerMpcap[1]:
	    log2file("Info: Got modified (not zeroed) idsn in MP_CAP\n")
	    return 5
	break
    if optfound == 0:
	log2file("Info: MP_CAP is not replied\n")
        return 3
    log2file("Info: MP_CAP is successfully replied\n")
    return 0

# returns 0 if correct ACK is received
def get_data_result(ans, sentseq, sentsize):
    expack = sentseq + sentsize
    acks = tcpsrlib.get_acklist(ans)
    if len(acks) == 0:
        log2file("Info: segment is not acked\n")
	return 1
    for ack in acks:
	if ack == expack:
            log2file("Info: segment successfully acked\n")
	    return 0
    log2file("Info: segment is partially acked\n")
    return 1

# MUST be used with Request_hdrdata
# return 0 if outgoing Timestamp is not affected
# return 1 if outgoing Timestamp option is removed
# return 2 if outgoing Timestamp (ts_val) is zeroed
# return 3 if outgoing Timestamp (ts_val) is changed
def how_otimestamp_affected(ans, ots, http=0):
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None: 
	return -1
    for opt in rcvdhdr[2]:
	if opt[0] != 'TIMESTAMP': continue
	if opt[1] == ots[0]:
	    log2file("Info: outgoing Timestamp has passed without changed\n")
	    return 0
	elif opt[1] == 0x00000000: 
	    log2file("Info: outgoing Timestamp was zeroed\n")
	    return 2
	else:
	    log2file("Info: outgoing Timestamp was changed\n")
	    return 3
    log2file("Info: outgoing Timestamp has removed\n")
    return 1

# MUST be used with Request_hdrdata
def is_mpdata_removed(ans, http=0):
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None: 
	return -1
    for opt in rcvdhdr[2]:
        if opt[0] != 'MP_DSS': continue
	return 0
    return 1

# MUST be used with Request_hdrdata
def is_mpdata_zeroed(ans, http=0):
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None: 
	return -1
    for opt in rcvdhdr[2]:
        if opt[0] != 'MP_DSS': continue
	if opt[1] == 0x0000000000000000: 
	    return 1
	else: 
	    return 0
    return -1

# MUST be used with Request_hdrdata
def is_mpdata_changed(ans, sentdsn, http=0):
    rcvdhdr = hdr_request_reply(ans, http=http)[1]
    if rcvdhdr is None: 
	return -1
    found = 0
    for opt in rcvdhdr[2]:
        if opt[0] != 'MP_DSS': continue
	if opt[1] == sentdsn: 
	    return 0
        else: 
	    return 1
    return -1

# We define the result is positive if at least one of segments is 
# delivered with the original TS option when segment is split 
# returns 0 if TSecr is successfully received
# returns 1 if Acks are not seen
# returns 2 if outgoing Timestamp is removed
# returns 3 if outgoing TS_val is changed (not re-synced)
# returns 4 if outgoing TS_val is zeroed (not re-synced)
# returns 5 if incoming Timestamp is removed
# returns 6 if incoming TS_ecr is changed
# returns 7 if incoming TS_ecr is zeroed
# returns 8 if outgoing Timestamp is changed, zeroed or removed but re-synced at incoming TS_ecr
# returns 9 in the other case
def get_data_known_opt_result(ans, sentts, sentseq, sentsize, http=0):
    retval = get_data_result(ans, sentseq, sentsize)
    if retval == 1: return 1
    zero_ecr = invalid_ecr = valid_ecr = 0

    # We adopt the first Timestamp option in the received acks
    for rcv in ans:
	for opt in rcv[2]:
	    if opt[0] != 'TIMESTAMP': continue
	    if opt[2] == sentts[0]:
	        log2file("Info: TS_ecr is successfully echoed\n")
	        valid_ecr = 1
	    elif opt[2] == 0: 
	        log2file("Info: Zero TS_ecr is replied\n")
	        zero_ecr = 1
	    else:
	        log2file("Info: Unexpected TS_ecr is replied\n")
		invalid_ecr = 1
	    break
	if valid_ecr or zero_ecr or invalid_ecr: 
	    break

    if zero_ecr == 0 and invalid_ecr == 0 and valid_ecr == 0:
	log2file("Info: Timestamp is not replied\n")

    otimestamp = how_otimestamp_affected(ans, sentts, http=http)
    if otimestamp == -1:
        return -1
    if valid_ecr:
        if otimestamp == 0:
	    return 0
	else: 
	    return 8
    elif zero_ecr:
        if otimestamp == 0:
	    return 7
        elif otimestamp == 2: 
	    return 4
	else:
	    return 9
    elif invalid_ecr:
        if otimestamp == 0:
	    return 6
	elif otimestamp == 3:
	    return 3
	else:
	    return 9
    # Timestamp is not replied
    else:
        if otimestamp == 0:
	    return 5
	elif otimestamp == 1:
	    return 2
	else:
	    return 9

# We define the result is positive if at least one of segments is 
# delivered with the original MP_DATA option when segment is split 
# MUST be used for data with Request_hdrdata 
# returns 0 if both MP_DATA and MP_ACK are passed
# returns 1 if regular Acks are not seen
# returns 2 if MP_DATA is removed
# returns 3 if MP_DATA is modified
# returns 4 if MP_DATA is zeroed
# returns 5 if MP_ACK is removed
# returns 6 if MP_ACK is modified
# returns 7 if MP_ACK is zeroed
# returns 8 in the other case
def get_data_opt_result(ans, sentdsn, sentseq, sentsize):
    datares = get_data_result(ans, sentseq, sentsize)
    if datares == 1: 
	return 1
    zeroed = 0
    invalid = 0
    for rcv in ans:
        dataacks = tcpsrlib.get_dataacks_from_tcpopt(rcv[2])
        if len(dataacks) == 0: continue
        log2file("Info: got MP_ACK" + ' 0x%x'%dataacks[0] + "\n")
	valid_dataacks = tcpsrlib.get_valid_dataacks_from_tcpopt(rcv[2])
        if len(valid_dataacks) == 0: 
	    log2file("Info: got zeroed MP_ACK\n")
	    zeroed = 1
	    continue
	for j in valid_dataacks:
	    if j == sentdsn + sentsize:
	        log2file("Info: got valid MP_ACK\n")
	        return 0
	log2file("Info: got invalid MP_ACK\n")
	invalid = 1

    # Check which mpdata or mpack is changed
    if invalid:
        mpdata_changed = is_mpdata_changed(ans, sentdsn)
	if mpdata_changed == -1: 
	    return -1
	elif mpdata_changed == 1:
	    log2file("Info: MP_DATA is changed\n")
	    return 3
	elif mpdata_changed == 0:
	    log2file("Info: MP_ACK is changed\n")
	    return 6
	else:
	    return 8
    # Check which mpdata or mpack is zeroed
    if zeroed:
        mpdata_zeroed = is_mpdata_zeroed(ans)
	if mpdata_zeroed == -1:
	    return -1
        elif mpdata_zeroed == 1: 
	    log2file("Info: MP_DATA is zeroed\n")
	    return 4
	elif mpdata_zeroed == 0:
	    log2file("Info: MP_ACK is zeroed\n")
	    return 7
	else: 
	    return 8
    # Check which mpdata or mpack is removed
    mpdata_remove = is_mpdata_removed(ans)
    if mpdata_remove == -1:
        return -1
    elif mpdata_remove == 1: 
	log2file("Info: MP_DATA is removed\n")
        return 2
    elif mpdata_remove == 0:
	log2file("Info: MP_ACK is removed\n")
        return 5
    else:
        return 8

# MUST be used for data with Request_hdrdata 
def is_ack_indirect(ans):
    for rcv in ans:
	if rcv[1].flag & tcplib.TH_RST == 1: continue
	if rcv[1].flag & tcplib.TH_SYN == 1: continue
	if rcv[1].flag & tcplib.TH_FIN == 1: continue
	if rcv[1].flag & tcplib.TH_ACK == 0: continue
	if rcv[1].ackno == 0: continue
	if rcv[0].length - rcv[0].hdrlen - rcv[1].hdrlen == 0:
	    log2file("Info: Got indirect Ack\n")
	    return 1
    log2file("Info: Got only direct Ack\n")
    return 0

def is_incoming_seq_rewritten(ans,http=0):
    rcv, rcvdhdr, senthdr, padding = hdr_request_reply(ans,http=http)
    if senthdr == None:
        return -1
    if rcv[1].seqno != senthdr[1].seqno:
        return 1
    else:
        return 0
    return -1
    
# MUST be used for data with Request_hdrdata 
def is_seq_rewritten(ans, myseq,http=0):
    rewritten = -1
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None: 
	return -1
    if rcvdhdr[1].seqno == myseq: 
	log2file("Info: our sent ISN was not rewritten\n")
        rewritten = 0
    else:
	log2file("Info: our sent ISN was rewritten\n")
        rewritten = 1
    return rewritten

def is_awnd_unexpected(ans):
    synack = tcpsrlib.get_synack(ans)
    if synack == None:
	return -1
    if synack[1].window == PeerAwnd: 
	log2file("Info: Got expected Awnd\n")
	return 0
    else: 
	log2file("Info: Got unexpected Awnd\n")
	return 1

# MUST be used for data with Request_hdrdata 
def is_awnd_rewritten(ans, myawnd, http=0):
    rewritten = -1
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None: 
	return -1
    if rcvdhdr[1].window == myawnd: 
	log2file("Info: our sent awnd was not rewritten\n")
        rewritten = 0
    else:
	log2file("Info: out sent awnd was rewritten\n")
        rewritten = 1
    return rewritten

# MUST be used for data with Request_hdrdata 
def are_segments_coalesced(ans, sent_len, http=0):
    rcvdhdr = hdr_request_reply(ans, http=http)[1]
    if rcvdhdr is None:
	return -1
    riph, rtcph, rtcpo = rcvdhdr
    rcvd_len = riph.length - riph.hdrlen - rtcph.hdrlen
    log2file('Info: sent %d Bytes data, peer received %d Bytes\n'%\
			(sent_len, rcvd_len))
    if rcvd_len > sent_len:
	log2file("Info: segments are coalesced\n")
	return 1
    elif rcvd_len == sent_len:
	log2file("Info: segments are not coalesced\n")
	return 0
    else:
	log2file("Info: peer received smaller segment, could be coalesced to former\n")
	return 1

# return 1 if all options are copied to the coalesced segment
# return 2 if some of options are copied to the coalesced segment
# return 3 if non of options are copied to the coalesced segment
# return 4 in the other cases
# MUST be used for data with Request_hdrdata 
def how_tcpopt_coalesced(ans, num_segs, optname, http=0):
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None:
	log2file("Info: failed to obtain header request\n")
	return -1
    riph, rtcph, rtcpo = rcvdhdr
    num_opt_rhdr = 0
    for opt in rtcpo:
	if opt[0] != optname:
	    continue
	num_opt_rhdr += 1
    num_opt_acks = 0
    if optname == 'MP_DSS':
        opt_acks = tcpsrlib.get_dataacklist(ans)
	nondup = []
	for i in opt_acks:
	    if not i in nondup:
	        nondup.append(i)
	num_opt_acks = len(nondup)
    elif optname == 'TIMESTAMP':
	for rcv in ans:
	    for opt in rcv[2]:
	        if opt[0] != 'TIMESTAMP':
	   	    continue
	   	num_opt_acks += 1
	
    num_opt = max(num_opt_rhdr, num_opt_acks-1)

    if num_opt == 0:
        log2file('Info: No %s is found in the coalesced segment\n'%optname)
	return 3
    elif num_opt == num_segs:
        log2file('Info: Coalesced segment had all %ss\n'%optname)
	return 1
    elif num_opt < num_segs:
        log2file('Info: Some of %ss are copied to coalesced segment\n'%optname)
	return 2
    elif num_opt > num_segs:
        log2file('Info: funny, coalesced segment had %ss more than transmitted\n'%optname)
	return 4

# detect split segments based on the peer-received segment
# MUST be used with Request_hdrdata
def is_segment_split(ans, sent_len, http=0):
    rcvdhdr = hdr_request_reply(ans,http=http)[1]
    if rcvdhdr is None: 
	return -1
    riph, rtcph, rtcpo = rcvdhdr
    rcvd_len = riph.length - riph.hdrlen - rtcph.hdrlen
    log2file('Info: sent %d Bytes data, peer received %d Bytes\n'%\
			(sent_len, rcvd_len))

    peer_rcvd_size = riph.length - riph.hdrlen - rtcph.hdrlen
    if rcvd_len < sent_len: 
        log2file('Info: Segment is split\n')
        return 1
    elif rcvd_len == sent_len: 
        log2file("Info: Segment is not split\n")
        return 0 
    else: 
        log2file("Info: Funny, peer-received segsize is larger than sent\n")
        return -1

# we assume at least one of acks has dataack as already checked
# return 1 if options are copied to all split segments
# return 2 if options are copied to some of split segments
# return 3 if any options are not copied to split segments
# return 4 in the other cases
def how_segment_split_from_dataack(ans):
    num_dataacks = 0
    for rcv in ans:
	dataacks = tcpsrlib.get_valid_dataacks_from_tcpopt(rcv[2])
	num_dataacks += len(dataacks)
	
    if num_dataacks == 0: 
        log2file("Info: No MP_DATA is given to split segments\n")
	return 3
    elif num_dataacks == len(tcpsrlib.get_acklist(ans)): 
        log2file("Info: MP_DATA is given to all split segments\n")
	return 1
    elif num_dataacks < len(tcpsrlib.get_acklist(ans)): 
        log2file("Info: MP_DATA is given to some of split segments\n")
	return 2
    else: 
        log2file("Info: More than 2 MP_DATAs are given to one of segments\n")
	return 4

def how_segment_split_from_ts(ans):
    num_ts = 0
    for rcv in ans:
	for opt in rcv[2]:
	    if opt[0] == 'TIMESTAMP':
	        num_ts += 1
    if num_ts == 0: 
        log2file("Info: No TIMESTAMP is given to split segments\n")
	return 3
    elif num_ts == len(tcpsrlib.get_acklist(ans)): 
        log2file("Info: TIMESTAMP is given to all split segments\n")
	return 1
    elif num_ts < len(tcpsrlib.get_acklist(ans)): 
        log2file("Info: TIMESTAMP is given to some of split segments\n")
	return 2
    else: 
        log2file("Info: More than 2 TIMESTAMPs are given to one of segments\n")
	return 4

# returns 0 if the receiver received the pseudo-rtxed segment
# returns 1 if the receiver didn't receive the pseudo-rtxed, and sender couldn't observe any acks
# returns 2 if the receiver didn't receive the pseudo-rtxed, but ack is advanced
# returns 3 if the receiver didn't receive the pseudo-rtxed, and ack indicated same sequence as sent segment
# returns 4 if the receiver received the pseudo-rtxed, but size was different
# returns 5 if connection has been reset due to pseudo retransmission
# returns 6 in the other cases
# MUST be used for data with Request_hdrdata 
def get_pseudo_rtx_result(ans, sentsize, sentseq, sentcontent, http=0):
    highest_ack = tcpsrlib.get_highest_ack(ans)
    if highest_ack == 0: 
	log2file("Info: Receiver didn't ack for pseudo rtx\n")
	if tcpsrlib.is_connection_reset(ans):
	    log2file("Info: pseudo rtx induced RST\n")
	    return 5
	else:
	    return 1

    rcv, rcvdhdr, senthdr, rcvd_payload = hdr_request_reply(ans, http=http)
    if rcvdhdr is None:
	if highest_ack > sentseq:
	    log2file("Info: ack is advanced, but rtxed is not received\n")
	    return 2
	elif highest_ack == sentseq:
	    log2file("Info: ack is observed, but not advanced\n")
	    return 3
	return 6

    riph, rtcph, rtcpo = rcvdhdr
    rcvd_len = riph.length - riph.hdrlen - rtcph.hdrlen
    rcvd_content = struct.unpack('!B', rcvd_payload[1:2])[0]
    if rcvd_len == sentsize and rcvd_content == sentcontent:
	log2file("Info: Pseudo retransmission has success\n")
	return 0
    elif rcvd_content == sentcontent:
	log2file("Info: Pseudo-retransmitted has been received, but resized\n")
	return 4
    else:
	log2file("Info: Receiver got modified content although first 1 bytes are not modified\n")
	return 6

# returns 0 if holed seq is successfully acked
# returns 1 if holed seq is not acked
# returns 2 if holed seq is acked to resend correct sequence number
# returns 3 in the other cases
def get_seqhole_result(ans, sentseq, skiplen, sentlen):
    highest_ack = tcpsrlib.get_highest_ack(ans)
    if highest_ack == sentseq + sentlen:
	return 0
    elif highest_ack == 0:
	return 1
    elif highest_ack == sentseq - skiplen:
	return 2
    else:
	return 3

# returns 0 if holed ack is successfully responded
# returns 1 if holed ack is not responded (no ack)
# returns 2 if holed ack got response to send correct ack
# returns 3 in the other cases
def get_ackhole_result(ans, sentack, skiplen):
    highest_seq = tcpsrlib.get_highest_seq(ans)
    if highest_seq == sentack:
	return 0
    elif highest_seq == 0:
	return 1
    elif highest_seq == sentack - skiplen:
	return 2
    else:
	return 3

#
# Data link layer routines for using pcap
# Returns tuple of interface name, source and destination MAC addresses
#
def get_linklayer_info(saddr, daddr):
    dmacaddr = 0
    ifname, smacaddr, err = tcpsrlib.get_ifname_and_smacaddr(saddr)
    if err:
	log2file("Warning: failed to lookup interface\n")
	return ("", smacaddr, dmacaddr)
    elif smacaddr != 0:
	for i in range(0, 3):
	    dmacaddr = tcpsrlib.get_dmacaddr(ifname, daddr)
	    if dmacaddr == 0:
	        log2file("Warning: failed to lookup destination MAC address\n")
	        continue
	    return (ifname, smacaddr, dmacaddr)
	log2file("Warning: continuous failure to lookup dest MAC address\n")
	return ("", smacaddr, dmacaddr)
    return (ifname, smacaddr, dmacaddr)
   
#
# Segment-output routines
#

def tcp_fin_close(daddr, dport, saddr, sport, seq, ackseq, awnd=Awnd, \
		options=(), usepcap=0, ifname="", dmac=0, smac=0, plabsrc=0):

    log2file("Info: Transmit Fin\n")
    fin = tcpsrlib.make_segment(daddr, saddr, dport, sport, awnd, seq, ackseq, \
		    tcplib.TH_ACK | tcplib.TH_FIN, options, ipcksum=usepcap)
    printpkts((fin,))
    for i in range(0, 2):
        ans, err = tcpsrlib.sendrecv_segments(daddr, (fin,), timeout=1.0, \
			sflags=0, usepcap=usepcap, ifname=ifname, \
			smacaddr=smac, dmacaddr=dmac)
        if err == -1:
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return err
	if len(tcpsrlib.get_acklist(ans)) > 0:
	    break
    printans(ans)
    ack = tcpsrlib.get_ack_for_fin(ans)
    if ack is None:
	if plabsrc:
	    close_dummy_conn(saddr, sport)
	log2file("Info: No Ack for FIN? return\n")
	return err

    fin = tcpsrlib.get_fin(ans)
    if fin is None: 
	log2file("Info: No Fin is observed? return\n")
        if plabsrc:
            close_dummy_conn(saddr, sport)
	return err

    log2file("Info: Transmit Ack for FIN\n")
    ack = tcpsrlib.make_segment(daddr, saddr, dport, sport, awnd, fin[1].ackno,\
		    fin[1].seqno+1L, tcplib.TH_ACK, ipcksum=usepcap)
    printpkts((ack,))
    err = tcpsrlib.send_segments(daddr, (ack,), usepcap=usepcap, ifname=ifname,\
		    smacaddr=smac, dmacaddr=dmac)
    if plabsrc:
        close_dummy_conn(saddr, sport)
    return err

def output_segments(daddr, dport, saddr, sport, startseq, ackseq, awnd, \
		segments, ts=(0,0), startdsn=(0,0), data=(), fq=0,\
		timeout=1.0, usepcap=0, ifname="", dmac=0, smac=0, http=0):

    # We assume DSN (0,0,0) is impossible except for SYN, so treat it as no DSN
    if startdsn == (0,0): dsnon = 0
    else: dsnon = 1
    nxtdsn = list(startdsn)
    nxtseq = startseq
    pkts = []

    # Compose TCP packets to transmit 
    for j in range(0, len(segments)):
        payload = ""
        soption = []
	contents = 0x00
	# compose payload
	if len(data) > j and data[j] != None:
	    contents = data[j]
	else:
	    contents = 0x99
	if (http == 1):
		get_str = ""
		for i in range(0, segments[j]-66):
			get_str += struct.pack('!B', contents)
		payload = "GET /%s HTTP/1.1\r\nHost: tcptest.smcquistin.uk\r\nConnection: close\r\n\r\n" % get_str
		payload = struct.pack(str(len(payload)) + 's', payload)
	else:
		for i in range(0, segments[j]):
			payload += struct.pack('!B', contents)

	# compose TCP option
	if ts != (0,0):
	    soption.append(['TIMESTAMP', ts[0], ts[1]])
	    soption.append(['NOP', ''])
	    soption.append(['NOP', ''])
	if dsnon: 
	    soption.append(['MP_DSS', False, False, False, None, 1500, nxtdsn[1], len(payload)])

	# compose TCP segment
	pkt = tcpsrlib.make_segment(daddr, saddr, dport, sport, awnd, \
			nxtseq, ackseq, tcplib.TH_ACK, tuple(soption), payload,\
			ipcksum=usepcap)
        pkts.append(pkt)

	nxtseq += len(payload)
	if dsnon:
	    nxtdsn[0] += len(payload)
	    nxtdsn[1] += len(payload)

    if fq:
        log2file("Info: Insert the first segment to the last\n")
        pkt = pkts.pop(0)
	pkts.append(pkt)

    # Transmit composed packets
    printpkts(pkts)
    ans, err = tcpsrlib.sendrecv_segments(daddr, pkts, timeout=timeout, \
		    sflags=0, usepcap=usepcap, ifname=ifname, \
		    smacaddr=smac, dmacaddr=dmac)
    if err == 0: 
	printans(ans)
    return ans, err

def tcp_syn_connect(daddr, dport, saddr, sport, isn, awnd=Awnd, options=(), \
		usepcap=0, ifname="", dmac=0, smac=0, plabsrc=0):

    seq = 0
    if plabsrc:
        dummy_failed = threading.Event()
        th_dummy_conn = threading.Thread(target=dummy_connect, \
			args=(daddr, saddr, dport, sport, dummy_failed))
	th_dummy_conn.setDaemon(True)
	th_dummy_conn.start()
	seq = get_peeped_isn(saddr, sport)
	if seq == 0 or dummy_failed.isSet() == True:
	    log2file("Warn: couldn't peep corresponding SYN\n")
	    return None, -2
    else:
	seq = isn

    syn = tcpsrlib.make_segment(daddr, saddr, dport, sport, awnd, seq, 0, \
		tcplib.TH_SYN, options, None, usepcap)
    synack = None
    for i in range(0, 3):
        log2file("Info: Transmit SYN\n")
	printpkts((syn,))
        ans, err = tcpsrlib.sendrecv_segments(daddr, (syn,), timeout=1.0, \
			sflags=tcplib.TH_SYN, usepcap=usepcap, ifname=ifname, \
			smacaddr=smac, dmacaddr=dmac)
	if err == -1: 
	    if plabsrc:
	       close_dummy_conn(saddr, sport)
	    return None, err
	printans(ans)
	if plabsrc:
	    if dummy_failed.isSet():
		return None, -2

	if tcpsrlib.is_connection_reset(ans) == 0:
	    synack = tcpsrlib.get_synack(ans)
	    if synack: 
	        break
	else:
	    log2file("Info: connection has been reset for SYN\n")
	    # Peeped SYN is not available anymore
	    if plabsrc:
		close_dummy_conn(saddr, sport)
	        return None, -2
        time.sleep(5)
    if synack == None: 
	if plabsrc:
	    close_dummy_conn(saddr, sport)
	return None, err

    log2file("Info: Transmit Ack for SYNACK\n")
    ack = tcpsrlib.make_segment(daddr, saddr, dport, sport, awnd, \
		    synack[1].ackno, synack[1].seqno+1L, tcplib.TH_ACK, \
		    ipcksum=usepcap)
    printpkts((ack,))
    ans, err = tcpsrlib.sendrecv_segments(daddr, (ack,), usepcap=usepcap, \
		    ifname=ifname, smacaddr=smac, dmacaddr=dmac)
    if tcpsrlib.is_connection_reset(ans):
	log2file("Info: connection has been reset against Ack for SYNACK\n")
	if plabsrc:
	    close_dummy_conn(saddr, sport)
	return None, -2

    return synack, err

#
# General routines called by similar experiments
#
def tcp_syn_test_x(dhost, dport, mptest=0, peroptpad=0, usepcap=0, plabsrc=0):
    result = copy.copy(TestEntries)
    daddr, lhost, saddr = tcpsrlib.gethostpair(dhost)
    if daddr == 0 or saddr == 0: 
	return result, 0
    sport = random.randrange(20000, 50000)

    ifname = ""
    dmacaddr = smacaddr = 0
    if usepcap:
        ifname, smacaddr, dmacaddr = get_linklayer_info(saddr, daddr)
	if ifname == "":
	    return result, -1

    if mptest and peroptpad:
        soptions = [('MSS', Mss), ('TIMESTAMP', Ts_vals[0], Ts_vals[1]), \
		   ('NOP',''), ('NOP',''), ('SACKOK',''), ('NOP',''), \
		   ('NOP',''), ('WSCALE', Winscale), ('NOP',''),\
		   ('MP_CAPABLE', 13, Mptcp_token, None)]
    elif mptest:
        soptions = [('MSS', Mss), ('TIMESTAMP',Ts_vals[0], Ts_vals[1]),\
		   ('SACKOK',''), ('WSCALE', Winscale), ('NOP',''), \
		   ('MP_CAPABLE', 13, Mptcp_token, None)]
    else:
        soptions = [('MSS', Mss), ('TIMESTAMP',Ts_vals[0], Ts_vals[1]), \
		   ('SACKOK',''), ('WSCALE', Winscale), ('NOP','')] 
    seq = 0
    if plabsrc:
        dummy_failed = threading.Event()
        th_dummy_conn = threading.Thread(target=dummy_connect, \
			args=(daddr, saddr, dport, sport, dummy_failed))
	th_dummy_conn.setDaemon(True)
	th_dummy_conn.start()
	seq = get_peeped_isn(saddr, sport)
	if seq == 0 or dummy_failed.isSet() == True:
	    log2file("Warn: couldn't peep corresponding SYN\n")
	    return result, -2
    else:
	seq = Isn

    syn = tcpsrlib.make_segment(daddr, saddr, dport, sport, Awnd, seq, 0, \
		tcplib.TH_SYN, tuple(soptions), ipcksum=usepcap)

    for i in range(0, 3):
	printpkts((syn,))
        ans, err = tcpsrlib.sendrecv_segments(daddr, (syn,), timeout=1.0, \
			sflags=0, usepcap=usepcap, ifname=ifname, \
			smacaddr=smacaddr, dmacaddr=dmacaddr)
	if err == -1:
	    return result, err
	printans(ans)

	if mptest:
	    res0 = get_syn_opt_result(ans)
	else: 
	    res0 = get_syn_result(ans)

	if res0 == 1 or res0 == 2: 
	    time.sleep(5)
	else: 
	    break

    if mptest and peroptpad:
        result['SynOpt2'] = res0
    elif mptest and peroptpad == 0:
        result['SynOpt'] = res0
    else:
        result['Syn'] = res0
    if res0 == 1 or res0 == 2: 
        if plabsrc:
	    close_dummy_conn(saddr, sport)
        return result, err

    # obtain awnd information (This must be done at SYN to detect syn proxy)
    if mptest == 0 or (mptest == 1 and peroptpad == 0):
        unexpawnd = is_awnd_unexpected(ans)
        if mptest and peroptpad == 0:
            result['UnexpAwnd4Opt'] = unexpawnd
        elif mptest == 0:
            result['UnexpAwnd'] = unexpawnd

    if tcpsrlib.is_connection_reset(ans):
        log2file("Info: We already got RST, return\n")
        if plabsrc:
	    close_dummy_conn(saddr, sport)
	return result, err

    log2file("Info: Transmit Ack for SYNACK\n")
    synack = tcpsrlib.get_synack(ans)
    ack = tcpsrlib.make_segment(daddr, saddr, dport, sport, Awnd, \
	        synack[1].ackno, synack[1].seqno+1L, tcplib.TH_ACK, \
		    ipcksum=usepcap)
    printpkts((ack,))
    err = tcpsrlib.send_segments(daddr, (ack,), usepcap=usepcap, ifname=ifname,\
		    smacaddr=smacaddr, dmacaddr=dmacaddr)
    if err: 
        if plabsrc:
	    close_dummy_conn(saddr, sport)
        return result, err

    err = tcp_fin_close(daddr, dport, saddr, sport, synack[1].ackno, \
		    synack[1].seqno+1L, usepcap=usepcap, ifname=ifname, \
		    dmac=dmacaddr, smac=smacaddr, plabsrc=plabsrc)
    return result, err

# opt=1: Known option (TIMESTAMP)
# opt=2: Unknown option (MP_DATA)
# opt=3: Unknown option for SYN, no option for data
def tcp_data_test_x(dhost, dport, opt=0, usepcap=0, plabsrc=0, http=0):
    result_type = ""
    if (http == 1):
    	result_type = "Http"
    result = copy.copy(TestEntries)
    daddr, lhost, saddr = tcpsrlib.gethostpair(dhost)
    if daddr == 0 or saddr == 0:
       	return result, 0
    sport = random.randrange(20000, 50000)

    ifname = ""
    dmacaddr = smacaddr = 0
    if usepcap:
        ifname, smacaddr, dmacaddr = get_linklayer_info(saddr, daddr)
	if ifname == "":
	    return result, -1

    if opt == 3:
        synopt = (('MSS', 512), ('TIMESTAMP', Ts_vals[0], Ts_vals[1]),\
		('SACKOK',''), ('WSCALE', Winscale), ('NOP',''), \
		('MP_CAPABLE', 13, Mptcp_token, None))
    else:
        synopt = (('MSS', 512),)
    synack, err = tcp_syn_connect(daddr, dport, saddr, sport, Isn, Awnd, \
		    synopt, usepcap, ifname, dmacaddr, smacaddr, plabsrc)
    if err == -1 or synack is None or err == -2: 
        return result, err 

    nxtseq = synack[1].ackno
    ackseq = synack[1].seqno + 1
    mss = tcpsrlib.get_mss_from_tcpopt(synack[2])
    if mss == 0:
        mss = 512
    nxtdsn = ts = [0, 0]
    data = (Request_hdrdata,)
    if opt == 1:
        ts = list(Ts_vals)
        mss -= 12
    if opt == 2: 
        nxtdsn = [Mptcp_idsn, 1]
        mss -= 16

    res0 = -1
    log2file("Info: test for a full-sized (" + '%d'%mss + " Bytes) segment\n")
    for i in range(0, 3):
        ans, err = output_segments(daddr, dport, saddr, sport, nxtseq, ackseq, \
			Awnd, (mss, ), tuple(ts), tuple(nxtdsn), data=data,\
			timeout=3.0, usepcap=usepcap, ifname=ifname, \
			dmac=dmacaddr, smac=smacaddr, http=http)
	if err == -1: 
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	if hdr_request_reply(ans,http=http,result=result)[0] == None:
    	    nxtseq = get_snd_nxt(ans, nxtseq)
    	    ackseq = get_rcv_nxt(ans, ackseq)
	    continue
	if opt == 0 or opt == 3: 
	    res0 = get_data_result(ans, nxtseq, mss)
	elif opt == 1: 
	    res0 = get_data_known_opt_result(ans, tuple(ts), nxtseq, mss, http=http)
	elif opt == 2: 
	    res0 = get_data_opt_result(ans, nxtdsn[0], nxtseq, mss)

	if tcpsrlib.is_connection_reset(ans):
	    log2file("Info: connection has been reset, cannot retry\n")
	    break
	if res0 == 1: 
	    time.sleep(1)
	else: 
	    break
    if opt == 0: 
	result['Data' + result_type] = res0
    elif opt == 1: 
	result['DataKnownOpt' + result_type] = res0
    elif opt == 2: 
	result['DataOpt' + result_type] = res0

    if res0 == 1 or res0 == -1:
	if plabsrc:
	    close_dummy_conn(saddr, sport)
        return result, err

    # obtain additional information 
    if opt == 0: 
	result['IndAck' + result_type] = is_ack_indirect(ans)
	result['ChangeSeq' + result_type] = is_seq_rewritten(ans, nxtseq,http=http)
	result['ChangeAwnd' + result_type] = is_awnd_rewritten(ans, Awnd,http=http)
	result['ChangeIncomingSeq' + result_type] = is_incoming_seq_rewritten(ans,http=http)
    elif opt == 1:
	result['IndAck4KnownOpt' + result_type] = is_ack_indirect(ans)
	result['ChangeSeq4KnownOpt' + result_type] = is_seq_rewritten(ans, nxtseq,http=http)
	result['ChangeAwnd4KnownOpt' + result_type] = is_awnd_rewritten(ans, Awnd,http=http)
    elif opt == 2:
	result['IndAck4Opt' + result_type] = is_ack_indirect(ans)
	result['ChangeSeq4Opt' + result_type] = is_seq_rewritten(ans, nxtseq,http=http)
	result['ChangeAwnd4Opt' + result_type] = is_awnd_rewritten(ans, Awnd,http=http)
    elif opt == 3:
	result['ChangeIncomingSeq4Opt' + result_type] = is_incoming_seq_rewritten(ans,http=http)

    if opt == 0:
        result['Split' + result_type] = is_segment_split(ans, mss,http=http)
    elif opt == 1:
        result['SplitKnownOpt' + result_type] = is_segment_split(ans, mss,http=http)
	if result['SplitKnownOpt' + result_type] > 0: 
	    result['SplitKnownOpt' + result_type] = how_segment_split_from_ts(ans,http=http)
    elif opt == 2:
        result['SplitOpt' + result_type] = is_segment_split(ans, mss,http=http)
	if result['SplitOpt' + result_type] > 0: 
	    result['SplitOpt' + result_type] = how_segment_split_from_dataack(ans,http=http)

    if tcpsrlib.is_connection_reset(ans):
	if plabsrc:
	    close_dummy_conn(saddr, sport)
	return result, err

    nxtseq = get_snd_nxt(ans, nxtseq)
    ackseq = get_rcv_nxt(ans, ackseq)
    err = tcp_fin_close(daddr, dport, saddr, sport, nxtseq, ackseq, \
		    usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
		    smac=smacaddr, plabsrc=plabsrc)
    return result, err

def tcp_segment_coalesce_1(dhost, dport, opt=0, fq=0, usepcap=0, plabsrc=0, http=0):
    retval = -1
    daddr, lhost, saddr = tcpsrlib.gethostpair(dhost)
    if daddr == 0 or saddr == 0: 
	return retval, 0
    sport = random.randrange(20000, 50000)

    ifname = ""
    dmacaddr = smacaddr = 0
    if usepcap:
        ifname, smacaddr, dmacaddr = get_linklayer_info(saddr, daddr)
	if ifname == "":
	    return result, -1

    if opt == 0 or opt == 2:
        synopts = (('MSS', 512),)
    elif opt == 1:
        synopts = (('MSS', 512), ('TIMESTAMP', Ts_vals[0], Ts_vals[1]), ('NOP', ''), ('NOP', ''))

    synack, err = tcp_syn_connect(daddr, dport, saddr, sport, Isn, Awnd, \
		    synopts, usepcap, ifname, dmacaddr, smacaddr, plabsrc)
    if err == -1 or synack is None or err == -2: 
        return retval, err 

    nxtseq = synack[1].ackno
    ackseq = synack[1].seqno + 1
    mss = tcpsrlib.get_mss_from_tcpopt(synack[2])
    if mss == 0:
        mss = 512
    nxtdsn = ts = [0, 0]
    if opt == 1:
        ts = list(Ts_vals)
    if opt == 2: 
        nxtdsn = [Mptcp_idsn, 1]
    
    # We keep room for TIMESTAMP that might be added by middleboxes
    if fq:
	data = (None, Request_hdrdata)
        if opt == 1:
            segs = (min(mss, PeerMss)-12, min(mss, PeerMss)/2-12, min(mss, PeerMss)/2-12)
	elif opt == 2:
            segs = (min(mss, PeerMss)-28, min(mss, PeerMss)/2-28, min(mss, PeerMss)/2-28)
	else:
            segs = (min(mss, PeerMss)-12, min(mss, PeerMss)/2-12, min(mss, PeerMss)/2-12)
    else:
	data = (Request_hdrdata,)
        if opt == 1:
            segs = (min(mss, PeerMss)/2-12, min(mss, PeerMss)/2-12, min(mss, PeerMss)-12)
	elif opt == 2:
            segs = (min(mss, PeerMss)/2-28, min(mss, PeerMss)/2-28, min(mss, PeerMss)-28)
	else:
            segs = (min(mss, PeerMss)/2-12, min(mss, PeerMss)/2-12, min(mss, PeerMss)-12)
    log2file("Info: test for small segments\n")

    # We try only once in each trial as it could cause sequence inconsisntency
    ans, err = output_segments(daddr, dport, saddr, sport, nxtseq, ackseq, \
			Awnd, segs, tuple(ts), tuple(nxtdsn), data=data, \
			fq=fq, timeout=3.0, usepcap=usepcap, ifname=ifname, \
			dmac=dmacaddr, smac=smacaddr, http=http)
    if err == -1: 
	if plabsrc:
	    close_dummy_conn(saddr, sport)
        return retval, err
    retval = are_segments_coalesced(ans, segs[1], http=http)
    if retval > 0:
        if opt == 1: 
            retval = how_tcpopt_coalesced(ans, 2, 'TIMESTAMP', http=http)
        elif opt == 2:
            retval = how_tcpopt_coalesced(ans, 2, 'MP_DSS', http=http)

    if tcpsrlib.is_connection_reset(ans):
	if plabsrc:
	    close_dummy_conn(saddr, sport)
	return retval, err

    nxtseq = get_snd_nxt(ans, nxtseq)
    ackseq = get_rcv_nxt(ans, ackseq)
    err = tcp_fin_close(daddr, dport, saddr, sport, nxtseq, ackseq, \
		    usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
		    smac=smacaddr, plabsrc=plabsrc)
    return retval, err

def tcp_segment_coalesce_x(dhost, dport, opt=0, fq=0, usepcap=0, plabsrc=0, http=0):
    result_type = ""
    if (http == 1):
    	result_type = "Http"
    result = copy.copy(TestEntries)
    tmp_res = [0, 0, 0] # number of res0 -1, 0 and more
    res0 = -1
    err = 0

    for i in range(0, 10):
        res0, err = tcp_segment_coalesce_1(dhost, dport, opt, fq, usepcap=usepcap, plabsrc=plabsrc, http=http)
	if err == -1:
	    return result, err
	elif err == -2:
	    time.sleep(10)
	    continue
	elif res0 > 0:
	    tmp_res[2] += 1
	    break
	elif res0 == 0:
	    tmp_res[1] += 1
	elif res0 == -1:
	    tmp_res[0] += 1

    if tmp_res[2] > 0:
        res = res0
    elif tmp_res[1] > 0:
        res = 0
    else:
        res = -1
    
    if res == -1:
        return result, err

    if opt == 0:
        if fq: 
	    result['CoalesceFq' + result_type] = res
	else: 
	    result['Coalesce' + result_type] = res
    elif opt == 1:
	if fq: 
	    result['CoalesceFqKnownOpt' + result_type] = res
	else: 
	    result['CoalesceKnownOpt' + result_type] = res
    elif opt == 2:
	if fq: 
	    result['CoalesceFqOpt' + result_type] = res
	else: 
	    result['CoalesceOpt' + result_type] = res
    return result, err

# resize:1 retransmit larger segment with different payload
# resize:2 retransmit smaller segment with different payload
def tcp_pseudo_rtx_test_x(dhost, dport, resize=0, usepcap=0, plabsrc=0, http=0):
    result_type = ""
    if (http == 1):
    	result_type = "Http"
    result = copy.copy(TestEntries)
    daddr, lhost, saddr = tcpsrlib.gethostpair(dhost)
    if daddr == 0 or saddr == 0: 
	return result, 0
    sport = random.randrange(20000, 50000)

    ifname = ""
    dmacaddr = smacaddr = 0
    if usepcap:
        ifname, smacaddr, dmacaddr = get_linklayer_info(saddr, daddr)
	if ifname == "":
	    return result, -1

    synack, err = tcp_syn_connect(daddr, dport, saddr, sport, Isn, Awnd, \
		    (('MSS', 512),), usepcap, ifname, dmacaddr, smacaddr, \
		    plabsrc)
    if err == -1 or synack is None or err == -2: 
        return result, err 

    nxtseq = synack[1].ackno
    ackseq = synack[1].seqno + 1
    mss = tcpsrlib.get_mss_from_tcpopt(synack[2])
    if mss == 0:
        mss = 512
    # We keep space where middlebox puts TIMESTAMP
    fullsiz = min(mss, PeerMss) - 12

    # transmit TCP segments (Here we expect duplicated ack)
    log2file("We expect to observe dup ack\n")
    if resize == 1:
        segs = (fullsiz, fullsiz-16)
    else:
        segs = (fullsiz, fullsiz)
    failure_count = 0
    while failure_count < 3:
	ans, err = output_segments(daddr, dport, saddr, sport, nxtseq, ackseq, \
			Awnd, segs, data=(None, Request_dupack), \
			usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
			smac=smacaddr,http=http)
	if err < 0 or tcpsrlib.is_connection_reset(ans):
	    if err == 0:
	        log2file("Info: connection has been reset during experiment\n")
	        err = -2
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	elif len(tcpsrlib.get_acklist(ans)) == 0:
	    failure_count += 1
	    continue
	elif tcpsrlib.get_highest_ack(ans) == nxtseq + sum(segs):
	    # The responder could send back dupack for segment with spdata.  
	    # If they are acked as usual, it could be done by middleboxes
	    log2file("Info: Positive ack could be done by middleboxes\n")
	    nxtseq += segs[0]
	    break
	nxtseq = get_snd_nxt(ans, nxtseq)
	break

    if failure_count > 2:
        log2file("Info: failed during test, impossible to continue\n")
        err = tcp_fin_close(daddr, dport, saddr, sport, nxtseq, ackseq, \
			usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
			smac=smacaddr, plabsrc=plabsrc)
        return result, err
    
    # Pseudo-retransmission, we assume second packet is treated as lost.  
    # Server should be implemented to send back same ackseq as seq if he 
    # observed special request
    if resize == 2:
        rsegs = (fullsiz-16,)
    else:
        rsegs = (fullsiz,)
    log2file("Info: Retransmit segment with different payload\n")
    for i in range(0, 3):
        ans, err = output_segments(daddr, dport, saddr, sport, nxtseq, ackseq, \
			Awnd, rsegs, data=(Request_hdrdata,), timeout=3.0, 
			usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
			smac=smacaddr,http=http)
        if err < 0: 
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	res0 = get_pseudo_rtx_result(ans, rsegs[0], nxtseq, Request_hdrdata, http=http)
	if i > 0 and res0 == 5:
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	if resize == 0:
            result['PseudoRtx' + result_type] = res0
	elif resize == 1:
            result['PseudoRtxL' + result_type] = res0
	elif resize == 2:
            result['PseudoRtxS' + result_type] = res0

	if tcpsrlib.is_connection_reset(ans):
	    log2file("Info: connection has been reset, cannot retry\n")
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	if res0 != 1:
	    break

    # Close connection 
    nxtseq = get_snd_nxt(ans, nxtseq)
    ackseq = get_rcv_nxt(ans, ackseq)
    err = tcp_fin_close(daddr, dport, saddr, sport, nxtseq, ackseq, \
		    usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
		    smac=smacaddr, plabsrc=plabsrc)
    return result, err

def tcp_seq_hole_test_x(dhost, dport, ackhole=0, usepcap=0, plabsrc=0, http=0):
    result_type = ""
    if (http == 1):
    	result_type = "Http"
    result = copy.copy(TestEntries)
    daddr, lhost, saddr = tcpsrlib.gethostpair(dhost)
    if daddr == 0 or saddr == 0: 
	return result, 0 
    sport = random.randrange(20000, 50000)

    ifname = ""
    dmacaddr = smacaddr = 0
    if usepcap:
        ifname, smacaddr, dmacaddr = get_linklayer_info(saddr, daddr)
	if ifname == "":
	    return result, -1

    synack, err = tcp_syn_connect(daddr, dport, saddr, sport, Isn, Awnd, \
		    (('MSS', 512),), usepcap, ifname, dmacaddr, smacaddr, \
		    plabsrc)
    if err == -1 or synack is None or err == -2: 
        return result, err 

    nxtseq = synack[1].ackno
    ackseq = synack[1].seqno + 1
    mss = tcpsrlib.get_mss_from_tcpopt(synack[2])
    if mss == 0:
        mss = 512
    data = ()
    if ackhole:
        data = (Request_hdrdata,)

    fullsiz = min(mss, PeerMss)-12
    failure_count = 0
    while failure_count < 3:
        ans, err = output_segments(daddr, dport, saddr, sport, nxtseq, ackseq, \
			Awnd, (fullsiz,), data=data, usepcap=usepcap, \
			ifname=ifname, dmac=dmacaddr, smac=smacaddr, http=http)
        if err < 0 or tcpsrlib.is_connection_reset(ans): 
	    if err == 0:
	        log2file("Info: connection has been reset during experiment\n")
	        err = -2
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	elif len(tcpsrlib.get_acklist(ans)) == 0:
	    failure_count += 1
	    continue
	elif ackhole and hdr_request_reply(ans,http=http,result=result)[0] == None:
	    nxtseq = get_snd_nxt(ans, nxtseq)
	    ackseq = get_rcv_nxt(ans, ackseq)
	    failure_count += 1
	    continue
	nxtseq = get_snd_nxt(ans, nxtseq)
	ackseq = get_rcv_nxt(ans, ackseq)
	break

    if failure_count > 2:
        log2file("Info: failed during test, impossible to continue\n")
        err = tcp_fin_close(daddr, dport, saddr, sport, nxtseq, ackseq, \
			usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
			smac=smacaddr, plabsrc=plabsrc)
        return result, err

    if ackhole: 
        log2file('Info: Transmit a segment with skipping %d ack num\n'%fullsiz)
        ackseq += fullsiz
    else: 
        log2file('Info: Transmit a segment with skipping %d seq num\n'%fullsiz)
        nxtseq += fullsiz
    
    for i in range(0, 3):
        ans, err = output_segments(daddr, dport, saddr, sport, nxtseq, ackseq, \
			Awnd, (fullsiz,), timeout=3.0, usepcap=usepcap, \
			ifname=ifname, dmac=dmacaddr, smac=smacaddr, http=http)
        if err < 0:
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err
	if ackhole:
	    result['AckHole' + result_type] = get_ackhole_result(ans, ackseq, fullsiz)
	    if result['AckHole'] != 1:
	        nxtseq = get_snd_nxt(ans, nxtseq)
	        ackseq = get_rcv_nxt(ans, ackseq)
	        break
	else:
	    result['SeqHole' + result_type] = get_seqhole_result(ans, nxtseq, fullsiz, fullsiz)
	    if result['SeqHole'] != 1:
	        nxtseq = get_snd_nxt(ans, nxtseq)
	        ackseq = get_rcv_nxt(ans, ackseq)
	        break
	if tcpsrlib.is_connection_reset(ans):
	    log2file("Info: connection has been reset, cannot retry\n")
	    if plabsrc:
	        close_dummy_conn(saddr, sport)
	    return result, err

    # Close connection 
    err = tcp_fin_close(daddr, dport, saddr, sport, nxtseq, ackseq, \
		    usepcap=usepcap, ifname=ifname, dmac=dmacaddr, \
		    smac=smacaddr, plabsrc=plabsrc)
    return result, err

#
# Entry points for each experiment
#
# MUST have 4 arguments, dest hostname, dest port, if use pcap, and 
# if platform is planetlab
#
# Regular SYN test
def tcp_syn_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_syn_test_x(dhost, dport, mptest=0, peroptpad=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# Test for SYN including unknown option
def tcp_syn_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_syn_test_x(dhost, dport, mptest=1, peroptpad=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# Test for SYN including unknown option (each option is 32-bit aligned)
def tcp_syn_opt2_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_syn_test_x(dhost, dport, mptest=1, peroptpad=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

def tcp_incoming_seq_sopt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_data_test_x(dhost, dport, opt=3, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

def tcp_incoming_seq_sopt_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_data_test_x(dhost, dport, opt=3, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# Regular full-sized segment test
def tcp_data_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_data_test_x(dhost, dport, opt=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# Regular full-sized segment test (w/ HTTP)
def tcp_data_test_http(dhost, dport, usepcap=0, plabsrc=0):
	result, err = tcp_data_test_x(dhost, dport, opt=0, usepcap=usepcap, plabsrc=plabsrc, http=1)
	return result, err

# Test for full-sized segment including known option
def tcp_data_known_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_data_test_x(dhost, dport, opt=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# Test for full-sized segment including known option (w/ HTTP)
def tcp_data_known_opt_test_http(dhost, dport, usepcap=0, plabsrc=0):
	result, err = tcp_data_test_x(dhost, dport, opt=1, usepcap=usepcap, plabsrc=plabsrc, http=1)
	return result, err

# Test for full-sized segment including unknown option
def tcp_data_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_data_test_x(dhost, dport, opt=2, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# Test for full-sized segment including unknown option (w/ HTTP)
def tcp_data_opt_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_data_test_x(dhost, dport, opt=2, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# segment coalescing test 
def tcp_seg_coalesce_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=0, fq=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# segment coalescing test (w/ HTTP)
def tcp_seg_coalesce_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=0, fq=0, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# segment coalescing test (with known option)
def tcp_seg_coalesce_known_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=1, fq=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# segment coalescing test (with known option) (w/ HTTP)
def tcp_seg_coalesce_known_opt_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=1, fq=0, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# segment coalescing test (with unknown option)
def tcp_seg_coalesce_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=2, fq=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# segment coalescing test (with unknown option) (w/ HTTP)
def tcp_seg_coalesce_opt_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=2, fq=0, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# segment coalescing test (force middleboxes queue)
def tcp_seg_coalesce_fq_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=0, fq=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# segment coalescing test (force middleboxes queue) (w/ HTTP)
def tcp_seg_coalesce_fq_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=0, fq=1, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# segment coalescing test (with option, force middleboxes queue)
def tcp_seg_coalesce_fq_known_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=1, fq=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# segment coalescing test (with option, force middleboxes queue) (w/ HTTP)
def tcp_seg_coalesce_fq_known_opt_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=1, fq=1, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# segment coalescing test (with option, force middleboxes queue)
def tcp_seg_coalesce_fq_opt_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=2, fq=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# segment coalescing test (with option, force middleboxes queue) (w/ HTTP)
def tcp_seg_coalesce_fq_opt_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_segment_coalesce_x(dhost, dport, opt=2, fq=1, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# Test for retransmission with different payload
def tcp_pseudo_rtx_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_pseudo_rtx_test_x(dhost, dport, resize=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

# Test for retransmission with different payload (w/ HTTP)
def tcp_pseudo_rtx_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_pseudo_rtx_test_x(dhost, dport, resize=0, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

def tcp_pseudo_larger_rtx_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_pseudo_rtx_test_x(dhost, dport, resize=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

def tcp_pseudo_larger_rtx_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_pseudo_rtx_test_x(dhost, dport, resize=1, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

def tcp_pseudo_smaller_rtx_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_pseudo_rtx_test_x(dhost, dport, resize=2, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

def tcp_pseudo_smaller_rtx_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_pseudo_rtx_test_x(dhost, dport, resize=2, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

# Test for hole of sequences
def tcp_seq_hole_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_seq_hole_test_x(dhost, dport, ackhole=0, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

def tcp_seq_hole_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_seq_hole_test_x(dhost, dport, ackhole=0, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

def tcp_ack_hole_test(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_seq_hole_test_x(dhost, dport, ackhole=1, usepcap=usepcap, plabsrc=plabsrc)
    return result, err

def tcp_ack_hole_test_http(dhost, dport, usepcap=0, plabsrc=0):
    result, err = tcp_seq_hole_test_x(dhost, dport, ackhole=1, usepcap=usepcap, plabsrc=plabsrc, http=1)
    return result, err

def merge_to_summary(summary, results):
    retval = copy.copy(summary)
    for k, v in results.iteritems():
	if v != -1: retval[k] = v
    return retval

#
# UDP flooding routines to avoid ICMP going to TCP
# Stopped by Fld_udp_on being offed 
#
UDP_FLOOD_DPORT = 24001
Fld_udp_on = threading.Event()
def flood_udp(daddr_str):
    global Fld_udp_on

    Fld_udp_on.set()
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udpsock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    payload = "a"
    while Fld_udp_on.isSet() == True:
        udpsock.sendto(payload, (daddr_str, UDP_FLOOD_DPORT))
	time.sleep(0.0005)
    log2file("Info: Fld_udp_on has been cleaned, return\n")
    udpsock.close()

#
# Peep ISN from SYN generated by OS with connect()
#
PEEP_BREAK_DPORT = 24000
Peeper_lock = threading.Lock()
Peeped_syns = [] # (src_addr, src_port, isn)
def peep_os_syn(daddr_str, dport):
    global Peeped_syns
    global Peeper_lock

    Peeper_lock.acquire()
    Peeped_syns = []
    for i in range(0, 10):
	Peeped_syns.append((0,0,0))
    Peeper_lock.release()

    os.putenv('LANG', 'C')
    os.putenv('PATH', '/bin:/sbin:/usr/bin:/usr/sbin:$PATH')
    cmd = 'netstat -rn | grep ^0.0.0.0 | sed s/\' \{2,\}\'/\' \'/g | cut -d\' \' -f2,8' 
    s = commands.getoutput(cmd)
    (nxthop_str, dummy, ifname) = s.partition(' ')
    try:
        fqdn = socket.getfqdn()
    except socket.gaierror:
	log2file("Error: failed to lookup localhost\n")
        sys.exit(1)
    try:
        saddr_str = socket.gethostbyname(fqdn)
    except socket.gaierror:
	log2file("Error: failed to lookup localhost\n")
        sys.exit(1)

    plib = pcaplib.pcaplib()
    if plib.lib == None:
	log2file("Error: failed to load libpcap\n")
	sys.exit(1)
    descrip = plib.Pcap_open_live(ifname, to_ms=4000)
    if descrip == None:
	log2file("Error: failed to open pcap descripter\n")
	sys.exit(1)
    filter = '(ip[8] = 1 and dst host %s and dst port %d and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0) or (ip[8] = 1 and dst host %s and dst port %d and udp)'%(daddr_str, dport, daddr_str, PEEP_BREAK_DPORT)
    err = plib.Pcap_compile(descrip, filter)
    if err != 0:
        plib.Pcap_close(descrip)
	log2file("Error: failed to set filter\n")
	sys.exit(1)

    while True:
        err, rcvfrm = plib.Pcap_next_ex(descrip)
	if err > 0:
	    ttl, proto = struct.unpack('!BB', rcvfrm[22:24])
	    # handling breaking packet (1-TTL UDP packet to BREAK_DPORT)
	    if ttl == 1 and proto == 17:
		err = -2
		break
	    # quick filtering of SYN from OS by TTL
	    elif ttl != 1 or proto != 6:
		continue
	    Peeper_lock.acquire()
	    Peeped_syns.pop(0)
	    Peeped_syns.append((struct.unpack('!L', rcvfrm[26:30])[0], \
				    struct.unpack('!H', rcvfrm[34:36])[0], \
				    struct.unpack('!L', rcvfrm[38:42])[0]))
	    Peeper_lock.release()
	    continue
	elif err == 0:
	    continue
	elif err == -2 or err == -1:
	    log2file('Error: pcap_next_ex returned %d\n'%err)
	    break
    plib.Pcap_close(descrip)
    return

def stop_peep_os_syn(daddr_str):
    try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    except (socket.error, socket.gaierror):
	log2file("Warn: failed to create socket to stop peeping OS syn\n")
	return
    for i in range(0, 3):
	s.sendto("*", (daddr_str, PEEP_BREAK_DPORT))
	time.sleep(0.3)
    s.close()

def get_peeped_isn(saddr, sport):
    global Peeper_lock

    for i in range(0, 3):
        Peeper_lock.acquire()
	for sy in reversed(Peeped_syns):
	    if sy[0] == saddr and sy[1] == sport:
		Peeper_lock.release()
	        return sy[2]
	Peeper_lock.release()
	time.sleep(0.01)
    return 0

#
# Dummy connections to avoid OS TCP resets connections
#
Connected_list = []
def dummy_connect(daddr, saddr, dport, sport, failed):
    global Connected_list

    log2file('Info: Trying to create dummy connection (sport %d dport %d)\n'%(sport, dport))
    daddr_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', daddr))
    saddr_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', saddr))
    try:
        ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM, \
			socket.IPPROTO_TCP)
	ss.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    except (socket.error, socket.gaierror, IOError):
	log2file("Error: error in open socket for dummy connection\n")
	return
    try:
	ss.bind((saddr_str, sport))
	ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except (socket.error, socket.gaierror, IOError):
	log2file("Error: error in bind for dummy connection\n")
	return
    try:
        ss.connect((daddr_str, dport))
    	Connected_list.append((saddr, sport, ss))
    except socket.error, e:
	log2file('Error: error in connecting dummy connection %d\n'%e[0])
	failed.set()
    return

def close_dummy_conn(saddr, sport):
    global Connected_list

    idx = -1
    found = 0
    for ent in Connected_list:
        idx += 1
	if ent[0] == saddr and ent[1] == sport:
	    try:
	        ent[2].close()
	        log2file("Info: Dummy connection has been closed\n")
	    except (socket.error, socket.herror, socket.gaierror):
		log2file("Warn: failed to close dummy connection\n")
	    found = 1
	    break
    if idx >= 0 and found:
	Connected_list.pop(idx)
    elif found == 0:
	log2file("Warn: corresponding dummy connection is not found\n")

def cleanup_dummy_conn():
    global Connected_list

    for ent in Connected_list:
        try:
	    ent[2].close()
	except (socket.error, socket.herror, socket.gaierror):
	    pass
    Connected_list = []
    
#
# Request destination planetlab node to start UDP flooding for experiments
#
def plabdst_udp_flood_operation(daddr, cmd):

    if cmd != FLOOD_UDP_START and cmd != FLOOD_UDP_STOP:
        log2file("Error: wrong argument for udp_flood_operation\n")
        return -1
    daddr_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', daddr))
    flood_confirmed = 0
    try:
        udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except (socket.error, OSError, socket.gaierror):
	log2file("Error: error in opening socket for requesting UDP flooding\n")
	return -1
    udpsock.settimeout(2)
    for i in range(0, 3):
	try:
	    udpsock.sendto(struct.pack('!L', cmd), \
			    (daddr_str, UDP_FLOOD_CTL_PORT))
	except socket.error:
	    log2file("Error: error in sending UDP flooding packet")
	    udpsock.close()
	    return -1
	try:
            (data, address) = udpsock.recvfrom(4)
	except socket.timeout:
	    continue
        if struct.unpack('!L',data[0:4])[0] == FLOOD_UDP_CONFIRMED: 
    	    flood_confirmed = 1
	    break
    udpsock.close()

    if flood_confirmed == 0:
        log2file("Error: server doesn't respond flooding request\n")
	return 1
    return 0


Alltests = [tcp_data_opt_test]

def tcp_mbox_test(dhost, dport, usepcap, plabsrc=0, plabdst=0):

    global logfile
    summary = copy.copy(TestEntries)

    date = '%s'%datetime.datetime.today()
    date = date.replace(' ', '')
    date = date.replace(':', '')
    date = date.replace('-', '')
    f = "log" + date[4:14] + date[15:20] + ".txt"
    try:
        logfile = open(f, 'w')
    except IOError:
        print "Error: failed to open logfile\n"
	return summary, -1

    err = 0
    tests = Alltests[:]

    daddr, lhost, laddr = tcpsrlib.gethostpair(dhost)
    if daddr == 0 or laddr == 0: 
        log2file("Warn: failed to lookup destination or local address\n")
        logfile.close()
        return summary, 1

    laddr_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', laddr))
    daddr_str = socket.inet_ntop(socket.AF_INET, struct.pack('!L', daddr))
    log2file('Client: %s %s '%(lhost, laddr_str))
    log2file('Server: %s %s : %s\n'%(dhost, daddr_str, dport))

    if plabsrc:
        th_flooder = threading.Thread(target=flood_udp, args=('8.8.8.8',))
	th_flooder.setDaemon(True)
	th_flooder.start()
        log2file("UDP flooder has been started\n")
        th_peeper = threading.Thread(target=peep_os_syn, args=(daddr_str, dport))
        th_peeper.setDaemon(True)
        th_peeper.start()
        log2file("SYN peeper has been started\n")
	time.sleep(3)
    if plabdst:
	err = plabdst_udp_flood_operation(daddr, FLOOD_UDP_START)
	if err == 1 or err == -1:
	    log2file("Warn: flood request failed, return\n")
	    logfile.close()
	    return summary, 1
	else:
	    log2file("Info: UDP flood start request has success\n")

    for test in tests:
        log2file("*** " + ' %s '%test.__name__ + " ***\n")
	if re.search('coalesce', test.__name__):
	    retval, err = test(dhost, dport, usepcap, plabsrc)
	else:
	    for i in range(0, 2):
	        retval0, err = test(dhost, dport, usepcap, plabsrc)
	        if err == -1: 
		    break
		elif (plabsrc or plabdst) and err == -2:
		    time.sleep(10)
		    retval0, err = test(dhost, dport, usepcap, plabsrc)

		if (plabsrc or plabdst) and err == -2:
		    time.sleep(10)

	        retval1, err = test(dhost, dport, usepcap, plabsrc)
	        if err == -1: 
		    break
		elif (plabsrc or plabdst) and err == -2:
		    time.sleep(10)
		    retval1, err = test(dhost, dport, usepcap, plabsrc)

	        if retval0 == retval1:
	            log2file("Info: match result.\n")
	            break
	        log2file("Info: unmatch result. try again\n")
            if err == -1:
                log2file("Warn: fatal error, return...")
	 	break
            retval = retval0
        summary = merge_to_summary(summary, retval)
        if test.__name__ == "tcp_syn_test" and retval['Syn'] != 0: break
        if test.__name__ == "tcp_data_test" and retval['Data'] != 0: break

    s = 'Result: %s\n'%make_result_string(summary)
    log2file(s)
    if plabsrc:
        global Fld_udp_on
	global Peeped_syns

        log2file("Info: stopping UDP flooder\n")
    	Fld_udp_on.clear()
	th_flooder.join(2)
	if th_flooder.isAlive():
	    log2file("Warn: failed to stop UDP flooder\n")
	    err = -1 
	else:
            log2file("Info: UDP flooder has been stopped\n")
	stop_peep_os_syn(daddr_str)
	th_peeper.join(2)
	if th_flooder.isAlive():
	    log2file("Warn: failed to stop SYN peeper\n")
	    err = -1
	else:
            log2file("Info: SYN peeper has been stopped\n")
	Peeped_syns = []

    if plabdst:
        err = plabdst_udp_flood_operation(daddr, FLOOD_UDP_STOP)
	if err == 1 or err == -1:
	    log2file("Warn: flood stop failed, MUST be manually stopped\n")
	else:
	    log2file("Info: UDP flood stop request has success\n")

    logfile.close()
    return summary, err

def is_new_domain(hostname, domainlist):
    domain = hostname.partition('.')[2]
    for i in domainlist:
	 if i == domain:
	     return 0
    return 1

def tcp_mbox_test_large(nodelist, dport, usepcap, plabsrc=0, plabdst=0):

    skipdomains = []

    nodes = open(nodelist, 'r')
    while 1:
        line = nodes.readline()
        if not line: break
	dhost = line.strip()
	if is_new_domain(dhost, skipdomains) == 0:
	    print 'Info: same domain as %s has already tested, skip\n'%dhost
	    continue
	retval, err = tcp_mbox_test(dhost, dport, usepcap, plabsrc, plabdst)
	if err == -1:
	    return
	if retval['Syn'] == 0 and retval['Data'] == 0:
	    skipdomains.append(dhost.partition('.')[2])
	    print 'Info: domain %s has done, skip upcoming same-domain hosts\n'%dhost.partition('.')[2]

def main():
    if len(sys.argv) != 5 and len(sys.argv) != 7: 
        print "Usage: python mboxcheck.py FUNCNAME ARG1 dport usepcap [plabsrc plabdst]"
        return

    f = getattr(__main__, sys.argv[1])
    dport = int(sys.argv[3])
    usepcap = int(sys.argv[4])
    plabsrc = plabdst = 0
    if len(sys.argv) == 7:
        plabsrc = int(sys.argv[5])
        plabdst = int(sys.argv[6])
    
    f(sys.argv[2], dport, usepcap, plabsrc, plabdst)
    return

if __name__ == "__main__":
    main()
