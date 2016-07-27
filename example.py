import tcpsrlib
import tcplib
import random
import struct

dhost = "vinson2.sfc.wide.ad.jp"
daddr, lhost, saddr = tcpsrlib.gethostpair(dhost)
sport = random.randrange(50000, 60000)
synopt = (('MSS', 512), ('SACKOK', ''), ('TIMESTAMP', 12345, 0), ('WSCALE', 3), ('NOP', ''))

dmacaddr = smacaddr = 0
ifname, smacaddr, err = tcpsrlib.get_ifname_and_smacaddr(saddr)
for i in range(0, 2):
    dmacaddr = tcpsrlib.get_dmacaddr(ifname, daddr)
    if dmacaddr == 0:
	continue
    break

syn = tcpsrlib.make_segment(daddr, saddr, 80, sport, 8192, 20000, 0, \
           tcplib.TH_SYN, options=synopt, payload=None, ipcksum=1)
print tcpsrlib.summarize_pkt(syn)

rcvpkts, err = tcpsrlib.sendrecv_segments(daddr, (syn,), timeout=1.0, \
	   sflags=tcplib.TH_SYN, usepcap=1, ifname=ifname, \
	   smacaddr=smacaddr, dmacaddr=dmacaddr)
for ans1 in rcvpkts:
    print tcpsrlib.summarize_ans1(ans1)
synack = tcpsrlib.get_synack(rcvpkts)

ack = tcpsrlib.make_segment(daddr, saddr, 80, sport, 8192, \
		synack[1].ackno, synack[1].seqno+1, tcplib.TH_ACK, ipcksum=1)

print tcpsrlib.summarize_pkt(ack)
err = tcpsrlib.send_segments(daddr, (ack,), usepcap=1, \
		ifname=ifname, smacaddr=smacaddr, dmacaddr=dmacaddr)

payload = ""
for i in range(0, 512):
    payload += struct.pack('!B', 0x12)
datapkt = tcpsrlib.make_segment(daddr, saddr, 80, sport, 8192, \
	synack[1].ackno, synack[1].seqno+1, tcplib.TH_ACK, \
	payload=payload, ipcksum=1)
rcvpkts, err = tcpsrlib.sendrecv_segments(daddr, (datapkt,), timeout=1.0, \
	   usepcap=1, ifname=ifname, smacaddr=smacaddr, dmacaddr=dmacaddr)
for ans1 in rcvpkts:
    print tcpsrlib.summarize_ans1(ans1)


