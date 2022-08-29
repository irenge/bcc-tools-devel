from __future__ import print_function
from bcc import BPF
import time
import sys
import math 
#import warnings

#warnings.filterwarnings("ignore")

#warnings.filterwarnings('ignore', '.*comparison of distinct pointer types. *', ) 

if sys.argv[1] == "-dev":
    device = sys.argv[2]
else:
    printf(" Enter -dev NICname")



b = BPF(src_file="stats_packets.c")
fn = b.load_func("packets_count", BPF.XDP)
b.attach_xdp(device, fn, 0)

packetcntd = b.get_table("packetcntd")
packetcntp = b.get_table("packetcntp")
packetcntx = b.get_table("packetcntx")
packetcnttcp = b.get_table("packetcnttcp")
packetcntudp = b.get_table("packetcntudp")
packetcntpng = b.get_table("packetcntpng")


prevp = [0] * 512
prevd = [0] * 512
prevm = [0] * 512
prevt = [0] * 512
prevu = [0] * 512
prevg = [0] * 512


percentage = [0] * 512
deltad = 0
deltap = 0
deltax = 0
deltat = 0
deltag = 0
deltau = 0

print("Packet counts, hit CTRL+C to stop")
while 1:
    try:
        for k,l,m,t,g,u in zip(packetcntd.keys(),packetcntp.keys(), packetcntx.keys(), packetcnttcp.keys(), packetcntpng.keys(),packetcntudp.keys()):
          
            vald = packetcntd.sum(k).value
            valp = packetcntp.sum(l).value
            valx = packetcntx.sum(m).value
            valt = packetcnttcp.sum(t).value
            valu = packetcntudp.sum(u).value
            valg = packetcntpng.sum(g).value

            
            i = k.value
            j = l.value
            n = m.value
            o = t.value
            p = g.value
            q = u.value

            
            if vald:
                deltad = vald - prevd[i]
                prevd[i] = vald
                print("XDP_DROP {} pkt/s".format(deltad))

            if valp:
                deltap = valp - prevp[j]
                prevp[j] = valp
                print("XDP_PASS {} pkt/s".format(deltap))
                if deltad ^ deltap:
                    percentage[j] = math.floor((deltad/(deltad + deltap))*100)
                print("Percentage dropped {} % ".format(percentage[j]))
            if valx:
                deltax = valx - prevm[n]
                prevm[n] = valx
                print("XDP_TX {} pkt/s".format(deltax))
                total = deltad + deltap + deltax
                print("Total {} pkts/s".format(total))

            if valt:
                deltat = valt - prevt[o]
                prevt[o] = valt
                print("TCP  {} pkt/s".format(deltat))
            if valu:
                deltau = valu - prevu[q]
                prevu[q] = valu
                print("UDP  {} pkt/s".format(deltau))

            if valg:
                deltag = valg - prevg[p]
                prevg[p] = valg
                print("Ping  {} pkt/s".format(deltag))


     
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
