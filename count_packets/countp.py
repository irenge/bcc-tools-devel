from __future__ import print_function
from bcc import BPF
import time
import sys
import math 

if sys.argv[1] == "-dev":
    device = sys.argv[2]
else:
    printf(" Enter -dev NICname")

b = BPF(src_file="program.c")
fn = b.load_func("packets_count", BPF.XDP)
b.attach_xdp(device, fn, 0)
packetcntd = b.get_table("packetcntd")
packetcntp = b.get_table("packetcntp")
packetcntx = b.get_table("packetcntx")

prevp = [0] * 512
prevd = [0] * 512
prevm = [0] * 512


percentage = [0] * 512
deltad = 0
deltap = 0
deltax = 0

print("Packets count: UDP packets - drooped  TCP - accepted -  Other type of  Packet - bounced to NIC, hit CTRL+C to stop")
while 1:
    try:
        for k,l,m in zip(packetcntd.keys(), packetcntp.keys(), packetcntx.keys()):
          
            vald = packetcntd.sum(k).value
            valp = packetcntp.sum(l).value
            valx = packetcntx.sum(m).value

            
            i = k.value
            j = l.value
            n = m.value
            
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

     
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)