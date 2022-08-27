from __future__ import print_function
from bcc import BPF
import time
import sys
import math 

if sys.argv[1] == "-dev":
    device = sys.argv[2]
else:
    printf(" Enter -dev NICname")

b = BPF(src_file="stats_packets.c")
fn = b.load_func("packets_count", BPF.XDP)
b.attach_xdp(device, fn, 0)
packetcntd = b.get_table("packetcntd")
packetcntp = b.get_table("packetcntp")

prevp = [0] * 512
prevd = [0] * 512

percentage = [0] * 512
deltad = 0
deltap = 0

print("Packet counts, hit CTRL+C to stop")
while 1:
    try:
        for k,l in zip(packetcntd.keys(),packetcntp.keys()):
          
            vald = packetcntd.sum(k).value
            valp = packetcntp.sum(l).value
            
            i = k.value
            j = l.value
            
            if vald:
                deltad = vald - prevd[i]
                prevd[i] = vald
                print("XDP_DROP {} pkt/s".format(deltad))

            if valp:
                deltap = valp - prevp[j]
                prevp[j] = valp
                print("XDP_PASS {} pkt/s".format(deltap))
                if deltad ^ deltap:
                    percentage[i] = math.floor((deltad/(deltad + deltap))*100)
                print("Percentage dropped {} % ".format(percentage[i]))
     
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
