#!/usr/bin/python3

from bcc import BPF
import time
import sys

if sys.argv[1] == "-dev":
    device = sys.argv[2]
else:
    printf(" Enter -dev NICname")

b = BPF(src_file="program.c")
fn = b.load_func("packets_count", BPF.XDP)
b.attach_xdp(device, fn, 0)
packetcnt = b.get_table("packetcntd")
prev = [0] * 256
print("Printing dropped packet counts, hit CTRL+C to stop")
while 1:
    try:
        for k in packetcnt.keys():
            val = packetcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                print(" {} pkt/s".format(delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
