## Packet Count Monitoring Script Documentation
### Overview
This script leverages the BPF (Berkeley Packet Filter) technology to monitor packet counts on a specified network interface card (NIC). The script attaches an eBPF program, defined in stats_packets.c, to the NIC and periodically retrieves and prints packet count statistics for various packet types.

### Prerequisites 
* Python environment
* bcc library installed: Follow this link [bcc pages](https://github.com/iovisor/bcc/blob/master/INSTALL.md) 
* Root privileges to run BPF programs
* A compiled stats_packets.c file with the eBPF program
### Usage
Run the script with the following command:
##
		sudo python script.py -dev <NICname>

NICname can be eth0, wlp57s0 ...
