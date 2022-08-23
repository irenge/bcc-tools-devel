    DRAFT TALK PLAN - 

    • XDP programs allow to write code that ‘s executed very early when a network packet arrives at the kernel.
    • Defined  with type BPF_PROG_TYPE_XDP
    • XDP exposes a limited set of information from the packet given that the kernel has not much time to process the information itself. 
    • Advantage : the packet is executed early on , XDP offers much higher control over how to handle the packet 
    • XDP programs define several actions that one can control and that allow to decide what to do with a packet
    • you can return 
        ◦ XDP_PASS from your XDP program  which means that the packet should pass to the next subsystem in the kernel 
        ◦ XDP_DROP: the kernel should ignore the packet completely and do nothing with it
        ◦ XDP_TX: the packet should be forwarded back to the network interface card that received the packet in the first place.
    • This opens door to interesting program in network layers
    • Use cases for XDP
            ▪ protect network against denial of service(DDoS) attacks
            ▪ monitoring 
            ▪ load balancing
            ▪ firewalling
    • Demo
