from __future__ import print_function
from bcc import BPF
from time import sleep

program = """
        BPF_HASH(callers, u64, unsigned long);

        TRACEPOINT_PROBE(kmem, kmalloc) {
            u64 ip = args->call_site;
            unsigned long *count;
            unsigned long c = 1;

            count = callers.lookup((u64 *)&ip);
            if (count != 0)
                c += *count;

            callers.update(&ip, &c);

            return 0;
        }
    """
b = BPF(text=program)
while True:
        try:
            sleep(1)
            for k,v in (b["callers"].items()):
            # sorted(b["callers"].items()):
                print ("%s %u" % (b.ksym(k.value), v.value))
            print
        except KeyboardInterrupt:
            exit()
