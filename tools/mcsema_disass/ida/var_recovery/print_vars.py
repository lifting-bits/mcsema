# quick script to print local variables recovered into cfg for debugging purposes.

import sys

# hackety
sys.path.append('../../bin_descend')
import CFG_pb2

def print_vars(M):
    for g in M.global_vars:
      print g
    for f in M.internal_funcs:
        if len(f.stackvars):
            print "ea: 0x%016x" % (f.entry_address)
            print "vars:"
            #print "refs:"
            for v in f.stackvars:
                #for r in v.var.ref_eas:
                #    print ("0x%08x" % r.inst_addr)
                print v
    return

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: %s <cfg_filename>"
    else:
        M = CFG_pb2.Module()
        M.ParseFromString(open(sys.argv[1],'rb').read())
        print_vars(M)
