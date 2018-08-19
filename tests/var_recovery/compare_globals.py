import sys
import logging
import mcsema_disass.ida.CFG_pb2 as CFG_pb2

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())
# do not log for now
logging.disable(logging.INFO)

def read_globals(M):
  global_variables = dict()
  for g in M.global_vars:
    global_variables[g.ea] = (g.name, g.size,)
    
  for key, value in sorted(global_variables.iteritems()):
    LOGGER.info("{:x} {}".format(key, value))

  return global_variables


def hex_string(s):
  return " ".join(["{:x}".format(i) for i in s])

if __name__ == "__main__":
  if len(sys.argv) != 3:
    print "Usage: %s <protobuf_nodebug> <protobuf_dwarf>"
  else:
    sys.stdout.write("Comparing NODEBUG [{}] vs. DWARF [{}]\n".format(
      sys.argv[1],
      sys.argv[2]))

    pleft_globals, pright_globals = None, None
    M = CFG_pb2.Module()
    with open(sys.argv[1], 'rb') as pleft:
      M.ParseFromString(pleft.read())
      pleft_globals = read_globals(M)

    M = CFG_pb2.Module()
    with open(sys.argv[2], 'rb') as pright:
      M.ParseFromString(pright.read())
      pright_globals = read_globals(M)


    left_keys = set(pleft_globals.iterkeys())
    right_keys = set(pright_globals.iterkeys())


    unique_left = left_keys - right_keys
    unique_right = right_keys - left_keys

    both = left_keys.intersection(right_keys)

    sys.stdout.write("Globals in NODEBUG but *not* in DWARF: {}\n".format(len(unique_left)))
    if unique_left:
      sys.stdout.write("\t{}\n".format(hex_string(unique_left)))

    sys.stdout.write("Globals in DWARF but *not* NODEBUG: {}\n".format(len(unique_right)))
    if unique_right:
      sys.stdout.write("\t{}\n".format(hex_string(unique_right)))


    sys.stdout.write("Common globals: {}\n".format(len(both)))

    disagreements = 0
    for k in both:
      li = pleft_globals[k]
      ri = pright_globals[k]

      if li[1] != ri[1]:
        disagreements += 1
        sys.stdout.write("\tVariables at {:x} disagree on size. {:x} [NODEBUG] vs. {:x} [DWARF]\n".format(k, li[1], ri[1]))

    sys.stdout.write("Total size disagreements: {}\n".format(disagreements))



