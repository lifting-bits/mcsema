import sys
import logging
import mcsema_disass.ida.CFG_pb2 as CFG_pb2

logging.basicConfig(filename="variable.log", level=logging.INFO)
LOGGER = logging.getLogger(__name__)

def print_vars(M):
  global_variables = dict()
  print "globals:"
  for g in M.global_vars:
    global_variables[g.ea] = g.name
    
  for key in sorted(global_variables.iterkeys()):
    LOGGER.info("{:x} {}".format(key, global_variables[key]))
  print "Number of global variables {}".format(len(M.global_vars))
  for seg in M.segments:
    print seg
  return
  
  
if __name__ == "__main__":
  if len(sys.argv) != 2:
    print "Usage: %s <cfg_filename>"
  else:
    M = CFG_pb2.Module()
    with open(sys.argv[1], 'rb') as inf:
      M.ParseFromString(inf.read())
      print_vars(M)
