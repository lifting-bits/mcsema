#! /usr/bin/env python
#to use this ,you have to put the CFG_pb2.py file,which from the  mcsema/tools/mcsema_disass/ida7/ ,into the same dir with this script
# type  python show_cfg.py "xxx.cfg" "xxx.txt" 
# the first arg is location of the cfg file you want to see,like "./maze.cfg"
# the second arg is the location of the generated cfg details if the cfg file,like "./cfgdetails.txt"
from sys import argv
import CFG_pb2

def ListModule(module,g):
  print("module name:",module.name,file=g)
  print('\n',file=g)

  #Function
  print("The Functions in the Module:",file=g)
  print('\n',file=g)
  for function in module.funcs:
    print("###########################################################",file=g)
    print("function name :", function.name,file=g)
    print("function ea :", function.ea,file=g)
    print("function is_entrypoint :", function.is_entrypoint,file=g)
    print("The blocks in the function:",file=g)
    print('\n',file=g)

    #The blocks in the Function
    for block in function.blocks:
      print("---------------------------------------------------------",file=g)
      print("block ea",block.ea,file=g)
      print("block is_referenced_by_data",block.is_referenced_by_data,file=g)
      print("The instructions in the block:",file=g)
      print('\n',file=g)

      #The Instruction in the Block
      for instruction in block.instructions:
        print("instruction ea",instruction.ea,file=g)
        print("instruction lp_ea",instruction.lp_ea,file=g)
        print("The  codereferences of the instruction:",file=g)
        print('\n',file=g)

        #The CodeReference of the Instruction
        for codereference in instruction.xrefs:
          if codereference.operand_type == CFG_pb2.CodeReference.OperandType.ImmediateOperand:
            print("codereference operand_type ImmediateOperand",file=g)
          elif codereference.operand_type == CFG_pb2.CodeReference.OperandType.MemoryOperand:
            print("codereference operand_type MemoryOperand",file=g)
          elif codereference.operand_type == CFG_pb2.CodeReference.OperandType.MemoryDisplacementOperand:
            print("codereference operand_type MemoryDisplacementOperand",file=g)
          elif codereference.operand_type == CFG_pb2.CodeReference.OperandType.ControlFlowOperand:
            print("codereference operand_type ControlFlowOperand",file=g)
          elif codereference.operand_type == CFG_pb2.CodeReference.OperandType.OffsetTable:
            print("codereference operand_type OffsetTable",file=g)  

          print("codereference ea",codereference.ea,file=g)
          print("codereference mask",codereference.mask,file=g)
        print('\n',file=g)

      #The successor in the block 
      for successor in block.successor_eas:
        print("successor ea",successor,file=g)
      print("---------------------------------------------------------",file=g)
      print('\n',file=g)

    #The ExceptionFrame of the Function
    print("The exceptionframes in the Function:",file=g)
    print('\n',file=g)
    for exceptionframe in function.eh_frame:
      print("exceptionframe func_ea",exceptionframe.func_ea,file=g)
      print("exceptionframe start_ea",exceptionframe.start_ea,file=g)
      print("exceptionframe end_ea",exceptionframe.end_ea,file=g)
      print("exceptionframe lp_eaa",exceptionframe.lp_ea,file=g)
      if exceptionframe.action == CFG_pb2.ExceptionFrame.Action.Cleanup:
        print("exceptionframe action Cleanup",file=g)
      elif exceptionframe.action == CFG_pb2.ExceptionFrame.Action.Catch:
        print("exceptionframe action Catch",file=g)

      #The ExternalVariable of the ExceptionFrame
      print("The externalvariables in the ExceptionFrame:",file=g)
      print('\n',file=g)
      for externalvariable in function.ttype:
        print("externalvariable name",externalvariable.name,file=g)
        print("externalvariable ea",externalvariable.ea,file=g)
        print("externalvariable size",externalvariable.size,file=g)
        print("externalvariable is_weak",externalvariable.is_weak,file=g)
        print("externalvariable is_thread_local",externalvariable.is_thread_local,file=g)
        print('\n',file=g)
      print('\n',file=g)
    print("FunctionDecl",function.decl,file=g)
    print("###########################################################",file=g)  
    print('\n',file=g)
  print("The Segments in the module:",file=g)
  print('\n',file=g)


  #Segments in the Module
  for segment in module.segments:
    print("###########################################################",file=g) 
    print("segment ea :", segment.ea,file=g)
    print("segment data :", segment.data.hex(),file=g)
    print("segment read_only :", segment.read_only,file=g)
    print("segment is_external :", segment.is_external,file=g)
    print("segment name :", segment.name,file=g)
    print("segment variable_name :", segment.variable_name,file=g)
    print("segment is_exported :", segment.is_exported,file=g)
    print("segment is_thread_local :", segment.is_thread_local,file=g)

    #Datareferences of the Segment
    print("The datareferences in the Segment:",file=g)
    print('\n',file=g)
    for datareference in segment.xrefs:
      print("datareference ea",datareference.ea,file=g)
      print("datareference width",datareference.width,file=g)
      print("datareference target_ea",datareference.target_ea,file=g)
      if datareference.target_fixup_kind == CFG_pb2.DataReference.TargetFixupKind.Absolute:
       print("datareference target_fixup_kind  Absolute",file=g)
      elif datareference.target_fixup_kind == CFG_pb2.DataReference.TargetFixupKind.OffsetFromThreadBase:
       print("datareference target_fixup_kind  OffsetFromThreadBase",file=g)
      print('\n',file=g)

     #Variables in the Segment 
    print("The variables in the Segment:",file=g)
    print('\n',file=g)
    for variable in segment.vars:
      print("variable ea",variable.ea,file=g)
      print("variable name",variable.name,file=g)
      print('\n',file=g)
    print("###########################################################",file=g) 
    print('\n',file=g)


    #The ExternalFunctions in the Module
  print("The ExternalFunctions in the Module:",file=g)
  print('\n',file=g)
  for externalfunction in module.external_funcs:
    print("###########################################################",file=g) 
    print("externalfunction ea :", externalfunction.ea,file=g)
    print("externalfunction name :", externalfunction.name,file=g)
    print("externalfunction has_return :", externalfunction.has_return,file=g)
    print("externalfunction no_return :", externalfunction.no_return,file=g)
    print("externalfunction argument_count :", externalfunction.argument_count,file=g)
    print("externalfunction is_weak :", externalfunction.is_weak,file=g)
    print("externalfunction FunctionDecl :", externalfunction.decl,file=g)
    if externalfunction.cc == CFG_pb2.ExternalFunction.CallingConvention.CallerCleanup:
      print("externalfunction CallingConvention  CallerCleanup",file=g)
    elif externalfunction.cc == CFG_pb2.ExternalFunction.CallingConvention.CalleeCleanup:
      print("externalfunction CallingConvention  CalleeCleanup",file=g)
    elif externalfunction.cc == CFG_pb2.ExternalFunction.CallingConvention.FastCall:
      print("externalfunction CallingConvention  FastCall",file=g)
    print("###########################################################",file=g) 
    print('\n',file=g)




     #The ExternalVariable  in the Module
  print("The ExternalVariable  in the Module:",file=g)
  print('\n',file=g)
  for externalvariable in module.external_vars:
    print("###########################################################",file=g) 
    print("externalvariable name :", externalvariable.name,file=g)
    print("externalvariable ea :", externalvariable.ea,file=g)
    print("externalvariable size :", externalvariable.size,file=g)
    print("externalvariable is_weak :", externalvariable.is_weak,file=g)
    print("externalvariable is_thread_local :", externalvariable.is_thread_local,file=g)
    print("###########################################################",file=g) 
    print('\n',file=g)



     #The GlobalVariable   in the Module 
  print("The GlobalVariable   in the Module:",file=g)
  print('\n',file=g)
  for globalvariable  in module.global_vars:
    print("###########################################################",file=g) 
    print("globalvariable ea :", externalvariable.ea,file=g)
    print("globalvariable name :", externalvariable.name,file=g)
    print("globalvariable size :", externalvariable.size,file=g)
    print("###########################################################",file=g) 
    print('\n',file=g)



     #The PreservedRegister   in the Module
  print("The PreservedRegister   in the Module:",file=g)
  print('\n',file=g)
  for preservedregister  in module.preserved_regs:
    print("###########################################################",file=g) 
    print("preservedregister registers :", preservedregister.registers,file=g)
    #The PreservationRange in the PreservedRegister
    print("The PreservationRange in the PreservedRegister:",file=g)
    print('\n',file=g)
    for preservationrange in preservedregister.ranges:
      print("preservationrange begin_ea",preservationrange.begin_ea,file=g)
      print("preservationrange end_ea",preservationrange.end_ea,file=g)
    print("###########################################################",file=g) 
    print('\n',file=g)



    #The DeadRegisters   in the Module 
  print("The DeadRegisters   in the Module:",file=g)
  print('\n',file=g)
  for deadregister  in module.dead_regs:
    print("###########################################################",file=g) 
    print("deadregister registers :", deadregister.registers,file=g)
    #The PreservationRange in the DeadRegister
    print("The PreservationRange in the DeadRegister:",file=g)
    print('\n',file=g)
    for dpreservationrange in deadregister.ranges:
      print("dpreservationrange begin_ea",dpreservationrange.begin_ea,file=g)
      print("dpreservationrange end_ea",dpreservationrange.end_ea,file=g)
    print("###########################################################",file=g) 
    print('\n',file=g)
  
  





 


def read_test():
    module=CFG_pb2.Module()
    first = argv[1]
    module_file = first
    
    
    f = open(module_file, "rb")
    module.ParseFromString(f.read())
    f.close()
    second = argv[2]
    g = open(second,'w')
    ListModule(module,g)
    g.close()


if __name__ == "__main__":
    read_test()




