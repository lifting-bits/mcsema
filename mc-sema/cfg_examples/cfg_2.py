import CFG_pb2

#helper to add a block
def add_block(func, blockDict, addr, follows):
  blockDict[addr] = func.blocks.add()
  blockDict[addr].base_address = addr
  for i in follows: blockDict[addr].block_follows.append(i)

def add_inst(block, addr, inst_bytes, true_target=None, false_target=None, data_off=None):
  inst = block.insts.add()
  inst.inst_addr = addr
  inst.inst_bytes = inst_bytes
  inst.inst_len = len(inst_bytes)
  if true_target != None: inst.true_target = true_target
  if false_target != None: inst.false_target = false_target 
  if data_off != None: inst.data_offset = data_off

#set up the module
M = CFG_pb2.Module()

#set up module metadata
M.module_name = u'bigger'

#add a data section of 4-bytes, 0-initted
Data = M.internal_data.add()
Data.base_address = 0x08000028
Data.data = "\x00\x00\x00\x00"
Data.read_only = False

#create a function to insert into the module
F = M.internal_funcs.add()
F.entry_address = 0x08000000

#create basic blocks to insert into the module
blockDict = {}
add_block(F, blockDict, 0x08000000, [0x0800000D, 0x0800001C])
add_block(F, blockDict, 0x0800000D, [0x08000021])
add_block(F, blockDict, 0x08000021, [])
add_block(F, blockDict, 0x0800001C, [])

#insert instructions into each block
#.text:08000000 55                      push    ebp
#.text:08000001 89 E5                   mov     ebp, esp
#.text:08000003 A1 28 00 00 08          mov     eax, ds:g_updt
#.text:08000008 39 45 08                cmp     [ebp+arg_0], eax
#.text:0800000B 7E 0F                   jle     short loc_800001C
curBlock = blockDict[0x08000000]
add_inst(curBlock, 0x08000000, "\x55")
add_inst(curBlock, 0x08000001, "\x89\xe5")
add_inst(curBlock, 0x08000003, "\xA1\x28\x00\x00\x08", data_off=0x08000028)
add_inst(curBlock, 0x08000008, "\x39\x45\x08")
add_inst(curBlock, 0x0800000B, "\x7E\x04", true_target=0x0800001C, false_target=0x0800000D)

#.text:0800000D 8B 45 08                mov     eax, [ebp+arg_0]
#.text:08000010 A3 28 00 00 08          mov     ds:g_updt, eax
#.text:08000015 B8 01 00 00 00          mov     eax, 1
#.text:0800001A EB 05                   jmp     short loc_800021
curBlock = blockDict[0x0800000D]
add_inst(curBlock, 0x0800000D, "\x8b\x45\x08")
add_inst(curBlock, 0x08000010, "\xA3\x28\x00\x00\x08", data_off=0x08000028)
add_inst(curBlock, 0x08000015, "\xb8\x01\x00\x00\x00")
add_inst(curBlock, 0x0800001A, "\xeb\x05", true_target=0x08000021)

#.text:08000021 5D                      pop     ebp
#.text:08000022 C3                      retn
curBlock = blockDict[0x08000021]
add_inst(curBlock, 0x08000021, "\x5d")
add_inst(curBlock, 0x08000022, "\xc3")

#.text:0800001C B8 00 00 00 00          mov     eax, 0
#.text:08000021 5D                      pop     ebp
#.text:08000022 C3                      retn
curBlock = blockDict[0x0800001C]
add_inst(curBlock, 0x0800001c, "\xb8\x00\x00\x00\x00")
add_inst(curBlock, 0x08000021, "\x5d")
add_inst(curBlock, 0x08000022, "\xc3")


#write out the message
out = M.SerializeToString()
f = file('cfg_2.cfg', 'wb')
f.write(out)
f.close()
del f
