import CFG_pb2

#helper to add a block
def add_block(func, blockDict, addr, follows):
  blockDict[addr] = func.blocks.add()
  blockDict[addr].base_address = addr
  for i in follows: blockDict[addr].block_follows.append(i)

def add_inst(block, addr, inst_bytes, true_target=None, false_target=None, data_off=None, ext_call=None):
  inst = block.insts.add()
  inst.inst_addr = addr
  inst.inst_bytes = inst_bytes
  inst.inst_len = len(inst_bytes)
  if true_target != None: inst.true_target = true_target
  if false_target != None: inst.false_target = false_target 
  if data_off != None: inst.data_offset = data_off
  if ext_call != None: inst.ext_call_name = ext_call

#set up the module
M = CFG_pb2.Module()

#set up module metadata
M.module_name = u'box'

#add a data section of 4-bytes, 0-initted
Data = M.internal_data.add()
Data.base_address = 0x00408000
Data.data = 'user32.dll\x00\x00MessageBoxA\x00Whatever you say\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x80\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x16\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x05\x00\x00\x00\r\x00\x00\x00\x06\x00\x00\x00\t\x00\x00\x00'
Data.read_only = False

#make some external calls 
LoadLibrary = M.external_funcs.add()
LoadLibrary.symbol_name = "LoadLibraryA"
LoadLibrary.calling_convention = CFG_pb2.ExternalFunction.CallerCleanup
LoadLibrary.has_return = True
LoadLibrary.no_return = False
LoadLibrary.argument_count = 2

GetProcAddress = M.external_funcs.add()
GetProcAddress.symbol_name = "GetProcAddress"
GetProcAddress.calling_convention = CFG_pb2.ExternalFunction.CallerCleanup
GetProcAddress.has_return = True
GetProcAddress.no_return = False
GetProcAddress.argument_count = 1

#create a function to insert into the module
F = M.internal_funcs.add()
F.entry_address = 0x00401030

#create basic blocks to insert into the module
blockDict = {}
add_block(F, blockDict, 0x00401030, [0x00401037, 0x0040106E])
add_block(F, blockDict, 0x0040106E, [])
add_block(F, blockDict, 0x00401037, [0x0040106A, 0x0040104E])
add_block(F, blockDict, 0x0040104E, [0x0040106A, 0x0040105E])
add_block(F, blockDict, 0x0040105E, [])
add_block(F, blockDict, 0x0040106A, [])

#insert instructions into each block
curBlock = blockDict[0x00401030]
#.text:00401030 83 7C 24 04 02                          cmp     [esp+arg_0], 2
#.text:00401035 75 37                                   jnz     short loc_40106E
add_inst(curBlock, 0x00401030, "\x83\x7c\x24\x04\x02")
add_inst(curBlock, 0x00401035, "\x75\x37", true_target=0x0040106E, false_target=0x00401037)

curBlock = blockDict[0x00401037]
#.text:00401037 8B 44 24 08                             mov     eax, [esp+arg_4]
#.text:0040103B 56                                      push    esi
#.text:0040103C 8B 70 04                                mov     esi, [eax+4]
#.text:0040103F 68 00 80 40 00                          push    offset LibFileName ; "user32.dll"
#.text:00401044 FF 15 04 60 40 00                       call    ds:LoadLibraryA
#.text:0040104A 85 C0                                   test    eax, eax
#.text:0040104C 74 1C                                   jz      short loc_40106A
add_inst(curBlock, 0x00401037, "\x8b\x44\x24\x08")
add_inst(curBlock, 0x0040103B, "\x56")
add_inst(curBlock, 0x0040103C, "\x8B\x70\x04")
add_inst(curBlock, 0x0040103F, "\x68\x00\x80\x40\x00", data_off=0x00408000)
add_inst(curBlock, 0x00401044, "\xFF\x15\x04\x60\x40\x00", ext_call="LoadLibraryA")
add_inst(curBlock, 0x0040104A, "\x85\xC0")
add_inst(curBlock, 0x0040104C, "\x74\x1C", true_target=0x0040106A, false_target=0x0040104E)

curBlock = blockDict[0x0040106E]
#.text:0040106E 33 C0                                   xor     eax, eax
#.text:00401070 C3                                      retn
add_inst(curBlock, 0x0040106E, "\x33\xC0")
add_inst(curBlock, 0x00401070, "\xc3")

curBlock = blockDict[0x0040104E]
#.text:0040104E 68 0C 80 40 00                          push    offset ProcName ; "MessageBoxA"
#.text:00401053 50                                      push    eax             ; hModule
#.text:00401054 FF 15 00 60 40 00                       call    ds:GetProcAddress
#.text:0040105A 85 C0                                   test    eax, eax
#.text:0040105C 74 0C                                   jz      short loc_40106A
add_inst(curBlock, 0x0040104E, "\x68\x0c\x80\x40\x00", data_off=0x0040800C)
add_inst(curBlock, 0x00401053, "\x50")
add_inst(curBlock, 0x00401054, "\xff\x14\x00\x60\x40\x00", ext_call="GetProcAddress")
add_inst(curBlock, 0x0040105A, "\x85\xc0")
add_inst(curBlock, 0x0040105C, "\x74\x0C", true_target=0x0040106A, false_target=0x0040105E)

curBlock = blockDict[0x0040105E]
#.text:0040105E 6A 00                   push    0
#.text:00401060 68 18 80 40 00          push    offset aWhateverYouSay ; "Whatever you say"
#.text:00401065 56                      push    esi
#.text:00401066 6A 00                   push    0
#.text:00401068 FF D0                   call    eax
#.text:0040106A 33 C0                                   xor     eax, eax
#.text:0040106C 5E                                      pop     esi
#.text:0040106D C3                                      retn
add_inst(curBlock, 0x0040105E, "\x6a\x00")
add_inst(curBlock, 0x00401060, "\x68\x18\x80\x40\x00", data_off=0x00408018)
add_inst(curBlock, 0x00401065, "\x56")
add_inst(curBlock, 0x00401066, "\x6a\x00")
add_inst(curBlock, 0x00401068, "\xff\xd0")
add_inst(curBlock, 0x0040106A, "\x33\xc0")
add_inst(curBlock, 0x0040106C, "\x5e")
add_inst(curBlock, 0x004010C3, "\xc3")


curBlock = blockDict[0x0040106A]
#.text:0040106A 33 C0                                   xor     eax, eax
#.text:0040106C 5E                                      pop     esi
#.text:0040106D C3                                      retn
add_inst(curBlock, 0x0040106A, "\x33\xc0")
add_inst(curBlock, 0x0040106C, "\x5E")
add_inst(curBlock, 0x0040106D, "\xC3")

#write out the message
out = M.SerializeToString()
f = file('cfg_3.cfg', 'wb')
f.write(out)
f.close()
del f
