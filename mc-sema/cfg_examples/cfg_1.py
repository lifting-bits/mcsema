import CFG_pb2

#helper to add a block
def add_block(func, blockDict, addr, follows):
  blockDict[addr] = func.blocks.add()
  blockDict[addr].base_address = addr
  for i in follows: blockDict[addr].block_follows.append(i)

def add_inst(block, addr, inst_bytes, true_target=None, false_target=None):
  inst = block.insts.add()
  inst.inst_addr = addr
  inst.inst_bytes = inst_bytes
  inst.inst_len = len(inst_bytes)
  if true_target != None: inst.true_target = true_target
  if false_target != None: inst.false_target = false_target 

#set up the module
M = CFG_pb2.Module()

#set up module metadata
M.module_name = u'insertion_sort'

#create a function to insert into the module
F = M.internal_funcs.add()
F.entry_address = 0x0804843C

#create basic blocks to insert into the module
blockDict = {}
add_block(F, blockDict, 0x0804843C, [0x08048453, 0x0804848D])
add_block(F, blockDict, 0x08048453, [0x0804845C])
add_block(F, blockDict, 0x08048469, [0x0804846B, 0x0804847B])
add_block(F, blockDict, 0x0804845C, [0x08048469, 0x0804847D])
add_block(F, blockDict, 0x0804846B, [0x0804846B, 0x0804847B])
add_block(F, blockDict, 0x0804847B, [0x0804847F])
add_block(F, blockDict, 0x0804847F, [0x0804848D, 0x0804845A])
add_block(F, blockDict, 0x0804847D, [0x0804845A, 0x0804848D])
add_block(F, blockDict, 0x0804845A, [0x08048469, 0x0804847D])
add_block(F, blockDict, 0x0804848D, [])

#insert instructions into each block

#.text:0804843C 55                      push    ebp
#.text:0804843D 57                      push    edi
#.text:0804843E 56                      push    esi
#.text:0804843F 53                      push    ebx
#.text:08048440 8B 4C 24 14             mov     ecx, [esp+10h+arg_0]
#.text:08048444 8B 6C 24 18             mov     ebp, [esp+10h+arg_4]
#.text:08048448 C7 01 01 00 00 80       mov     dword ptr [ecx], 80000001h
#.text:0804844E 83 FD 01                cmp     ebp, 1
#.text:08048451 7E 3A                   jle     short loc_804848D
curBlock = blockDict[0x0804843C]
add_inst(curBlock, 0x0804843C, "\x55")
add_inst(curBlock, 0x0804843D, "\x57")
add_inst(curBlock, 0x8040843E, "\x56")
add_inst(curBlock, 0x8040843F, "\x53")
add_inst(curBlock, 0x80408440, "\x86\x4c\x24\x14")
add_inst(curBlock, 0x80408444, "\x86\x6c\x24\x18")
add_inst(curBlock, 0x80408448, "\xc7\x01\x01\x00\x00\x80")
add_inst(curBlock, 0x8040844E, "\x83\xFd\x01")
add_inst(curBlock, 0x80408451, "\x7E\x3A", true_target=0x0804848D, false_target=0x08048453)

#.text:08048453 BF 01 00 00 00          mov     edi, 1
#.text:08048458 EB 02                   jmp     short loc_804845C
curBlock = blockDict[0x08048453]
add_inst(curBlock, 0x08048453, "\xBF\x01\x00\x00\x00")
add_inst(curBlock, 0x08048458, "\xeb\x02", true_target=0x0804845C)

#.text:0804845C 8B 74 B9 04             mov     esi, [ecx+edi*4+4]
#.text:08048460 89 F8                   mov     eax, edi
#.text:08048462 8B 14 B9                mov     edx, [ecx+edi*4]
#.text:08048465 39 D6                   cmp     esi, edx
#.text:08048467 7D 14                   jge     short loc_8
curBlock = blockDict[0x0804845C] 
add_inst(curBlock, 0x0804845C  , "\x8b\x74\xb9\x04")
add_inst(curBlock, 0x08048460  , "\x89\xf8")
add_inst(curBlock, 0x08048462  , "\x8b\x14\xb9")
add_inst(curBlock, 0x08048465  , "\x39\xd6")
add_inst(curBlock, 0x08048467  , "\x7d\x14", true_target=0x0804847d, false_target=0x08048469)

#.text:08048469 89 FB                   mov     ebx, edi
#.text:0804846B
#.text:0804846B                         loc_804846B:
#.text:0804846B 89 54 99 04             mov     [ecx+ebx*4+4], edx
#.text:0804846F 83 E8 01                sub     eax, 1
#.text:08048472 89 C3                   mov     ebx, eax
#.text:08048474 8B 14 81                mov     edx, [ecx+eax*4]
#.text:08048477 39 D6                   cmp     esi, edx
#.text:08048479 7C F0                   jl      short loc_8
curBlock = blockDict[0x08048469]
add_inst(curBlock, 0x08048469, "\x89\xfb")
add_inst(curBlock, 0x0804856b, "\x89\x54\x99\x04")
add_inst(curBlock, 0x0804856f, "\x83\xe8\x01")
add_inst(curBlock, 0x08048572, "\x89\xc3")
add_inst(curBlock, 0x08048574, "\x8b\x14\x81")
add_inst(curBlock, 0x08048577, "\x39\xd6")
add_inst(curBlock, 0x08048579, "\x7c\xf0", true_target=0x0804846b, false_target=0x0804847b)

#.text:0804846B
#.text:0804846B                         loc_804846B:
#.text:0804846B 89 54 99 04             mov     [ecx+ebx*4+4], edx
#.text:0804846F 83 E8 01                sub     eax, 1
#.text:08048472 89 C3                   mov     ebx, eax
#.text:08048474 8B 14 81                mov     edx, [ecx+eax*4]
#.text:08048477 39 D6                   cmp     esi, edx
#.text:08048479 7C F0                   jl      short loc_8
curBlock = blockDict[0x0804846b]
add_inst(curBlock, 0x0804856b, "\x89\x54\x99\x04")
add_inst(curBlock, 0x0804856f, "\x83\xe8\x01")
add_inst(curBlock, 0x08048572, "\x89\xc3")
add_inst(curBlock, 0x08048574, "\x8b\x14\x81")
add_inst(curBlock, 0x08048577, "\x39\xd6")
add_inst(curBlock, 0x08048579, "\x7c\xf0", true_target=0x0804846b, false_target=0x0804847b)

#.text:0804847B EB 02                   jmp     short loc_804847F
curBlock = blockDict[0x0804847B]
add_inst(curBlock, 0x0804847B, "\xeb\x02", true_target=0x0804847F)

#.text:0804847D 89 FB                   mov     ebx, edi
#.text:0804847F                         loc_804847F:
#.text:0804847F 89 74 99 04             mov     [ecx+ebx*4+4], esi
#.text:08048483 8D 47 01                lea     eax, [edi+1]
#.text:08048486 83 C7 02                add     edi, 2
#.text:08048489 39 EF                   cmp     edi, ebp
#.text:0804848B 7E CD                   jle     short loc_804845A
curBlock = blockDict[0x0804847D]
add_inst(curBlock, 0x0804847D, "\x89\xFB")
add_inst(curBlock, 0x0804847F, "\x89\x74\x99\x04")
add_inst(curBlock, 0x08048483, "\x8d\x47\x01")
add_inst(curBlock, 0x08048486, "\x83\xc7\x02")
add_inst(curBlock, 0x08048489, "\x39\xEF")
add_inst(curBlock, 0x0804848b, "\x7e\xcd", true_target=0x0804845a, false_target=0x0804848d)

#.text:0804847F                         loc_804847F:
#.text:0804847F 89 74 99 04             mov     [ecx+ebx*4+4], esi
#.text:08048483 8D 47 01                lea     eax, [edi+1]
#.text:08048486 83 C7 02                add     edi, 2
#.text:08048489 39 EF                   cmp     edi, ebp
#.text:0804848B 7E CD                   jle     short loc_804845A
curBlock = blockDict[0x0804847F]
add_inst(curBlock, 0x0804847F, "\x89\x74\x99\x04")
add_inst(curBlock, 0x08048483, "\x8d\x47\x01")
add_inst(curBlock, 0x08048486, "\x83\xc7\x02")
add_inst(curBlock, 0x08048489, "\x39\xEF")
add_inst(curBlock, 0x0804848b, "\x7e\xcd", true_target=0x0804845a, false_target=0x0804848d)

#.text:0804845A 89 C7                   mov     edi, eax
#.text:0804845C 8B 74 B9 04             mov     esi, [ecx+edi*4+4]
#.text:08048460 89 F8                   mov     eax, edi
#.text:08048462 8B 14 B9                mov     edx, [ecx+edi*4]
#.text:08048465 39 D6                   cmp     esi, edx
#.text:08048467 7D 14                   jge     short loc_8
curBlock = blockDict[0x0804845A] 
add_inst(curBlock, 0x0804845A , "\x89\xc7")
add_inst(curBlock, 0x0804845C  , "\x8b\x74\xb9\x04")
add_inst(curBlock, 0x08048460  , "\x89\xf8")
add_inst(curBlock, 0x08048462  , "\x8b\x14\xb9")
add_inst(curBlock, 0x08048465  , "\x39\xd6")
add_inst(curBlock, 0x08048467  , "\x7d\x14", true_target=0x0804847d, false_target=0x08048469)


#.text:0804848D 5B                      pop     ebx
#.text:0804848E 5E                      pop     esi
#.text:0804848F 5F                      pop     edi
#.text:08048490 5D                      pop     ebp
#.text:08048491 C3                      ret
curBlock = blockDict[0x0804848D]
add_inst(curBlock, 0x0804848D, "\x5b")
add_inst(curBlock, 0x0804848E, "\x5e")
add_inst(curBlock, 0x0804848F, "\x5f")
add_inst(curBlock, 0x08048480, "\x5d")
add_inst(curBlock, 0x08048481, "\xc3")

#write out the message
out = M.SerializeToString()
f = file('cfg_1.cfg', 'wb')
f.write(out)
f.close()
del f
