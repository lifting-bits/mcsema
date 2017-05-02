
define print-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $_rip = *((unsigned long long *)($rptr + 2408))
  printf "0x%lx\n", $_rip
  dont-repeat
end

define print-reg-state-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "             emulated                   native\n"
  printf "rip     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2408)), $rip
  printf "rax     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2152)), $rax
  printf "rbx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2168)), $rbx
  printf "rcx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2184)), $rcx
  printf "rdx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2200)), $rdx
  printf "rsi     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2216)), $rsi
  printf "rdi     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2232)), $rdi
  printf "rbp     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2264)), $rbp
  printf "rsp     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2248)), $rsp
  printf "r8      0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2280)), $r8
  printf "r9      0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2296)), $r9
  printf "r10     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2312)), $r10
  printf "r11     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2328)), $r11
  printf "r12     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2344)), $r12
  printf "r13     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2360)), $r13
  printf "r14     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2376)), $r14
  printf "r15     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 2392)), $r15
  dont-repeat
end

define addr-of-xmm0-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm0) = 0x%016lx\n", $rptr + 16
  dont-repeat
end

define addr-of-xmm1-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm1) = 0x%016lx\n", $rptr + 80
  dont-repeat
end

define addr-of-xmm2-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm2) = 0x%016lx\n", $rptr + 144
  dont-repeat
end

define addr-of-xmm3-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm3) = 0x%016lx\n", $rptr + 208
  dont-repeat
end

define addr-of-xmm4-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm4) = 0x%016lx\n", $rptr + 272
  dont-repeat
end

define addr-of-xmm5-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm5) = 0x%016lx\n", $rptr + 336
  dont-repeat
end

define addr-of-xmm6-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm6) = 0x%016lx\n", $rptr + 400
  dont-repeat
end

define addr-of-xmm7-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm7) = 0x%016lx\n", $rptr + 464
  dont-repeat
end

define addr-of-xmm8-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm8) = 0x%016lx\n", $rptr + 528
  dont-repeat
end

define addr-of-xmm9-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm9) = 0x%016lx\n", $rptr + 592
  dont-repeat
end

define addr-of-xmm10-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm10) = 0x%016lx\n", $rptr + 656
  dont-repeat
end

define addr-of-xmm11-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm11) = 0x%016lx\n", $rptr + 720
  dont-repeat
end

define addr-of-xmm12-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm12) = 0x%016lx\n", $rptr + 784
  dont-repeat
end

define addr-of-xmm13-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm13) = 0x%016lx\n", $rptr + 848
  dont-repeat
end

define addr-of-xmm14-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm14) = 0x%016lx\n", $rptr + 912
  dont-repeat
end

define addr-of-xmm15-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm15) = 0x%016lx\n", $rptr + 976
  dont-repeat
end

define print-flags-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $flptr = (char *) ($rptr + 2065)
  printf "eflags ["
  if $flptr[0]
    printf "CF "
  end
  if $flptr[2]
    printf "PF "
  end
  if $flptr[4]
    printf "AF "
  end
  if $flptr[6]
    printf "ZF "
  end
  if $flptr[8]
    printf "SF "
  end
  if $flptr[10]
    printf "OF "
  end
  if $flptr[12]
    printf "DF "
  end
  printf "]\n"
  dont-repeat
end

define print-reg-state-32
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "         emulated           native\n"
  printf "eip     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2408)), $eip
  printf "eax     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2152)), $eax
  printf "ebx     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2168)), $ebx
  printf "ecx     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2184)), $ecx
  printf "edx     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2200)), $edx
  printf "esi     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2216)), $esi
  printf "edi     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2232)), $edi
  printf "ebp     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2264)), $ebp
  printf "esp     0x%08lx        0x%016lx\n", *((unsigned long long *)($rptr + 2248)), $esp
  dont-repeat
end


define addr-of-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rip = 0x%016lx\n", $rptr + 2408
  dont-repeat
end

define addr-of-rax
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rax = 0x%016lx\n", $rptr + 2152
  dont-repeat
end

define addr-of-rbx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rbx = 0x%016lx\n", $rptr + 2168
  dont-repeat
end

define addr-of-rcx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rcx = 0x%016lx\n", $rptr + 2184
  dont-repeat
end

define addr-of-rdx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rdx = 0x%016lx\n", $rptr + 2200
  dont-repeat
end

define addr-of-rsi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rsi = 0x%016lx\n", $rptr + 2216
  dont-repeat
end

define addr-of-rdi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rdi = 0x%016lx\n", $rptr + 2232
  dont-repeat
end

define addr-of-rbp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rbp = 0x%016lx\n", $rptr + 2264
  dont-repeat
end

define addr-of-rsp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&rsp = 0x%016lx\n", $rptr + 2248
  dont-repeat
end


define addr-of-r8
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r8 = 0x%016lx\n", $rptr + 2280
  dont-repeat
end

define addr-of-r9
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r9 = 0x%016lx\n", $rptr + 2296
  dont-repeat
end

define addr-of-r10
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r10 = 0x%016lx\n", $rptr + 2312
  dont-repeat
end

define addr-of-r11
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r11 = 0x%016lx\n", $rptr + 2328
  dont-repeat
end

define addr-of-r12
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r12 = 0x%016lx\n", $rptr + 2344
  dont-repeat
end

define addr-of-r13
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r13 = 0x%016lx\n", $rptr + 2360
  dont-repeat
end

define addr-of-r14
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r14 = 0x%016lx\n", $rptr + 2376
  dont-repeat
end

define addr-of-r15
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&r15 = 0x%016lx\n", $rptr + 2392
  dont-repeat
end

