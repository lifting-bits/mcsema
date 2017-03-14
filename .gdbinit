
define print-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $_rip = *((unsigned long long *)($rptr + 0))
  printf "0x%lx\n", $_rip
  dont-repeat
end

define print-reg-state-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "             emulated                   native\n"
  printf "rip     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 0)), $rip
  printf "rax     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 8)), $rax
  printf "rbx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 16)), $rbx
  printf "rcx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 24)), $rcx
  printf "rdx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 32)), $rdx
  printf "rsi     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 40)), $rsi
  printf "rdi     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 48)), $rdi
  printf "rbp     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 64)), $rbp
  printf "rsp     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 56)), $rsp
  printf "r8      0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 72)), $r8
  printf "r9      0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 80)), $r9
  printf "r10     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 88)), $r10
  printf "r11     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 96)), $r11
  printf "r12     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 104)), $r12
  printf "r13     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 112)), $r13
  printf "r14     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 120)), $r14
  printf "r15     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 128)), $r15
  dont-repeat
end


define addr-of-xmm0-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm0) = 0x%016lx\n", $rptr + 304
  dont-repeat
end

define addr-of-xmm1-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm1) = 0x%016lx\n", $rptr + 320
  dont-repeat
end

define addr-of-xmm2-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm2) = 0x%016lx\n", $rptr + 336
  dont-repeat
end

define addr-of-xmm3-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm3) = 0x%016lx\n", $rptr + 352
  dont-repeat
end

define addr-of-xmm4-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm4) = 0x%016lx\n", $rptr + 368
  dont-repeat
end

define addr-of-xmm5-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm5) = 0x%016lx\n", $rptr + 384
  dont-repeat
end

define addr-of-xmm6-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm6) = 0x%016lx\n", $rptr + 400
  dont-repeat
end

define addr-of-xmm7-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm7) = 0x%016lx\n", $rptr + 416
  dont-repeat
end

define addr-of-xmm8-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm8) = 0x%016lx\n", $rptr + 432
  dont-repeat
end

define addr-of-xmm9-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm9) = 0x%016lx\n", $rptr + 448
  dont-repeat
end

define addr-of-xmm10-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm10) = 0x%016lx\n", $rptr + 464
  dont-repeat
end

define addr-of-xmm11-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm11) = 0x%016lx\n", $rptr + 480
  dont-repeat
end

define addr-of-xmm12-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm12) = 0x%016lx\n", $rptr + 496
  dont-repeat
end

define addr-of-xmm13-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm13) = 0x%016lx\n", $rptr + 512
  dont-repeat
end

define addr-of-xmm14-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm14) = 0x%016lx\n", $rptr + 528
  dont-repeat
end

define addr-of-xmm15-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::xmm15) = 0x%016lx\n", $rptr + 544
  dont-repeat
end

define print-flags-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $flptr = (char *) ($rptr + 136)
  printf "eflags ["
  if $flptr[0]
    printf "CF "
  end
  if $flptr[1]
    printf "PF "
  end
  if $flptr[2]
    printf "AF "
  end
  if $flptr[3]
    printf "ZF "
  end
  if $flptr[4]
    printf "SF "
  end
  if $flptr[5]
    printf "OF "
  end
  if $flptr[6]
    printf "DF "
  end
  printf "]\n"
  dont-repeat
end

define print-reg-state-32
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "         emulated           native\n"
  printf "eip     0x%08x        0x%08x\n", *((unsigned *)($rptr + 0)), $eip
  printf "eax     0x%08x        0x%08x\n", *((unsigned *)($rptr + 4)), $eax
  printf "ebx     0x%08x        0x%08x\n", *((unsigned *)($rptr + 8)), $ebx
  printf "ecx     0x%08x        0x%08x\n", *((unsigned *)($rptr + 12)), $ecx
  printf "edx     0x%08x        0x%08x\n", *((unsigned *)($rptr + 16)), $edx
  printf "esi     0x%08x        0x%08x\n", *((unsigned *)($rptr + 20)), $esi
  printf "edi     0x%08x        0x%08x\n", *((unsigned *)($rptr + 24)), $edi
  printf "ebp     0x%08x        0x%08x\n", *((unsigned *)($rptr + 28)), $ebp
  printf "esp     0x%08x        0x%08x\n", *((unsigned *)($rptr + 32)), $esp
  dont-repeat
end


define addr-of-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rip) = 0x%016lx\n", $rptr + 0
  dont-repeat
end

define addr-of-rax
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rax) = 0x%016lx\n", $rptr + 8
  dont-repeat
end

define addr-of-rbx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rbx) = 0x%016lx\n", $rptr + 16
  dont-repeat
end

define addr-of-rcx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rcx) = 0x%016lx\n", $rptr + 24
  dont-repeat
end

define addr-of-rdx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rdx) = 0x%016lx\n", $rptr + 32
  dont-repeat
end

define addr-of-rsi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rsi) = 0x%016lx\n", $rptr + 40
  dont-repeat
end

define addr-of-rdi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rdi) = 0x%016lx\n", $rptr + 48
  dont-repeat
end

define addr-of-rbp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rbp) = 0x%016lx\n", $rptr + 64
  dont-repeat
end

define addr-of-rsp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rsp) = 0x%016lx\n", $rptr + 56
  dont-repeat
end

define addr-of-r8
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r8) = 0x%016lx\n", $rptr + 72
  dont-repeat
end

define addr-of-r9
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r9) = 0x%016lx\n", $rptr + 80
  dont-repeat
end

define addr-of-r10
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r10) = 0x%016lx\n", $rptr + 88
  dont-repeat
end

define addr-of-r11
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r11) = 0x%016lx\n", $rptr + 96
  dont-repeat
end

define addr-of-r12
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r12) = 0x%016lx\n", $rptr + 104
  dont-repeat
end

define addr-of-r13
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r13) = 0x%016lx\n", $rptr + 112
  dont-repeat
end

define addr-of-r14
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r14) = 0x%016lx\n", $rptr + 120
  dont-repeat
end

define addr-of-r15
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r15) = 0x%016lx\n", $rptr + 128
  dont-repeat
end



define addr-of-eip
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::eip) = 0x%08x\n", $rptr + 0
  dont-repeat
end

define addr-of-eax
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::eax) = 0x%08x\n", $rptr + 4
  dont-repeat
end

define addr-of-ebx
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::ebx) = 0x%08x\n", $rptr + 8
  dont-repeat
end

define addr-of-ecx
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::ecx) = 0x%08x\n", $rptr + 12
  dont-repeat
end

define addr-of-edx
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::edx) = 0x%08x\n", $rptr + 16
  dont-repeat
end

define addr-of-esi
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::esi) = 0x%08x\n", $rptr + 20
  dont-repeat
end

define addr-of-edi
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::edi) = 0x%08x\n", $rptr + 24
  dont-repeat
end

define addr-of-ebp
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::ebp) = 0x%08x\n", $rptr + 28
  dont-repeat
end

define addr-of-esp
  set $rptr = ((unsigned (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::esp) = 0x%08x\n", $rptr + 32
  dont-repeat
end
