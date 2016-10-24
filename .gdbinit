

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
  printf "r8      0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 532)), $r8
  printf "r9      0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 540)), $r9
  printf "r10     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 548)), $r10
  printf "r11     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 556)), $r11
  printf "r12     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 564)), $r12
  printf "r13     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 572)), $r13
  printf "r14     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 580)), $r14
  printf "r15     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 588)), $r15
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
  printf "&(RegState::r8) = 0x%016lx\n", $rptr + 532
  dont-repeat
end

define addr-of-r9
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r9) = 0x%016lx\n", $rptr + 540
  dont-repeat
end

define addr-of-r10
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r10) = 0x%016lx\n", $rptr + 548
  dont-repeat
end

define addr-of-r11
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r11) = 0x%016lx\n", $rptr + 556
  dont-repeat
end

define addr-of-r12
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r12) = 0x%016lx\n", $rptr + 564
  dont-repeat
end

define addr-of-r13
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r13) = 0x%016lx\n", $rptr + 572
  dont-repeat
end

define addr-of-r14
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r14) = 0x%016lx\n", $rptr + 580
  dont-repeat
end

define addr-of-r15
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r15) = 0x%016lx\n", $rptr + 588
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
