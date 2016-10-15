

define print-reg-state-64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "             emulated                   native\n"
  printf "rip     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 0)), $rip
  printf "rax     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 8)), $rax
  printf "rbx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 16)), $rbx
  printf "rcx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 24)), $rcx
  printf "rdx     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 32)), $rdx
  printf "rdi     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 48)), $rdi
  printf "rsi     0x%016lx        0x%016lx\n", *((unsigned long long *)($rptr + 40)), $rsi
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

define addr-of-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rip) = 0x%016x\n", $rptr + 0
  dont-repeat
end

define addr-of-rax
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rax) = 0x%016x\n", $rptr + 8
  dont-repeat
end

define addr-of-rbx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rbx) = 0x%016x\n", $rptr + 16
  dont-repeat
end

define addr-of-rcx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rcx) = 0x%016x\n", $rptr + 24
  dont-repeat
end

define addr-of-rdx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rdx) = 0x%016x\n", $rptr + 32
  dont-repeat
end

define addr-of-rdi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rdi) = 0x%016x\n", $rptr + 48
  dont-repeat
end

define addr-of-rsi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rsi) = 0x%016x\n", $rptr + 40
  dont-repeat
end

define addr-of-rbp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rbp) = 0x%016x\n", $rptr + 64
  dont-repeat
end

define addr-of-rsp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::rsp) = 0x%016x\n", $rptr + 56
  dont-repeat
end

define addr-of-r8
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r8) = 0x%016x\n", $rptr + 532
  dont-repeat
end

define addr-of-r9
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r9) = 0x%016x\n", $rptr + 540
  dont-repeat
end

define addr-of-r10
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r10) = 0x%016x\n", $rptr + 548
  dont-repeat
end

define addr-of-r11
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r11) = 0x%016x\n", $rptr + 556
  dont-repeat
end

define addr-of-r12
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r12) = 0x%016x\n", $rptr + 564
  dont-repeat
end

define addr-of-r13
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r13) = 0x%016x\n", $rptr + 572
  dont-repeat
end

define addr-of-r14
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r14) = 0x%016x\n", $rptr + 580
  dont-repeat
end

define addr-of-r15
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "&(RegState::r15) = 0x%016x\n", $rptr + 588
  dont-repeat
end

