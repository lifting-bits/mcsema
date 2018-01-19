
define print-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $_rip = *((unsigned long long *)($rptr + 2408))
  printf "0x%lx\n", $_rip
  dont-repeat
end

set $__rax_offset = 2216
set $__flags_offset = 2064
set $__xmm0_offset = 16

define print-reg-state-amd64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "             emulated                   native\n"
  set $__rax_ptr = $rptr + $__rax_offset
  printf "rip     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 16 * 16)), $rip
  printf "rax     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 0 * 16)), $rax
  printf "rbx     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 1 * 16)), $rbx
  printf "rcx     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 2 * 16)), $rcx
  printf "rdx     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 3 * 16)), $rdx
  printf "rsi     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 4 * 16)), $rsi
  printf "rdi     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 5 * 16)), $rdi
  printf "rsp     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 6 * 16)), $rsp
  printf "rbp     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 7 * 16)), $rbp
  printf "r8      0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 8 * 16)), $r8
  printf "r9      0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 9 * 16)), $r9
  printf "r10     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 10 * 16)), $r10
  printf "r11     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 11 * 16)), $r11
  printf "r12     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 12 * 16)), $r12
  printf "r13     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 13 * 16)), $r13
  printf "r14     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 14 * 16)), $r14
  printf "r15     0x%016lx        0x%016lx\n", *((unsigned long long *)($__rax_ptr + 15 * 16)), $r15
  dont-repeat
end

define print-flags-amd64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $flptr = (char *) ($rptr + $__flags_offset)
  printf "eflags ["
  if $flptr[1]
    printf "CF "
  end
  if $flptr[3]
    printf "PF "
  end
  if $flptr[5]
    printf "AF "
  end
  if $flptr[7]
    printf "ZF "
  end
  if $flptr[9]
    printf "SF "
  end
  if $flptr[11]
    printf "DF "
  end
  if $flptr[13]
    printf "OF "
  end
  printf "]\n"
  dont-repeat
end

define print-flags-x86
  print-flags-amd64
end

define print-reg-state-x86
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "             emulated                   native\n"
  set $__rax_ptr = $rptr + $__rax_offset
  printf "eip     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 16 * 16)), (unsigned) $pc
  printf "eax     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 0 * 16)), $eax
  printf "ebx     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 1 * 16)), $ebx
  printf "ecx     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 2 * 16)), $ecx
  printf "edx     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 3 * 16)), $edx
  printf "esi     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 4 * 16)), $esi
  printf "edi     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 5 * 16)), $edi
  printf "esp     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 6 * 16)), $esp
  printf "ebp     0x%08x        0x%08x\n", *((unsigned *)($__rax_ptr + 7 * 16)), $ebp
  dont-repeat
end

set $__x0_offset = 544

define print-reg-state-aarch64
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  printf "\temulated\n"
  set $__x0_ptr = $rptr + $__x0_offset
  set $__i = 0
  while $__i < 31
    printf "x%d\t0x%016lx\t&x%d = 0x%lx\n", $__i, *((unsigned long long *)($__x0_ptr + $__i * 16)), $__i, $__x0_ptr + $__i * 16
    set $__i = $__i + 1
  end
  
  printf "sp\t0x%016lx\n", *((unsigned long long *)($__x0_ptr + $__i * 16))
  set $__i = $__i + 1
  printf "pc\t0x%016lx\t&pc = 0x%lx\n", *((unsigned long long *)($__x0_ptr + $__i * 16)), $__x0_ptr + $__i * 16
  dont-repeat
end


define addr-of-rip
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rip = 0x%016lx\n", $__rax_ptr + 16 * 16
  dont-repeat
end

define addr-of-rax
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rax = 0x%016lx\n", $__rax_ptr + 0 * 16
  dont-repeat
end

define addr-of-rbx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rbx = 0x%016lx\n", $__rax_ptr + 1 * 16
  dont-repeat
end

define addr-of-rcx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rcx = 0x%016lx\n", $__rax_ptr + 2 * 16
  dont-repeat
end

define addr-of-rdx
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rdx = 0x%016lx\n", $__rax_ptr + 3 * 16
  dont-repeat
end

define addr-of-rsi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rsi = 0x%016lx\n", $__rax_ptr + 4 * 16
  dont-repeat
end

define addr-of-rdi
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rdi = 0x%016lx\n", $__rax_ptr + 5 * 16
  dont-repeat
end

define addr-of-rsp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rsp = 0x%016lx\n", $__rax_ptr + 6 * 16
  dont-repeat
end

define addr-of-rbp
  set $rptr = ((unsigned long long (*)(void))__mcsema_debug_get_reg_state)()
  set $__rax_ptr = $rptr + $__rax_offset
  printf "&rbp = 0x%016lx\n", $__rax_ptr + 7 * 16
  dont-repeat
end

