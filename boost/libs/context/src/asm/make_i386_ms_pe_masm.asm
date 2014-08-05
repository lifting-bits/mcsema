
;           Copyright Oliver Kowalke 2009.
;  Distributed under the Boost Software License, Version 1.0.
;     (See accompanying file LICENSE_1_0.txt or copy at
;           http://www.boost.org/LICENSE_1_0.txt)

;  --------------------------------------------------------------
;  |    0    |    1    |    2    |    3    |    4     |    5    |
;  --------------------------------------------------------------
;  |    0h   |   04h   |   08h   |   0ch   |   010h   |   014h  |
;  --------------------------------------------------------------
;  |   EDI   |   ESI   |   EBX   |   EBP   |   ESP    |   EIP   |
;  --------------------------------------------------------------
;  --------------------------------------------------------------
;  |    6    |    7    |    8    |                              |
;  --------------------------------------------------------------
;  |   018h  |   01ch  |   020h  |                              |
;  --------------------------------------------------------------
;  |    sp   |   size  |  limit  |                              |
;  --------------------------------------------------------------
;  --------------------------------------------------------------
;  |    9    |                                                  |
;  --------------------------------------------------------------
;  |  024h   |                                                  |
;  --------------------------------------------------------------
;  |fc_execpt|                                                  |
;  --------------------------------------------------------------
;  --------------------------------------------------------------
;  |   10    |                                                  |
;  --------------------------------------------------------------
;  |  028h   |                                                  |
;  --------------------------------------------------------------
;  |fc_strage|                                                  |
;  --------------------------------------------------------------
;  --------------------------------------------------------------
;  |   11    |    12   |                                        |
;  --------------------------------------------------------------
;  |  02ch   |   030h  |                                        |
;  --------------------------------------------------------------
;  | fc_mxcsr|fc_x87_cw|                                        |
;  --------------------------------------------------------------

.386
.XMM
.model flat, c
_exit PROTO, value:SDWORD 
align_stack PROTO, vp:DWORD
seh_fcontext PROTO, except:DWORD, frame:DWORD, context:DWORD, dispatch:DWORD
.code

make_fcontext PROC EXPORT
    push ebp                        ; save previous frame pointer; get the stack 16 byte aligned
    mov  ebp,         esp           ; set EBP to ESP 
    sub  esp,         010h          ; allocate stack space

    mov  eax,         [ebp+08h]     ; load 1. arg of make_fcontext, pointer to context stack (base)
    lea  eax,         [eax-034h]    ; reserve space for fcontext_t at top of context stack
    mov  [esp],       eax           ; address in EAX becomes 1.arg of align_stack
    call  align_stack               ; call align_stack, EAX contains address at 16 byte boundary after return
                                    ; == pointer to fcontext_t and address of context stack

    mov  ecx,         [ebp+08h]     ; load 1. arg of make_fcontext, pointer to context stack (base)
    mov  [eax+018h],  ecx           ; save address of context stack (base) in fcontext_t
    mov  edx,         [ebp+0ch]     ; load 2. arg of make_fcontext, context stack size
    mov  [eax+01ch],  edx           ; save context stack size in fcontext_t
    neg  edx                        ; negate stack size for LEA instruction (== substraction)
    lea  ecx,         [ecx+edx]     ; compute bottom address of context stack (limit)
    mov  [eax+020h],  ecx           ; save address of context stack (limit) in fcontext_t
    mov  ecx,         [ebp+010h]    ; load 3. arg of make_fcontext, pointer to context function
    mov  [eax+014h],  ecx           ; save address of context function in fcontext_t

    stmxcsr [eax+02ch]              ; save MMX control word
    fnstcw  [eax+030h]              ; save x87 control word

    lea  edx,         [eax-01ch]    ; reserve space for last frame and seh on context stack, (ESP - 0x4) % 16 == 0
    mov  [eax+010h],  edx           ; save address in EDX as stack pointer for context function

    mov  ecx,         seh_fcontext  ; set ECX to exception-handler
    mov  [edx+018h],  ecx           ; save ECX as SEH handler
    mov  ecx,         0ffffffffh    ; set ECX to -1
    mov  [edx+014h],  ecx           ; save ECX as next SEH item
    lea  ecx,         [edx+014h]    ; load address of next SEH item
    mov  [eax+024h],  ecx           ; save next SEH

    mov  ecx,         finish        ; abs address of finish
    mov  [edx],       ecx           ; save address of finish as return address for context function
                                    ; entered after context function returns

    add  esp,         010h          ; deallocate stack space
    pop  ebp

    ret

finish:
    ; ESP points to same address as ESP on entry of context function + 0x4
    xor   eax,        eax
    mov   [esp],      eax           ; exit code is zero
    call  _exit                     ; exit application
    hlt
make_fcontext ENDP
END
