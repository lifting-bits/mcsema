BITS 32
SEGMENT .text

;this function needs to mock up what a 'ret' does
;we take 2 parameters - 
;  * the return address to branch to
;  * a pointer to the register context structure
;  * we need to take all of the registers that are in 
;    the register parameter structure and 


global _doRet

; void doRet(uint32_t retPtr, regs *r, uint32_t frame);
_doRet:
    mov edi, [esp+12] ;frame
    add edi, 12
    mov eax, [esp+4] ;retPtr
    mov esp, edi
    pop ebp
    jmp eax

global _doCall

;void doCall(uint32_t tgtPtr, regs *r)
_doCall:
    ;we need to put the address of 'done' into our stack
    ;TODO
    mov eax, done

    ;add the parameter
    mov eax, [esp+8]
    push eax

    ;then, call the specified tgtptr
    mov eax, [esp+4]
    call eax

    ;this is where we come back to
done:

    ret
