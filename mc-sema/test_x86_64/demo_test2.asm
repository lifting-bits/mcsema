BITS 64
SEGMENT .text

filler: db 0x00

start:
    mov ecx, eax
    xor eax, eax
    inc eax
    xor ebx, ebx
header:
    cmp ebx, ecx
    je done
    add eax, eax 
    inc ebx
    jmp header
done:
    ret
