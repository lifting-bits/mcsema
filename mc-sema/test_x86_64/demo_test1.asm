BITS 64
SEGMENT .text

filler: db 0x00

start:
    add eax, 1
    ret
