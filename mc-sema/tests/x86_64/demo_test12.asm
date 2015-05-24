BITS 32
SEGMENT .text

filler: db 0x00

start:
    mov word [store_ss], ss
    mov word [store_cs], cs
    mov word [store_ds], ds
    mov word [store_es], es
    mov word [store_fs], fs
    mov word [store_gs], gs
    xor eax, eax
    mov eax, ss
    pushf
    pop eax
    ret

    
SEGMENT .data 
store_ss:
dd 0x00
store_cs:
dd 0x00
store_ds:
dd 0x00
store_es:
dd 0x00
store_fs:
dd 0x00
store_gs:
dd 0x00
