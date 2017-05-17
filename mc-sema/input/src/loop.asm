    .486
    .model flat, stdcall
    option casemap :none 
    include \masm32\include\windows.inc
    include \masm32\macros\macros.asm
    include \masm32\include\masm32.inc
    include \masm32\include\gdi32.inc
    include \masm32\include\user32.inc
    include \masm32\include\kernel32.inc
    includelib \masm32\lib\masm32.lib
    includelib \masm32\lib\gdi32.lib
    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

    .data

    message db 'Hello world!',13,10,0
    dot db '.',0
    
    .code

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

start:                          ; Entry point

    mov ecx, 1000
    xor eax, eax
loop1:
    inc eax
;    push ecx
;    print offset dot
;    pop ecx
    loop loop1
    ret
        
; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл


proc_B proc

    inc eax
    ret

proc_B endp

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл


end start
