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
    
    .code

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

start:                          ; Entry point
    cmp eax, 0
    jle lthen
lelse:
    mov eax, offset start + 1
    jmp lcont
lhalt:
    ret
    
lthen:
    mov eax, offset l1 + 6
l1:
    sub eax, 5
lcont:
    sub eax, 1
    jmp eax
        
; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл


end start
