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

    .code

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

start:                          ; Entry point

    mov ebx, 3
    mov edi, (offset foo - 4)
    add edi, ebx
    inc edi
    call edi
    ret
; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
    message db 'Hello world!',13,10,0
; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

foo proc

    print offset message
    ret
    
foo endp

end start