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
    fp dd ?   
    

    .code

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

start:                          ; Entry point

    mov ebx, offset foo
    mov dword ptr fp, ebx
    xor ebx, ebx
    mov eax, dword ptr fp
    call eax
    ret
    
; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

foo proc

    print addr message
    mov eax, 12345
    ret
    
foo endp

end start
