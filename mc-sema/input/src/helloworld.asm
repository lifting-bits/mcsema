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

    mov edi, offset foo
    mov ebx, 2
    printloop:
    print chr$("Hey, this actually works.",13,10)
    sub ebx, 1
    jnz printloop
    call edi
    exit
    ret

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

foo proc

    print chr$("This is a function call!",13,10)
    ret
    
foo endp

end start                       ; Tell MASM where the program ends