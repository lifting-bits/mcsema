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
	add eax, 42
	.if SDWORD PTR eax < 0
	mov ebx, 5
	.else
	sub eax, 7
	mov ebx, 3
	.endif
	add eax, ebx
	ret

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

end start                       ; Tell MASM where the program ends