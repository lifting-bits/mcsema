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

; �������������������������������������������������������������������������

	.code

; �������������������������������������������������������������������������

start:                          ; Entry point
	mov ecx, 1523
	xor ebx, ebx
	xor eax, eax
	.while SDWORD PTR ecx >= 0
	add eax, ecx
	dec ecx
	.if eax >= 5000
	xor eax, eax
	inc ebx
	.endif
	.endw
	add ecx, ebx
	ret

; �������������������������������������������������������������������������

end start                       ; Tell MASM where the program ends