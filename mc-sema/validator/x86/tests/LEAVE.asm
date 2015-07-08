BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; LEAVE
    enter 0x8, 0x1
    mov edi, esp 
    mov ebx, [esp]
    mov eax, ebp
    ;TEST_BEGIN_RECORDING
    leave
    ;TEST_END_RECORDING
    mov esp, edi
    mov [esp], ebx
    mov ebp, eax

