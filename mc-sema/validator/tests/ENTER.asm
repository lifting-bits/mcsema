BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; ENTER
    mov eax, esp
    mov edi, ebp
    mov ebx, esp
    sub ebx, 0x4
    ;TEST_BEGIN_RECORDING
    enter 0x4, 0x0
    cmp ebp, ebx
    mov ebp, 0x0
    ;TEST_END_RECORDING
    mov esp, eax
    mov ebp, edi

