BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF|FLAG_OF
;TEST_FILE_META_END
    ; SHLD32mrCL
    mov cl, 0x3
    mov eax, 0x5dc
    ;TEST_BEGIN_RECORDING
    lea ebx, [esp - 4]
    mov dword [ebx], 0xfa7
    shld [ebx], eax, cl
    mov edx, [ebx]
    mov ebx, 0
    ;TEST_END_RECORDING

