BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; Composite1
    mov eax, 0x18
    ;TEST_BEGIN_RECORDING
    mov ecx, eax
    xor eax, eax
    xor ebx, ebx
    cmp ebx, ecx
    ;TEST_END_RECORDING

