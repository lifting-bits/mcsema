BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; LOOP
    mov ecx, 0x18
    xor eax, eax
    inc eax
    ;TEST_BEGIN_RECORDING
again_1:
    add eax, eax
    loop again_1
    inc eax
    ;TEST_END_RECORDING

