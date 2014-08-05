BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; LOOPNE
    mov eax, 0x4096
    mov ecx, 0x32
    ;TEST_BEGIN_RECORDING
again_2:
    shr eax, 0x1
    loopne again_2
    inc eax
    ;TEST_END_RECORDING

