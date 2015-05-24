BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_PF|FLAG_SF|FLAG_AF
;TEST_FILE_META_END
    ; BT32rr
    mov eax, 0x08000000
    mov ebx, 27
    clc ; clear carry since we will set it
    ;TEST_BEGIN_RECORDING
    bt eax, ebx
    ;TEST_END_RECORDING

