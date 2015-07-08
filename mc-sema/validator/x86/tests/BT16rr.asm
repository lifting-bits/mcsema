BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_PF|FLAG_SF|FLAG_AF
;TEST_FILE_META_END
    ; BT16rr
    mov ax, 0x0800
    mov bx, 11
    clc ; clear carry since we will set it
    ;TEST_BEGIN_RECORDING
    bt ax, bx
    ;TEST_END_RECORDING


