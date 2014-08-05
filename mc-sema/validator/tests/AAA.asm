BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; AAA
    mov al, 0x45
    add al, 0x23
    ;enable tracing
    ;TEST_BEGIN_RECORDING
    aaa
    ;disable tracing
    ;TEST_END_RECORDING

