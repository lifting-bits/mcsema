BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; ADD64rr
    mov rcx, 0x7fffffff
    mov rdx, 0x6ffeeeeee
    ;TEST_BEGIN_RECORDING
    add rcx, rdx
    ;TEST_END_RECORDING

