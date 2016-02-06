BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF
;TEST_FILE_META_END
    ; IMUL64m
    mov rax, 0x323
    mov rbx, 0xbbbbbbbb
    push rbx
    pop rbx
    ;TEST_BEGIN_RECORDING
    imul rax, [rsp - 8]
    ;TEST_END_RECORDING

