BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_PE|FLAG_FPU_C1
;TEST_FILE_META_END
    ; set up st0 to be PI
    FLDPI
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-08]
    mov dword [rdi], 0x1

    FISUBR dword [rdi]
    mov edi, 0x0
    ;TEST_END_RECORDING
