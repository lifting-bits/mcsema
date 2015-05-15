BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-08]
    mov dword [rdi], 0
    FSTCW [rdi]
    FLDCW [rdi]
    mov edi, 0
    ;TEST_END_RECORDING

