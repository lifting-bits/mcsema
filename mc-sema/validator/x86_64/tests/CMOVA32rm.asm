BITS 64 
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; CMOVA32rm
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x4]
    mov DWORD [rdi], 0x3
    cmova eax, [rdi]
    mov rdi, 0x0
    ;TEST_END_RECORDING

