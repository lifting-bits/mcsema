BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; FADDP
    lea rdi, [rsp-0x8]
    ; load -1.25 in st0
    mov DWORD [rdi], 0xbfa00000
    fld DWORD [rdi]
    ;TEST_BEGIN_RECORDING
    fabs
    mov rdi, 0x0
    ;TEST_END_RECORDING

