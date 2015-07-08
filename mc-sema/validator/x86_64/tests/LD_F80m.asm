BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; LD_F80m
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0xc]
    mov DWORD [rdi], 0x2168c000
    mov DWORD [rdi+0x4], 0xc90fdaa2
    mov DWORD [rdi+0x8], 0x00004000
    fld TWORD [rdi]
    mov edi, 0x0
    ;TEST_END_RECORDING

