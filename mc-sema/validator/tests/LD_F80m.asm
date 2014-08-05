BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; LD_F80m
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0xc]
    mov DWORD [edi], 0x2168c000
    mov DWORD [edi+0x4], 0xc90fdaa2
    mov DWORD [edi+0x8], 0x00004000
    fld TWORD [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING

