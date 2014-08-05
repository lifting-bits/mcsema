BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; FADDP
    lea edi, [esp-0x10]
    mov DWORD [edi], 0x2168c000
    mov DWORD [edi+0x4], 0xc90fdaa2
    mov DWORD [edi+0x8], 0x00004000
    fld TWORD [edi]
    fld TWORD [edi]
    ;TEST_BEGIN_RECORDING
    fsubp
    mov edi, 0x0
    ;TEST_END_RECORDING

