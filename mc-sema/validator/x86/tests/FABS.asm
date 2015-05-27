BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; FADDP
    lea edi, [esp-0x8]
    ; load -1.25 in st0
    mov DWORD [edi], 0xbfa00000
    fld DWORD [edi]
    ;TEST_BEGIN_RECORDING
    fabs
    mov edi, 0x0
    ;TEST_END_RECORDING

