BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; SUB8rm
    ;TEST_BEGIN_RECORDING
    lea eax, [esp-0x4]
    mov DWORD [eax], 0xc8
    mov ebx, 0x2
    sub bl, BYTE [eax]
    mov eax, [eax]
    ;TEST_END_RECORDING

