BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; ADD16rm
    ;TEST_BEGIN_RECORDING
    lea eax, [esp-0x10]
    mov DWORD [eax], 0x1000
    mov bx, 0x2
    add bx, [eax]
    mov eax, [eax]
    ;TEST_END_RECORDING

