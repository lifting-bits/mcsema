BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; AND32mr
    ;TEST_BEGIN_RECORDING
    lea eax, [esp-0x4]
    mov DWORD [eax], 0x55555
    mov ebx, 0x77777
    and DWORD [eax], ebx
    mov eax, 0x0
    ;TEST_END_RECORDING

