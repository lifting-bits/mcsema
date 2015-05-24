BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    ; ST_F64m
    FLD1
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x10]
    fst QWORD [edi]
    mov eax, [edi+0x00]
    mov ebx, [edi+0x04]
    mov edi, 0x0
    ;TEST_END_RECORDING

