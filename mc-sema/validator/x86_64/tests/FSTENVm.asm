BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; FSTENVm
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x200]
    fstenv [rdi]
    mov eax, [rdi] ;control word
    mov ebx, [rdi+0x4] ;status word
    mov ecx, [rdi+0x8] ;tag word
    ;mov edx, [edi+0xc] ;EIP - unsupported
    ;mov esi, [edi+0x10] ;FOPCODE + FPU EIP Segment - unsupported
    ;mov ebp, [edi+0x14] ;data pointer - unsupported
    ;mov edi, [edi+0x18] ;data pointer selector - unsupported
    mov edi, 0x0
    ;TEST_END_RECORDING

