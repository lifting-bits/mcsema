BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; Composite2
    mov ecx, 0x18
    xor ebx, ebx
    xor eax, eax
    inc eax
    ;TEST_BEGIN_RECORDING
again:
    cmp ebx, ecx
    je done
    inc ebx
    add eax, eax
    jmp again
done:
    inc eax
    ;TEST_END_RECORDING

