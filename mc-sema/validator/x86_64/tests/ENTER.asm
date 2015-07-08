BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; ENTER
    mov rax, rsp
    mov rdi, rbp
    mov rbx, rsp
    sub rbx, 0x8
    ;TEST_BEGIN_RECORDING
    enter 0x8, 0x0
    cmp rbp, rbx
    mov rbp, 0x0
    ;TEST_END_RECORDING
    mov rsp, rax
    mov rbp, rdi

