BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; LEAVE
    enter 0x8, 0x1
    mov rdi, rsp 
    mov rbx, [rsp]
    mov rax, rbp
    ;TEST_BEGIN_RECORDING
    leave
    ;TEST_END_RECORDING
    mov rsp, rdi
    mov [rsp], rbx
    mov rbp, rax

