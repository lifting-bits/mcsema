BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea rdi, [rsp-0x300]
and rdi, 0xFFFFFFFFFFFFFFF0
FXSAVE [rdi]
; a simple sanity check that something was written
mov eax, [rdi]
mov edi, 0
;TEST_END_RECORDING

