BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea rdi, [rsp-0xc]
mov word [rdi], 0x2
FILD word [rdi]
mov word [rdi], 0x5
FILD word [rdi]
; get the IEEE remainder of 5/2
FPREM1
mov edi, 0
;TEST_END_RECORDING

