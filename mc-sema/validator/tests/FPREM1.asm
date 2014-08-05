BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea edi, [esp-0xc]
mov word [edi], 0x2
FILD word [edi]
mov word [edi], 0x5
FILD word [edi]
; get the IEEE remainder of 5/2
FPREM1
mov edi, 0
;TEST_END_RECORDING

