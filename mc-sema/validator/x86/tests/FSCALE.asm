BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

lea edi, [esp-0xc]
mov word [edi], 0x2
fild word [edi]; st1 = 2
fild word [edi]; st0 = 2
mov edi, 0
;TEST_BEGIN_RECORDING
FSCALE ; st0 = 8
;TEST_END_RECORDING

