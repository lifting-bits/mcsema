BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; set up st0 to be 1/2
lea edi, [esp-04]
mov dword [edi], 0x3f000000
fld dword [edi]
;TEST_BEGIN_RECORDING
f2xm1
mov edi, 0
;TEST_END_RECORDING

