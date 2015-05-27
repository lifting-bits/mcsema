BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; set up st0 to be 3.141593
lea edi, [esp-04]
mov dword [edi], 0x40490fdb
fld dword [edi]
;TEST_BEGIN_RECORDING
lea edi, [esp-04]
mov dword [edi], 0x40490fdb
FADD dword [edi]
mov edi, 0
;TEST_END_RECORDING

