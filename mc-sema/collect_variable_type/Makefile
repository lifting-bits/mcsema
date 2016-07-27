
EXE = basic basic_ptr
CFLAGS = -O0 -m32

all: $(EXE)

basic: basic.cc
	$(CC) $(CFLAGS) -o $@ $<

basic_ptr: basic_ptr.cc
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) $(EXE)
