CC=clang
DISASS=mcsema-disass
IDA32=~/ida-6.9/idal
IDA64=~/ida-6.9/idal64

SRCS=$(wildcard *.c)
X86=$(addprefix x86/,$(SRCS:.c=.elf))
X64=$(addprefix amd64/,$(SRCS:.c=.elf))
X86_CFGS=$(addprefix x86/,$(SRCS:.c=.cfg))
X64_CFGS=$(addprefix amd64/,$(SRCS:.c=.cfg))

.PHONY: all clean

# do not delete intermediate targets
# we may want to examine these manually
.PRECIOUS: x86/%.elf amd64/%.elf

all: $(X86_CFGS) $(X64_CFGS)

# Build an ELF from our source
x86/%.elf: %.c
	${CC} -m32 -o $@ $<

amd64/%.elf: %.c
	${CC} -m64 -o $@ $<

# Translate ELFs to CFG
x86/%.cfg: x86/%.elf
	${DISASS} --disassembler ${IDA32} --arch x86 --os linux --output $@ --binary $< --entrypoint main

amd64/%.cfg: amd64/%.elf
	${DISASS} --disassembler ${IDA64} --arch amd64 --os linux --output $@ --binary $< --entrypoint main

clean:
	rm -f x86/*.elf x86/*.cfg
	rm -f amd64/*.elf amd64/*.cfg
