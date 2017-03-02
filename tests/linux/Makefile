CC=clang-3.8
DISASS=mcsema-disass
ifdef IDA_PATH
	IDA32=$(IDA_PATH)/idal
	IDA64=$(IDA_PATH)/idal64
else
	IDA32=~/ida-6.9/idal
	IDA64=~/ida-6.9/idal64
endif

SRCS=$(wildcard *.c)
X86=$(addprefix x86/,$(SRCS:.c=.elf))
X64=$(addprefix amd64/,$(SRCS:.c=.elf))

X86_CFGS=$(addprefix x86/,$(SRCS:.c=.cfg))
X64_CFGS=$(addprefix amd64/,$(SRCS:.c=.cfg))

X86_ELFS=$(wildcard x86/*.elf)
X64_ELFS=$(wildcard amd64/*.elf)

X86_ELFS_CFGS=$(X86_ELFS:.elf=.cfg)
X64_ELFS_CFGS=$(X64_ELFS:.elf=.cfg)

.PHONY: all clean

# do not delete intermediate targets
# we may want to examine these manually
.PRECIOUS: x86/%.elf amd64/%.elf

all: $(X86_CFGS) $(X64_CFGS) $(X86_ELFS_CFGS) $(X64_ELFS_CFGS)

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
	rm -f $(X86)
	rm -f $(X86_CFGS)
	rm -f $(X64)
	rm -f $(X64_CFGS)
