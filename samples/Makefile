# The tool targets x86-64 Linux (ELF) binaries. On macOS the system `gcc` is
# clang emitting Mach-O, so use an x86-64 Linux cross-compiler instead
# (brew install filosottile/musl-cross/musl-cross, or any x86_64-linux-gnu-gcc).
ifeq ($(shell uname -s),Darwin)
  ifeq ($(origin CC),default)
    CC := $(firstword $(shell command -v x86_64-linux-gnu-gcc x86_64-linux-musl-gcc 2>/dev/null))
    ifeq ($(CC),)
      $(error no x86-64 Linux cross-compiler found; brew install filosottile/musl-cross/musl-cross)
    endif
  endif
endif
CC ?= gcc
CFLAGS ?= -g -O0 -fno-stack-protector -no-pie -fno-omit-frame-pointer -Wno-unused-result
PYTHON ?= $(if $(wildcard ../.venv/bin/python),../.venv/bin/python,python3)

all: vuln vuln.angrgui.json jsonc_printbuf checks_sample

vuln: vuln.c
	$(CC) $(CFLAGS) -o $@ $<

# CVE-2020-12762: the verbatim vulnerable json-c 0.14 printbuf functions. Target
# printbuf_extend (p -> symbolic 16-byte struct, min_size symbolic) with an
# int_overflow check and angr finds min_size near INT_MAX that overflows min_size+8.
jsonc_printbuf: jsonc_printbuf.c
	$(CC) $(CFLAGS) -fno-inline -o $@ $<

# the example project; its addresses depend on the toolchain, so derive them
vuln.angrgui.json: vuln make_workspace.py
	$(PYTHON) make_workspace.py vuln

clean:
	rm -f vuln vuln.angrgui.json jsonc_printbuf

.PHONY: all clean

# planted bugs for the div_by_zero / null_deref / oob_read checks
checks_sample: checks_sample.c
	$(CC) $(CFLAGS) -fno-inline -o $@ $<
