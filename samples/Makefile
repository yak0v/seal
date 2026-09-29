CC ?= gcc
CFLAGS ?= -g -O0 -fno-stack-protector -no-pie -fno-omit-frame-pointer -Wno-unused-result

all: vuln

vuln: vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f vuln vuln.angrgui.json

.PHONY: all clean
