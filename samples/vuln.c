/*
 * vuln.c — a small program with deliberate bugs for trying out the GUI.
 *
 * Build:  make            (see Makefile: gcc -g -O0 -fno-stack-protector -no-pie)
 *
 * Functions worth pointing the tool at:
 *   alloc_msg   unsigned 32-bit multiply overflow  (count * size)  -> undersized malloc
 *   frame_size  16-bit add that wraps after truncation (len + 8)
 *   scale       signed 32-bit overflow in a * b + 100
 *   route       branchy dispatcher: nice execution tree, one branch reaches abort()
 *   checksum    plain loop, no bug (control case)
 *   main        reads a few bytes from stdin and dispatches
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 1. classic multiplication overflow: count * size wraps, malloc is too small */
uint8_t *alloc_msg(uint32_t count, uint32_t size) {
    uint32_t total = count * size;          /* <- overflow here */
    if (total == 0)
        return NULL;
    uint8_t *p = (uint8_t *)malloc(total);
    if (!p)
        return NULL;
    for (uint32_t i = 0; i < count; i++)
        memset(p + (size_t)i * size, 0x41, size);  /* writes past the end when wrapped */
    return p;
}

/* 2. 16-bit wrap: len + 8 is computed in 32 bits then truncated to 16 */
uint16_t frame_size(const uint8_t *hdr) {
    uint16_t len = (uint16_t)(hdr[0] | (hdr[1] << 8));
    uint16_t total = len + 8;               /* <- wraps when len > 0xfff7 */
    if (total < len)
        return 0;                            /* the compiler may or may not keep this */
    return total;
}

/* 3. signed overflow */
int scale(int a, int b) {
    int r = a * b;                           /* <- signed overflow */
    return r + 100;                          /* <- and again */
}

/* 4. a loop with no bug, useful as a control */
uint32_t checksum(const uint8_t *data, uint32_t n) {
    uint32_t sum = 0;
    if (n > 64)
        n = 64;
    for (uint32_t i = 0; i < n; i++)
        sum = (sum << 1) ^ data[i];
    return sum;
}

/* 5. dispatcher with several branches, one of which aborts */
int route(int cmd, int x) {
    switch (cmd) {
    case 1:
        if (x < 0)
            return -1;
        return x * 2;
    case 2:
        if (x > 1000) {
            if (x == 4242)
                abort();                     /* reachable with cmd=2, x=4242 */
            return 1000;
        }
        return x;
    case 3:
        return scale(x, 3);
    case 4:
        return (int)frame_size((const uint8_t *)&x);
    default:
        return 0;
    }
}

int main(void) {
    uint8_t buf[8] = {0};
    if (read(0, buf, sizeof buf) < 2)
        return 1;
    int cmd = buf[0];
    int x = (int)(int8_t)buf[1] * 100;
    int r = route(cmd, x);
    if (r == 7)
        alloc_msg((uint32_t)buf[2] << 24, (uint32_t)buf[3] << 8);
    return r & 0xff;
}
