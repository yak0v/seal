#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirrors the CVE shape: a "canvas" with a REAL buffer + size (concrete context the
 * caller sets up), and one USER-CONTROLLED coordinate. The write index is derived
 * from the coordinate; it's out of bounds only for specific coordinates. With the
 * context concrete and only `coord` symbolic, that OOB is a precise condition — not
 * "every path", which is what happens when everything is symbolic. */
typedef struct { unsigned char *buf; int size; int origin; } Canvas;

__attribute__((noinline))
int render(Canvas *cv, long coord) {
    int idx = (int)(coord >> 12) - cv->origin;   /* pixel index from the user coordinate */
    if (idx < 0) idx = 0;
    cv->buf[idx] = 0xff;                          /* OOB write when idx >= cv->size */
    return idx;
}

int main(int argc, char **argv) {
    Canvas cv;
    cv.size = 256;
    cv.origin = 4;
    cv.buf = (unsigned char *)calloc(cv.size, 1);
    long coord = (argc > 1) ? atol(argv[1]) : 65536;   /* benign default: idx small */
    int r = render(&cv, coord);
    printf("rendered idx=%d (size=%d)\n", r, cv.size);
    free(cv.buf);
    return 0;
}
