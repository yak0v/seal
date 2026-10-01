/* Verbatim vulnerable functions from json-c 0.14 (printbuf.c), the code affected
 * by CVE-2020-12762 (signed integer overflow -> out-of-bounds heap write).
 * The pre-patch arithmetic is reproduced exactly; the fix added INT_MAX guards. */
#include <stdlib.h>
#include <string.h>

struct printbuf {
    char *buf;
    int bpos;
    int size;
};

/* --- the vulnerable code, exactly as shipped in json-c 0.14 --------------- */
static int printbuf_extend(struct printbuf *p, int min_size)
{
    char *t;
    int new_size;

    if (p->size >= min_size)
        return 0;

    new_size = p->size * 2;              /* overflows when p->size > INT_MAX/2 */
    if (new_size < min_size + 8)
        new_size = min_size + 8;         /* overflows when min_size > INT_MAX-8 */
    if (!(t = (char *)realloc(p->buf, new_size)))
        return -1;
    p->size = new_size;
    p->buf = t;
    return 0;
}

int printbuf_memappend(struct printbuf *p, const char *buf, int size)
{
    if (p->size <= p->bpos + size + 1)   /* p->bpos + size + 1 overflows int */
    {
        if (printbuf_extend(p, p->bpos + size + 1) < 0)
            return -1;
    }
    memcpy(p->buf + p->bpos, buf, size);
    p->bpos += size;
    p->buf[p->bpos] = '\0';
    return size;
}

/* keep both functions reachable / not inlined away so angr can target them */
int main(int argc, char **argv)
{
    struct printbuf p = { malloc(32), 0, 32 };
    char data[8] = {0};
    printbuf_memappend(&p, data, argc);
    return p.bpos;
}
