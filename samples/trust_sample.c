/*
 * trust_sample.c — planted shapes for the "trust & direction" features that otherwise
 * only have live arm64 validation: a CONDITIONAL finding (an index driven by a skipped
 * call's return) and a CONCRETE-GATE (a branch decided by a value a from-scratch run
 * leaves concrete). Built like the other samples (x86-64 ELF, -O0 -no-pie).
 */
#include <stdint.h>

/* A real callee whose return (0..3) is what via_return() indexes by. With skip_calls ON
 * (the default) SEAL leaves this call's return UNCONSTRAINED, so a bug through it is
 * CONDITIONAL on this return — which constrain_return / return_bounds resolve. */
int clip_count(int a, int b) {
    int n = 0;
    if (a > 0) n++;
    if (b > 0) n++;
    if (a > b) n++;
    return n;
}

/* Indexes a caller-supplied 4-int (16-byte) buffer by clip_count's return. OOB write
 * if the return can be >= 4. Under skip_calls the return is free => a conditional lead;
 * constrain_return(clip_count, max=3) dismisses it, max>=4 keeps it. buf is a pointer
 * arg so an oob_write check anchors to it cleanly. */
int via_return(int *buf, int a, int b) {
    int n = clip_count(a, b);
    buf[n] = a;
    return buf[0];
}

/* A branch gated by a value a from-scratch run keeps CONCRETE: the global g_mode (0 in
 * the binary). The guarded read p[i] is only reachable if g_mode != 0, which never
 * happens unless g_mode is made symbolic => a concrete gate whose other side is never
 * explored. */
int g_mode = 0;
int gated(const int *p, int i) {
    if (g_mode) {
        return p[i];
    }
    return -1;
}

/* A branch gated by the POINTED-TO value. Without a backing region, p[0] reads 0 and the
 * guarded block is unreachable; with limits.auto_pointers the pointee is symbolic and the
 * block becomes reachable — the whole point of auto_pointers (bugs in pointed-to data). */
int by_pointee(const int *p) {
    if (p[0] == 0x5a) {
        return p[1] + 1;
    }
    return 0;
}

/* Size-dependent off-by-one: trusts `n` as the length but the bound uses <= instead of <,
 * so buf[n] is read one past the end of a size-n buffer. Only findable if the buffer's size
 * is modeled as the SYMBOLIC n (size_from), not a fixed number — with a fixed size the off-by-
 * one at buf[n] (n < fixed) looks in-bounds. The triggering length shows up as n in the witness. */
char at_index(const char *buf, unsigned n, unsigned i) {
    if (i <= n) {
        return buf[i];
    }
    return 0;
}

/* OOB WRITE masked by an earlier read that pins the index: buf is 4 ints (16 bytes); the
 * read buf[r-1] makes angr concretize the symbolic index r, and the later write buf[r]
 * (OOB when r>=4) then sees a pinned r and looks in-bounds. The write is the more dangerous
 * primitive, so under-reporting it is exactly the gap #2 targets. */
int rw_mask(int *buf, unsigned r) {
    int x = 0;
    if (r) x = buf[r - 1];
    buf[r] = x + 1;
    return x;
}

/* A fill loop whose length n is attacker-controlled, into a fixed 4-int (16-byte) buffer.
 * dst[k] is an OOB WRITE once k >= 4 (n > 4). Reaching that write takes MORE than 4 loop
 * iterations, so a low loop_bound cuts the loop BEFORE the overflow — the run comes back
 * clean, but ONLY because angr stopped unrolling (summary.truncation flags that the loop
 * was bounded). Raising loop_bound past the overflow index surfaces the write. This is the
 * bounded-symbolic-execution blind spot #3 targets: "0 findings" that is really "didn't
 * look far enough into the loop." */
int fill_n(int *dst, unsigned n) {
    for (unsigned k = 0; k < n; k++) {
        dst[k] = (int)k;
    }
    return dst[0];
}

int main(void) { return 0; }
