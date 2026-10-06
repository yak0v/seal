/*
 * checks_sample.c — minimal, planted bugs for the newer built-in checks
 * (div_by_zero, null_deref, oob_read). Built like the other samples (x86-64 ELF,
 * -O0 -no-pie). Each function takes its inputs in the ABI arg registers so a test
 * can mark them symbolic and confirm the check fires with a concrete witness.
 */
#include <stdint.h>

/* div_by_zero: the divisor is b; a/b faults when b == 0. (angr normally assumes the
 * divisor is non-zero and prunes this — the check must still find it.) */
int div_z(int a, int b) {
    return a / b;
}

/* null_deref: dereferences the pointer argument; NULL when p == 0. */
int null_d(int *p) {
    return *p + 1;
}

/* oob_read: reads buf[i]; with the buffer declared as 16 bytes (4 ints), i >= 4
 * reads out of bounds (information leak). */
int oob_r(const int *buf, uint32_t i) {
    return buf[i];
}

int main(void) { return 0; }
