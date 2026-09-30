/*
 * machine.c -- a self-contained toy virtual machine + a layered input check.
 *
 * This is a research/education artifact for exercising a symbolic-execution
 * GUI on a NON-toy amount of code with NO source available to the tool: it is
 * compiled and then stripped, so the tool sees only sub_XXXX functions and
 * machine instructions. Nothing here targets third-party software; the point
 * is to produce interesting, input-dependent control flow (a dispatcher, a
 * bytecode loop, nested conditions) so the path tree and generated angr script
 * have something real to show.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ a tiny VM */
enum {
    OP_HALT = 0, OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_XOR, OP_AND, OP_OR,
    OP_ROTL, OP_DUP, OP_SWAP, OP_JZ, OP_JNZ, OP_JMP, OP_MIX, OP_NEG
};

static uint32_t rotl32(uint32_t v, unsigned r) {
    r &= 31;
    return (v << r) | (v >> ((32 - r) & 31));
}

/* interpret a fixed program, seeded with `seed`, return the top of stack */
static uint32_t vm_run(const int8_t *prog, int n, uint32_t seed) {
    uint32_t st[32];
    int sp = 0;
    int pc = 0;
    uint32_t acc = seed;
    st[sp++] = seed;
    while (pc < n && sp > 0 && sp < 30) {
        int op = prog[pc++];
        switch (op) {
        case OP_HALT:  return st[sp - 1];
        case OP_PUSH:  st[sp++] = (uint32_t)(uint8_t)prog[pc++]; break;
        case OP_ADD:   st[sp - 2] = st[sp - 2] + st[sp - 1]; sp--; break;
        case OP_SUB:   st[sp - 2] = st[sp - 2] - st[sp - 1]; sp--; break;
        case OP_MUL:   st[sp - 2] = st[sp - 2] * st[sp - 1]; sp--; break;
        case OP_XOR:   st[sp - 2] = st[sp - 2] ^ st[sp - 1]; sp--; break;
        case OP_AND:   st[sp - 2] = st[sp - 2] & st[sp - 1]; sp--; break;
        case OP_OR:    st[sp - 2] = st[sp - 2] | st[sp - 1]; sp--; break;
        case OP_ROTL:  st[sp - 1] = rotl32(st[sp - 1], (unsigned)prog[pc++]); break;
        case OP_DUP:   st[sp] = st[sp - 1]; sp++; break;
        case OP_SWAP:  { uint32_t t = st[sp - 1]; st[sp - 1] = st[sp - 2]; st[sp - 2] = t; } break;
        case OP_NEG:   st[sp - 1] = (uint32_t)(-(int32_t)st[sp - 1]); break;
        case OP_MIX:   acc = rotl32(acc ^ st[sp - 1], 7) + 0x9e3779b9u; st[sp - 1] ^= acc; break;
        case OP_JZ:    { int t = prog[pc++]; if (st[sp - 1] == 0) pc = t; } break;
        case OP_JNZ:   { int t = prog[pc++]; if (st[sp - 1] != 0) pc = t; } break;
        case OP_JMP:   pc = prog[pc]; break;
        default:       return 0xdeadbeef;
        }
    }
    return st[sp - 1];
}

/* a fixed "hash" program for the VM */
static const int8_t PROG[] = {
    OP_PUSH, 0x11, OP_XOR, OP_ROTL, 5, OP_DUP, OP_MIX,
    OP_PUSH, 0x2f, OP_ADD, OP_ROTL, 3, OP_MIX,
    OP_PUSH, 0x7d, OP_MUL, OP_XOR, OP_HALT
};

static uint32_t transform(uint32_t x) {
    return vm_run(PROG, (int)sizeof(PROG), x);
}

/* ---------------------------------------------------------- a layered checker */
/* returns 0 only when the two 32-bit words satisfy a chain of conditions.
   A symbolic-execution tool should be able to find those words. */
int validate(uint32_t user, uint32_t code) {
    uint32_t h = transform(user);

    if ((user & 0xff) != 0x5a)
        return 1;
    if (((user >> 8) & 0xff) < 0x20)
        return 2;
    if (h % 97 != 42)
        return 3;

    uint32_t mixed = h ^ rotl32(code, 11);
    for (int i = 0; i < 4; i++)
        mixed = rotl32(mixed + (code >> (i * 8)), 5) ^ 0x1234567u;

    if ((mixed & 0xffff) != (user & 0xffff))
        return 4;
    if (code == user)
        return 5;
    if ((int32_t)(code - user) <= 0)
        return 6;
    return 0;   /* accepted */
}

/* a second, independent entry point with its own dispatcher */
long dispatch(int cmd, long a, long b) {
    switch (cmd & 7) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : -1;
    case 4: return (long)transform((uint32_t)a) + b;
    case 5:
        if (a > b) {
            if (a - b > 1000)
                return validate((uint32_t)a, (uint32_t)b);
            return a - b;
        }
        return b - a;
    case 6: {
        long acc = 0;
        for (int i = 0; i < 8 && i < (int)a; i++)
            acc += transform((uint32_t)(b + i));
        return acc;
    }
    default: return 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <user-hex> <code-hex>\n", argv[0]);
        return 2;
    }
    uint32_t user = (uint32_t)strtoul(argv[1], NULL, 16);
    uint32_t code = (uint32_t)strtoul(argv[2], NULL, 16);
    int r = validate(user, code);
    if (r == 0)
        puts("accepted");
    else
        printf("rejected (%d)\n", r);
    return r;
}
