/* struct_sample.c — functions that take a pointer-to-struct whose members are
 * themselves pointers, to exercise nested-pointer buffer setup. */
#include <stdint.h>

struct msg { int *data; uint32_t len; };

/* reads data[i] THROUGH the pointer member — oob read when i leaves the sub-buffer */
int readmsg(struct msg *m, uint32_t i) {
    return m->data[i];
}

/* linked: next->next->val — two pointer hops */
struct node { struct node *next; int val; };
int second(struct node *n) {
    return n->next->val;
}

int main(void) { return 0; }
