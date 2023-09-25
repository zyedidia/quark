#include <stdio.h>

char quark_notouch[1] __attribute__((weak));

extern int end;

static int returns;

void on_return() {
    returns++;
    if (end) {
        printf("returns: %d\n", returns);
    }
}
