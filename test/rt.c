#include <stdio.h>

extern int end;

static int returns;

void on_return() {
    returns++;
    if (end) {
        printf("returns: %d\n", returns);
    }
}
