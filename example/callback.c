#include <stdio.h>

int n;
void __quark_callback() {
    printf("callback! %d\n", n);
    n++;
}
