#include <stdio.h>

#include "interceptor.h"

char (*getchar_orig) (void);

int my_func(const char *s) {
    printf("intercepted\n");
}

int main(int argc, const char* argv[]) {
    getchar();
    getchar_orig = intercept_function("getchar", my_func);
    getchar();
    getchar_orig();
    unintercept_function("getchar");
    getchar();
    return 0;
}
